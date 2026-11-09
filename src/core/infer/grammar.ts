import type { MessageRecord } from './state.js';

/**
 * Conversation grammar.
 *
 * The state graph in `state.ts` counts which message labels followed which. That is a
 * first-order model and it cannot tell a reply from an unsolicited message. This module pairs
 * a request with the response that answers it, which is what makes latency, pipelining and a
 * handshake visible — three things that a reader needs before touching a target.
 *
 * The pairing rule is FIFO: the oldest unanswered forward message is matched to the next
 * reverse message. That is right for strict request/response protocols and for pipelining, and
 * it is wrong for anything that answers out of order, which the notes say out loud.
 */

export interface Exchange {
  index: number;
  request: { label: string; ts: number; length: number };
  response: { label: string; ts: number; length: number } | null;
  latencyMs: number | null;
}

export interface CallShape {
  request: string;
  responses: Array<{ label: string; count: number }>;
}

export interface GrammarAnalysis {
  exchanges: Exchange[];
  calls: CallShape[];
  latency: { count: number; minMs: number; medianMs: number; maxMs: number } | null;
  unpairedRequests: number;
  unpairedResponses: number;
  /** Leading exchanges whose pair never recurs, in order. */
  handshake: string[];
  pipelined: boolean;
  notes: string[];
}

export function inferGrammar(messages: MessageRecord[]): GrammarAnalysis {
  // Timestamps come from the segment that carried each message, so several messages can share
  // one. On a tie the request must sort before the response, otherwise a burst is paired
  // backwards and the latency figures go with it.
  const ordered = [...messages].sort(
    (a, b) => a.ts - b.ts || (a.direction === b.direction ? a.offset - b.offset : a.direction === 'forward' ? -1 : 1),
  );
  const notes: string[] = [];

  if (ordered.length < 2) {
    return {
      exchanges: [],
      calls: [],
      latency: null,
      unpairedRequests: 0,
      unpairedResponses: 0,
      handshake: [],
      pipelined: false,
      notes: ['fewer than two messages: there is no conversation to pair'],
    };
  }

  const pending: MessageRecord[] = [];
  const exchanges: Exchange[] = [];
  let unpairedResponses = 0;
  let pipelined = false;

  for (const message of ordered) {
    if (message.direction === 'forward') {
      if (pending.length > 0) pipelined = true;
      pending.push(message);
      continue;
    }

    const request = pending.shift();
    if (!request) {
      unpairedResponses++;
      continue;
    }
    exchanges.push({
      index: exchanges.length,
      request: { label: request.label, ts: request.ts, length: request.bytes.length },
      response: { label: message.label, ts: message.ts, length: message.bytes.length },
      latencyMs: Math.max(0, (message.ts - request.ts) * 1000),
    });
  }

  for (const request of pending) {
    exchanges.push({
      index: exchanges.length,
      request: { label: request.label, ts: request.ts, length: request.bytes.length },
      response: null,
      latencyMs: null,
    });
  }

  const paired = exchanges.filter((exchange) => exchange.response !== null);
  const latencies = paired.map((exchange) => exchange.latencyMs!).sort((a, b) => a - b);

  const latency =
    latencies.length === 0
      ? null
      : {
          count: latencies.length,
          minMs: latencies[0]!,
          medianMs: latencies[Math.floor(latencies.length / 2)]!,
          maxMs: latencies[latencies.length - 1]!,
        };

  const calls = buildCalls(paired);
  const handshake = findHandshake(exchanges);

  if (unpairedResponses > 0) {
    notes.push(
      `${unpairedResponses} message(s) arrived from the server side with no outstanding request; either the capture starts mid-conversation or the protocol pushes data`,
    );
  }
  if (pending.length > 0) {
    notes.push(`${pending.length} request(s) were never answered inside the capture`);
  }
  if (pipelined) {
    notes.push('more than one request was outstanding at a time; the FIFO pairing assumes answers come back in order');
  }
  if (calls.length > 0) {
    const strict = calls.every((call) => call.responses.length === 1);
    if (strict && paired.length > 3) notes.push('every request type was answered by exactly one response type: strict request/response');
    else if (paired.length > 3) notes.push('some request types were answered by more than one response type; the reply depends on the request arguments');
  }

  return {
    exchanges,
    calls,
    latency,
    unpairedRequests: pending.length,
    unpairedResponses,
    handshake,
    pipelined,
    notes,
  };
}

function buildCalls(exchanges: Exchange[]): CallShape[] {
  const table = new Map<string, Map<string, number>>();
  for (const exchange of exchanges) {
    const bucket = table.get(exchange.request.label) ?? new Map<string, number>();
    const label = exchange.response!.label;
    bucket.set(label, (bucket.get(label) ?? 0) + 1);
    table.set(exchange.request.label, bucket);
  }

  return [...table.entries()]
    .map(([request, responses]) => ({
      request,
      responses: [...responses.entries()]
        .map(([label, count]) => ({ label, count }))
        .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label)),
    }))
    .sort((a, b) => a.request.localeCompare(b.request));
}

/**
 * A handshake is the leading run of request/response pairs that never repeats. Anything after
 * the handshake is steady state, which is where a replay should start.
 */
function findHandshake(exchanges: Exchange[]): string[] {
  const signature = (exchange: Exchange): string => `${exchange.request.label} -> ${exchange.response?.label ?? 'none'}`;
  let prefix = 0;
  while (prefix < exchanges.length) {
    const current = signature(exchanges[prefix]!);
    const repeatsLater = exchanges.slice(prefix + 1).some((exchange) => signature(exchange) === current);
    if (repeatsLater) break;
    prefix++;
  }

  if (prefix === 0 || prefix > 6 || exchanges.length - prefix < 3) return [];
  return exchanges.slice(0, prefix).map(signature);
}
