import type { CaptureAnalysis, FlowAnalysis } from './pipeline.js';
import type { Field } from './infer/fields.js';

export interface FieldDiff {
  name: string;
  status: 'added' | 'removed' | 'changed' | 'same';
  before?: Field;
  after?: Field;
  detail: string[];
}

export interface FlowDiff {
  key: string;
  framingBefore: string;
  framingAfter: string;
  verdict: string;
  fields: FieldDiff[];
}

export interface DiffReport {
  flows: FlowDiff[];
  notes: string[];
}

/**
 * Compares the inferred layout of two captures.
 *
 * This is the drift check for a protocol that ships new versions: a field that used to
 * vary and is now constant, or a field that moved, is exactly what a client update breaks on.
 */
export function diffCaptures(before: CaptureAnalysis, after: CaptureAnalysis): DiffReport {
  const notes: string[] = [];
  const flows: FlowDiff[] = [];

  const pairs = pairFlows(before.flows, after.flows);
  if (pairs.length === 0) notes.push('no flow could be paired between the two captures');
  if (before.flows.length !== after.flows.length) {
    notes.push(`flow count changed: ${before.flows.length} before, ${after.flows.length} after`);
  }

  for (const [a, b] of pairs) {
    const beforeFields = primaryFields(a);
    const afterFields = primaryFields(b);
    const fields = compareFields(beforeFields, afterFields);
    const changed = fields.filter((f) => f.status !== 'same');

    flows.push({
      key: a.flow.key === b.flow.key ? a.flow.key : `${a.flow.key} -> ${b.flow.key}`,
      framingBefore: describeFraming(a),
      framingAfter: describeFraming(b),
      verdict: verdict(a, b, changed),
      fields,
    });
  }

  return { flows, notes };
}

function pairFlows(before: FlowAnalysis[], after: FlowAnalysis[]): Array<[FlowAnalysis, FlowAnalysis]> {
  const pairs: Array<[FlowAnalysis, FlowAnalysis]> = [];
  const used = new Set<FlowAnalysis>();

  for (const left of before) {
    const exact = after.find((right) => right.flow.key === left.flow.key && !used.has(right));
    const byPort = after.find((right) => right.flow.b.port === left.flow.b.port && !used.has(right));
    const chosen = exact ?? byPort;
    if (chosen) {
      used.add(chosen);
      pairs.push([left, chosen]);
    }
  }

  if (pairs.length === 0 && before[0] && after[0]) pairs.push([before[0], after[0]]);
  return pairs;
}

function primaryFields(analysis: FlowAnalysis): Field[] {
  return analysis.primary === 'forward' ? analysis.forward.fields : analysis.reverse.fields;
}

function compareFields(before: Field[], after: Field[]): FieldDiff[] {
  const diffs: FieldDiff[] = [];

  for (const field of before) {
    const match = after.find((candidate) => candidate.offset === field.offset && candidate.anchor === field.anchor);
    if (!match) {
      diffs.push({
        name: field.name,
        status: 'removed',
        before: field,
        detail: [`no field starts at ${field.anchor} offset ${field.offset} in the second capture`],
      });
      continue;
    }

    const detail: string[] = [];
    if (match.name !== field.name) detail.push(`renamed from ${field.name} to ${match.name}`);
    if (match.length !== field.length) detail.push(`width ${field.length} -> ${match.length}`);
    if (match.role !== field.role) detail.push(`role ${field.role} -> ${match.role}`);
    if (match.stats.constant !== field.stats.constant) {
      detail.push(`constant ${field.stats.constant ?? 'none'} -> ${match.stats.constant ?? 'none'}`);
    }
    // A raw distinct-count change usually just means the captures hold different numbers of
    // messages. What matters is a field becoming constant, which is how a removed feature
    // shows up in the layout.
    if ((field.stats.distinct === 1) !== (match.stats.distinct === 1)) {
      detail.push(field.stats.distinct === 1 ? 'field stopped being constant' : 'field became constant');
    }

    diffs.push({
      name: match.name,
      status: detail.length === 0 ? 'same' : 'changed',
      before: field,
      after: match,
      detail,
    });
  }

  for (const field of after) {
    const match = before.find((candidate) => candidate.offset === field.offset && candidate.anchor === field.anchor);
    if (!match) {
      diffs.push({
        name: field.name,
        status: 'added',
        after: field,
        detail: [`new field at ${field.anchor} offset ${field.offset}`],
      });
    }
  }

  return diffs;
}

function verdict(before: FlowAnalysis, after: FlowAnalysis, changed: FieldDiff[]): string {
  if (describeFraming(before) !== describeFraming(after)) return 'framing changed; treat this as a new protocol version';
  if (changed.length === 0) return 'layout is stable across both captures';
  const removed = changed.filter((f) => f.status === 'removed').length;
  const added = changed.filter((f) => f.status === 'added').length;
  if (removed > 0 && added > 0) return 'fields moved; a client built for the first capture will misparse the second';
  return `${changed.length} field(s) differ; check whether the difference is a protocol change or just different traffic`;
}

function describeFraming(analysis: FlowAnalysis): string {
  const direction = analysis.primary === 'forward' ? analysis.forward : analysis.reverse;
  const best = direction.best;
  if (!best) return 'none';
  if (best.lengthPrefix) {
    const spec = best.lengthPrefix;
    return `length-prefix ${spec.size}B ${spec.endian} @${spec.lenOffset} bias ${spec.bias}`;
  }
  if (best.startMarker) return `marker 0x${best.startMarker.marker.toString('hex')}`;
  if (best.delimiter) return `delimiter 0x${best.delimiter.terminator.toString('hex')}`;
  if (best.fixed) return `fixed ${best.fixed.size}B`;
  return 'unframed';
}
