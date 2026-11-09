export interface ParsedArgs {
  command: string;
  positional: string[];
  flags: Map<string, string | true>;
  unknown: string[];
}

export function parseArgs(argv: string[]): ParsedArgs {
  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  const unknown: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]!;
    if (token === '--') {
      positional.push(...argv.slice(i + 1));
      break;
    }
    if (token.startsWith('--')) {
      const [name, inline] = splitFlag(token.slice(2));
      if (inline !== undefined) {
        flags.set(name, inline);
        continue;
      }
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags.set(name, next);
        i++;
      } else {
        flags.set(name, true);
      }
      continue;
    }
    if (token.startsWith('-') && token.length > 1 && !isNumber(token)) {
      for (const letter of token.slice(1)) flags.set(letter, true);
      continue;
    }
    positional.push(token);
  }

  const [command = '', ...rest] = positional;
  if (command === '') unknown.push('missing command');
  return { command, positional: rest, flags, unknown };
}

function splitFlag(value: string): [string, string | undefined] {
  const equals = value.indexOf('=');
  if (equals === -1) return [value, undefined];
  return [value.slice(0, equals), value.slice(equals + 1)];
}

function isNumber(value: string): boolean {
  return /^-?\d+(\.\d+)?$/.test(value);
}

export function flagString(flags: Map<string, string | true>, name: string): string | undefined {
  const value = flags.get(name);
  return typeof value === 'string' ? value : undefined;
}

export function flagNumber(flags: Map<string, string | true>, name: string): number | undefined {
  const value = flagString(flags, name);
  if (value === undefined) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

export function flagBool(flags: Map<string, string | true>, name: string): boolean {
  const value = flags.get(name);
  return value === true || value === 'true' || value === '1';
}
