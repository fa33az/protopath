import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Root of the repository, independent of the working directory the tests are launched from. */
export const root = fileURLToPath(new URL('../../', import.meta.url));

export function capture(name: string): string {
  return join(root, 'captures', name);
}
