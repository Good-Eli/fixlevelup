import { lstat, mkdtemp, open, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { openPayloadKeyDirectory } from '../src/requests/crypto/payload-key-directory.js';
import type { PayloadKeySlots } from '../src/requests/crypto/payload-key-directory.js';

/** Only per-run local synthetic slot generations. No credential or path defaults in T. */
export async function createSyntheticKeySlots(environment: string): Promise<{
  directory: string; slots: PayloadKeySlots; close(): Promise<void>;
}> {
  if (process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] !== '1' || process.platform !== 'linux') {
    throw new Error('Expected isolated Linux key slot fixture');
  }
  const parent = await realpath(tmpdir());
  const directory = await mkdtemp(join(parent,'p05-key-slots-'));
  const original = await lstat(directory, { bigint: true });
  let closed = false;
  const close = async () => {
    if (closed) { return; }
    const current = await lstat(directory, { bigint: true });
    if (dirname(directory) !== parent || !/^p05-key-slots-[a-zA-Z0-9]{6}$/.test(basename(directory))
      || !current.isDirectory() || current.dev !== original.dev || current.ino !== original.ino
      || current.birthtimeNs !== original.birthtimeNs || await realpath(directory) !== directory) {
      throw new Error('Refusing to remove a different slot generation');
    }
    await rm(directory, { recursive: true });
    closed = true;
  };
  try {
    const root = await open(parent, 'r');
    try { await root.sync(); } finally { await root.close(); }
    return { directory, slots: await openPayloadKeyDirectory(directory, environment), close };
  } catch (error) {
    await close();
    throw error;
  }
}
