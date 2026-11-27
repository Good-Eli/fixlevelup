/**
 * Local immutable payload-key slot generation. Provision an absolute 0700
 * directory owned by the service euid outside both the database and the
 * checkout. Provision its directory entry durably (fsync its parent after
 * creation) before use. Linux directory descriptors use a trusted procfs
 * mount. Deployment must use a local, disk-backed filesystem that honors
 * hard links and fsync (including the backing store of an overlay). Directory
 * ownership and mode are not protection against root, the same euid, a
 * compromised process, or an operator renaming an active generation.
 *
 * One service identity acts as writer; create publishes only by no-clobber
 * hard link. A successful create waits for synchronous local durability (file
 * and directory fsync), not just an enqueue, and is not a DB transaction or
 * a backup/replication guarantee. DB rollback or an indeterminate I/O failure
 * can leave an orphan; a final leaf is NEVER deleted or adopted on retry.
 * No overwrite/update API exists. Rewrap or restore into a separately
 * provisioned generation and switch only when that complete generation has
 * been verified offline, with writers stopped. A missing/invalid slot is a
 * hard failure, with no fallback to old generations, DB material or keys.
 */
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import type { BigIntStats } from 'node:fs';
import { link, lstat, open, statfs, unlink } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { posix } from 'node:path';
import type { PayloadKind } from './payload-cipher.js';

export interface PayloadKeySlotRef {
  readonly environment: string;
  readonly cellId: string;
  readonly requestId: string;
  readonly kind: PayloadKind;
  readonly revision: number;
}

export interface PayloadKeyWrap {
  readonly keyId: string;
  readonly wrappedDek: Buffer;
}

export interface PayloadKeySlots {
  readonly environment: string;
  create(ref: PayloadKeySlotRef, wrap: PayloadKeyWrap): Promise<void>;
  read(ref: PayloadKeySlotRef): Promise<PayloadKeyWrap>;
}

const DIRECTORY_FLAGS = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
const READ_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const STAGE_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const WRAP_BYTES = 60;
const MAX_RECORD_BYTES = 384;
const PAYLOAD_KINDS: ReadonlySet<string> = new Set(['CONTACT', 'ADDRESS', 'DETAILS']);
const KNOWN_FILESYSTEMS = new Set([
  0xef53, 0x58465342, 0x9123683e, 0xf2f52010, 0x2fc12fc1, 0x794c7630, // ext*, XFS, Btrfs, F2FS, ZFS, overlay
]);

// Never propagate I/O paths, record content, cause or stack-frame paths.
function unavailable(): Error {
  const message = 'Payload key slot unavailable';
  const error = new Error(message);
  error.stack = `Error: ${message}`;
  return error;
}

function validEnvironment(value: string): boolean {
  return typeof value === 'string' && value.length >= 1 && value.length <= 24 && !/[^\x20-\x7e]/.test(value);
}

function validUuid(value: string): boolean {
  return typeof value === 'string' && value.length === 36 && UUID.test(value);
}

function validKeyId(value: string): boolean {
  return typeof value === 'string' && value.length >= 4 && value.length <= 64
    && /^[A-Za-z0-9]/.test(value) && !/[^A-Za-z0-9._-]/.test(value);
}

function slot(ref: PayloadKeySlotRef, expectedEnvironment: string): { leaf: string; prefix: string } {
  const { environment, cellId, requestId, kind, revision } = ref;
  if (environment !== expectedEnvironment || !validUuid(cellId) || !validUuid(requestId)
    || !PAYLOAD_KINDS.has(kind) || !Number.isSafeInteger(revision) || revision < 1) {
    throw unavailable();
  }
  return {
    leaf: `${cellId}.slot`,
    prefix: `p05/key-slot/v1\n${environment}\n${cellId}\n${requestId}\n${kind}\n${String(revision)}\n`,
  };
}

function encodeWrap(prefix: string, wrap: PayloadKeyWrap): Buffer {
  const { keyId, wrappedDek } = wrap;
  if (!validKeyId(keyId) || !Buffer.isBuffer(wrappedDek) || wrappedDek.length !== WRAP_BYTES) {
    throw unavailable();
  }
  return Buffer.from(`${prefix}${keyId}\n${wrappedDek.toString('hex')}\n`, 'ascii');
}

function decodeWrap(prefix: string, bytes: Buffer): PayloadKeyWrap {
  // latin1 is 1:1 with bytes; unlike Node's ASCII decoder it cannot mask a
  // non-ASCII octet into an otherwise valid canonical descriptor character.
  const descriptor = bytes.toString('latin1');
  if (!descriptor.startsWith(prefix)) { throw unavailable(); }
  const [keyId, hex, final, ...extra] = descriptor.slice(prefix.length).split('\n');
  if (keyId === undefined || !validKeyId(keyId) || hex === undefined || hex.length !== WRAP_BYTES * 2
    || /[^0-9a-f]/.test(hex) || final !== '' || extra.length !== 0) {
    throw unavailable();
  }
  return { keyId, wrappedDek: Buffer.from(hex, 'hex') };
}

function fdPath(dir: FileHandle): string {
  return `/proc/self/fd/${String(dir.fd)}`;
}

function sameInode(a: BigIntStats, b: BigIntStats): boolean {
  return a.dev === b.dev && a.ino === b.ino;
}

function sameGeneration(a: BigIntStats, b: BigIntStats): boolean {
  return sameInode(a, b) && a.birthtimeNs === b.birthtimeNs;
}

function requireAncestor(stats: BigIntStats, euid: bigint): void {
  // A root/private-user-owned sticky ancestor (e.g. /tmp) cannot let another
  // unprivileged uid unlink or rename the next verified directory component.
  if (!stats.isDirectory() || (stats.uid !== 0n && stats.uid !== euid)
    || ((stats.mode & 0o022n) !== 0n && (stats.mode & 0o1000n) === 0n)) {
    throw unavailable();
  }
}

function requireDirectory(stats: BigIntStats, euid: bigint): void {
  if (!stats.isDirectory() || stats.uid !== euid || (stats.mode & 0o7777n) !== 0o700n) {
    throw unavailable();
  }
}

// Open each caller-selected component individually with O_NOFOLLOW, relative
// to a still-open parent. No record operation re-resolves that pathname.
async function openGeneration(components: readonly string[], euid: bigint): Promise<FileHandle> {
  let dir = await open('/', DIRECTORY_FLAGS);
  try {
    for (const component of components) {
      requireAncestor(await dir.stat({ bigint: true }), euid);
      const parent = dir;
      dir = await open(`${fdPath(parent)}/${component}`, DIRECTORY_FLAGS);
      await parent.close();
    }
    requireDirectory(await dir.stat({ bigint: true }), euid);
    return dir;
  } catch (error) {
    await dir.close();
    throw error;
  }
}

function requireRecord(stats: BigIntStats, euid: bigint, links: bigint): void {
  if (!stats.isFile() || stats.uid !== euid || (stats.mode & 0o7777n) !== 0o600n || stats.nlink !== links) {
    throw unavailable();
  }
}

async function readRecord(path: string, prefix: string, euid: bigint): Promise<PayloadKeyWrap> {
  const expected = await lstat(path, { bigint: true });
  requireRecord(expected, euid, 1n);
  const file = await open(path, READ_FLAGS);
  try {
    const before = await file.stat({ bigint: true });
    requireRecord(before, euid, 1n);
    if (!sameInode(expected, before) || before.size < 1n || before.size > BigInt(MAX_RECORD_BYTES)) {
      throw unavailable();
    }
    const bytes = Buffer.alloc(MAX_RECORD_BYTES + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await file.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead === 0) { break; }
      offset += bytesRead;
    }
    const after = await lstat(path, { bigint: true });
    requireRecord(after, euid, 1n);
    if (offset !== Number(before.size) || !sameInode(before, after) || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
      throw unavailable();
    }
    return decodeWrap(prefix, bytes.subarray(0, offset));
  } finally {
    await file.close();
  }
}

async function unlinkStage(path: string, stage: BigIntStats, euid: bigint): Promise<void> {
  // Cleanup is allowed only if the staging leaf still names our inode.
  const named = await lstat(path, { bigint: true });
  if (!named.isFile() || named.uid !== euid || !sameInode(stage, named)) { throw unavailable(); }
  await unlink(path);
}

async function createRecord(dir: FileHandle, leaf: string, bytes: Buffer, euid: bigint): Promise<void> {
  const parent = fdPath(dir);
  const stagePath = `${parent}/.slot-stage-${randomBytes(16).toString('hex')}`;
  const finalPath = `${parent}/${leaf}`;
  const staged = await open(stagePath, STAGE_FLAGS, 0o600);
  try {
    const stage = await staged.stat({ bigint: true });
    try {
      // Enforce the exact mode even when umask removed owner access on create.
      await staged.chmod(0o600);
      requireRecord(await staged.stat({ bigint: true }), euid, 1n);
      await staged.writeFile(bytes);
      await staged.sync();
      const source = await lstat(stagePath, { bigint: true });
      requireRecord(source, euid, 1n);
      if (!sameInode(stage, source) || source.size !== BigInt(bytes.length)) { throw unavailable(); }
      // Same directory, so hard link is atomic and refuses an existing final
      // leaf (even a symlink) without replacing it. Never unlink finalPath.
      await link(stagePath, finalPath);
      const published = await lstat(finalPath, { bigint: true });
      requireRecord(published, euid, 2n);
      if (!sameInode(stage, published)) { throw unavailable(); }
    } finally {
      // Failed cleanup is itself an indeterminate create, not success.
      await unlinkStage(stagePath, stage, euid);
    }
    const published = await lstat(finalPath, { bigint: true });
    requireRecord(published, euid, 1n);
    if (!sameInode(stage, published)) { throw unavailable(); }
    await staged.sync();
    await dir.sync();
  } finally {
    await staged.close();
  }
}

export async function openPayloadKeyDirectory(directory: string, environment: string): Promise<PayloadKeySlots> {
  try {
    if (process.platform !== 'linux' || process.geteuid === undefined || !validEnvironment(environment)
      || typeof directory !== 'string' || !posix.isAbsolute(directory) || Buffer.byteLength(directory) > 4096
      || directory.includes('\0') || directory === '/' || directory.endsWith('/')
      || posix.normalize(directory) !== directory) {
      throw unavailable();
    }
    const euid = BigInt(process.geteuid());
    const components = directory.slice(1).split('/');
    const initial = await openGeneration(components, euid);
    let identity: BigIntStats;
    try {
      identity = await initial.stat({ bigint: true });
      // Reject clearly unsupported filesystems (e.g. tmpfs, NFS). This is not
      // proof that an overlay's backing store or device honors flushes.
      if (!KNOWN_FILESYSTEMS.has((await statfs(fdPath(initial))).type >>> 0)) { throw unavailable(); }
      await initial.sync();
    } finally {
      await initial.close();
    }

    async function useGeneration<T>(operation: (dir: FileHandle) => Promise<T>): Promise<T> {
      const pinned = await openGeneration(components, euid);
      try {
        if (!sameGeneration(identity, await pinned.stat({ bigint: true }))) { throw unavailable(); }
        const result = await operation(pinned);
        // Refuse if the configured namespace no longer resolves to the
        // generation used, even though its descriptor never redirected I/O.
        const current = await openGeneration(components, euid);
        try {
          if (!sameGeneration(identity, await current.stat({ bigint: true }))) { throw unavailable(); }
        } finally {
          await current.close();
        }
        return result;
      } finally {
        await pinned.close();
      }
    }

    return Object.freeze({
      environment,
      async create(ref: PayloadKeySlotRef, wrap: PayloadKeyWrap): Promise<void> {
        try {
          const { leaf, prefix } = slot(ref, environment);
          const bytes = encodeWrap(prefix, wrap);
          await useGeneration(dir => createRecord(dir, leaf, bytes, euid));
        } catch {
          throw unavailable();
        }
      },
      async read(ref: PayloadKeySlotRef): Promise<PayloadKeyWrap> {
        try {
          const { leaf, prefix } = slot(ref, environment);
          return await useGeneration(dir => readRecord(`${fdPath(dir)}/${leaf}`, prefix, euid));
        } catch {
          throw unavailable();
        }
      },
    });
  } catch {
    throw unavailable();
  }
}
