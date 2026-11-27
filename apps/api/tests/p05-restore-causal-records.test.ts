import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { AuthorityRecordV3, SnapshotManifest } from '../src/files/file-restore/contract.js';
import {
  readSnapshot, requireAuthorityV2, requireAuthorityV3, signAuthorityV2, signAuthorityV3, signSnapshot, validateLimits,
} from '../src/files/file-restore/records.js';

const keys = generateKeyPairSync('ed25519');
const sourceDatabase = `fixlevelup_legal_test_${'a'.repeat(24)}`;
const destinationDatabase = `fixlevelup_file_restore_${'b'.repeat(24)}`;
const namespace = '48fb83bd-f4a5-4fdc-b386-ad4e2ca4e8f3';
const base = { namespace, incarnation: 'a26d985f-963f-497f-a98a-cdaad0200bad', writerEpoch: 1n, seq: 0n, hash: 'c'.repeat(64) };
const manifest: SnapshotManifest = { sourceDatabase, destinationDatabase, schemaVersion: '20261125000100_request_intake_effects',
  dumpSha256: 'd'.repeat(64), base, aliases: [], inventory: [] };
const limits = validateLimits({ maxObjects: 1, maxIntents: 1, maxObjectBytes: 1, maxTotalObjectBytes: 1, maxManifestBytes: 4096, maxDumpBytes: 4096 });
const policySha256 = 'e'.repeat(64);

describe('P05 carried-policy signed records (offline)', () => {
  it('keeps byte-exact legacy snapshots and binds the policy exclusively to v2 snapshots', () => {
    const legacy = signSnapshot(manifest, keys.privateKey);
    expect(legacy.payload).toBe(JSON.stringify([1, sourceDatabase, destinationDatabase, manifest.schemaVersion, manifest.dumpSha256,
      [base.namespace, base.incarnation, '1', '0', base.hash], [], []]));
    const carried = signSnapshot({ ...manifest, policySha256 }, keys.privateKey);
    expect(carried.payload).toBe(JSON.stringify([2, sourceDatabase, destinationDatabase, manifest.schemaVersion, manifest.dumpSha256,
      [base.namespace, base.incarnation, '1', '0', base.hash], [], [], policySha256]));
    expect(readSnapshot(legacy, keys.publicKey, limits).manifest).toEqual(manifest);
    expect(readSnapshot(carried, keys.publicKey, limits).manifest).toEqual({ ...manifest, policySha256 });
    expect(readSnapshot(carried, keys.publicKey, limits).hash).not.toBe(readSnapshot(legacy, keys.publicKey, limits).hash);
    expect(() => readSnapshot(signSnapshot({ ...manifest, policySha256: 'unknown' }, keys.privateKey), keys.publicKey, limits))
      .toThrow(expect.objectContaining({ code: 'RESTORE_INPUT' }));
  });

  it('keeps distinct v2 and v3 authority formats and refuses malformed v3 policy digests', () => {
    const record: AuthorityRecordV3 = { sourceDatabase, destinationDatabase, sourceDatabaseOid: 12345, sourceProfile: 'S3',
      oldNamespace: base.namespace, oldWriterEpoch: '1', challenge: '1'.repeat(64), manifestSha256: '2'.repeat(64),
      overlaySha256: '3'.repeat(64), inventorySha256: '4'.repeat(64), head: { ...base, writerEpoch: 2n },
      cluster: { systemIdentifier: '548479843765487598', serverVersionNum: '180007', postmasterStart: '2026-01-01 00:00:00.123+00' },
      drainFact: 'P05_EMPTY_AFTER_DRAIN', policySha256 };
    const v2 = signAuthorityV2(record, keys.privateKey);
    const v3 = signAuthorityV3(record, keys.privateKey);
    expect(requireAuthorityV2(v2, keys.publicKey).record).not.toHaveProperty('policySha256');
    expect(requireAuthorityV3(v3, keys.publicKey).record).toEqual(record);
    expect(() => requireAuthorityV2(v3, keys.publicKey)).toThrow(expect.objectContaining({ code: 'RESTORE_AUTHORITY' }));
    expect(() => requireAuthorityV3(v2, keys.publicKey)).toThrow(expect.objectContaining({ code: 'RESTORE_AUTHORITY' }));
    expect(() => requireAuthorityV3(signAuthorityV3({ ...record, policySha256: 'a'.repeat(63) }, keys.privateKey), keys.publicKey))
      .toThrow(expect.objectContaining({ code: 'RESTORE_AUTHORITY' }));
  });
});
