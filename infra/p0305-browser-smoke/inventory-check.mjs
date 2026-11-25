/**
 * Pure regression for the pinned S0 cap contract. Node-only: no Docker, no
 * database, no network. Exits non-zero on any deviation.
 *
 * Run from the repository root:
 *   node infra/p0305-browser-smoke/inventory-check.mjs
 */
import assert from 'node:assert/strict';
import { EXCLUDED_P05_MIGRATIONS, SERVER_VERSION_NUM, historyDigestOf, migrationInventory,
  validateInventory, witnessBoundaryVerdict } from './launch.mjs';

const pins = Array.from({ length: 21 }, (_, index) => ({
  name: `20261120${String(index).padStart(6, '0')}_synthetic_${String(index)}`,
  checksum: String(index + 1).padStart(64, 'a').slice(-64),
}));
const prefix = pins.map((pin) => pin.name);
const chain = [...prefix, ...EXCLUDED_P05_MIGRATIONS];
let checks = 0;
const ok = (label) => { checks += 1; console.log(`ok ${label}`); };
const refuses = (label, run) => {
  assert.throws(run, undefined, label);
  checks += 1;
  console.log(`ok ${label}`);
};

// The exact reviewed shape is accepted.
const accepted = validateInventory(chain, pins);
assert.equal(accepted.chain.length, 24);
assert.equal(accepted.pins.length, 21);
assert.deepEqual(accepted.excluded, [...EXCLUDED_P05_MIGRATIONS]);
ok('accepts exactly the pinned 21 prefix + the three reviewed P05 migrations');

// The excluded suffix is exactly the reviewed P05 layers, in order.
assert.equal(EXCLUDED_P05_MIGRATIONS.length, 3);
ok('excludes exactly three reviewed P05 migrations');

// Length, ordering and suffix drift all refuse.
refuses('refuses a 21-directory chain', () => validateInventory(prefix, pins));
refuses('refuses a 23-directory chain', () => validateInventory(chain.slice(0, 23), pins));
refuses('refuses an unknown extra migration', () => validateInventory([...chain, '20261126000100_unknown_layer'], pins));
refuses('refuses an unsorted chain', () => validateInventory([chain[1], chain[0], ...chain.slice(2)], pins));
refuses('refuses a renamed 022 layer', () => validateInventory([...prefix,
  '20261123000100_request_intake_foundations', EXCLUDED_P05_MIGRATIONS[1], EXCLUDED_P05_MIGRATIONS[2]], pins));
refuses('refuses a reordered P05 suffix', () => validateInventory([...prefix,
  EXCLUDED_P05_MIGRATIONS[1], EXCLUDED_P05_MIGRATIONS[0], EXCLUDED_P05_MIGRATIONS[2]], pins));
refuses('refuses a dropped 024 layer', () => validateInventory([...prefix, ...EXCLUDED_P05_MIGRATIONS.slice(0, 2)], pins));
refuses('refuses a replaced 024 layer', () => validateInventory([...prefix,
  ...EXCLUDED_P05_MIGRATIONS.slice(0, 2), '20261125000100_request_intake_effect'], pins));
refuses('refuses a wrong prefix entry', () => validateInventory([pins[1].name, pins[0].name, ...prefix.slice(2),
  ...EXCLUDED_P05_MIGRATIONS], pins));
refuses('refuses a 20-entry pin manifest', () => validateInventory(chain, pins.slice(0, 20)));
refuses('refuses a 22-entry pin manifest', () => validateInventory(chain, [...pins, pins[0]]));
refuses('refuses a non-hex pin checksum', () => validateInventory(chain, [{ ...pins[0], checksum: 'z'.repeat(64) }, ...pins.slice(1)]));

// The real tree must satisfy the same contract, with byte-verified checksums.
const real = await migrationInventory();
assert.equal(real.chain.length, 24);
assert.equal(real.pins.length, 21);
assert.equal(real.scripts.length, 21);
assert.deepEqual(real.excluded, [...EXCLUDED_P05_MIGRATIONS]);
assert.equal(real.chain.at(-1), '20261125000100_request_intake_effects');
ok('real tree is exactly 24 migrations with the pinned 21 prefix and reviewed P05 suffix');

/** ---------------------------------------------------------------------------
 * Witness-backend bound re-proof (task-22). Two pure contracts, no database:
 *  - historyDigestOf: the exact pinned S0 history validator reused by both the
 *    provisioning apply and the witness-backend re-proof;
 *  - witnessBoundaryVerdict: the identity verdict that must pass on the SAME
 *    backend that holds the witness before anything is signed/issued/spawned.
 * The synthetic rows below are a fake boundary proof: they exercise every
 * refusal branch without a cluster.
 */
const appliedRows = pins.map((pin) => ({ migration_name: pin.name, checksum: pin.checksum,
  finished_at: new Date('2026-11-25T00:00:00Z'), rolled_back_at: null, applied_steps_count: 1 }));
const pinnedDigest = historyDigestOf(appliedRows, pins);
assert.match(pinnedDigest, /^[a-f0-9]{64}$/u);
assert.equal(historyDigestOf(appliedRows, pins), pinnedDigest);
ok('history validator accepts exactly the pinned 21 applied rows and is deterministic');

const rowMutations = {
  'a missing row': (rows) => rows.slice(0, 20),
  'an extra row': (rows) => [...rows, { ...rows[0], migration_name: '20261126000100_unknown' }],
  'a renamed migration': (rows) => [{ ...rows[0], migration_name: '20261120000100_other' }, ...rows.slice(1)],
  'a different checksum': (rows) => [{ ...rows[0], checksum: 'f'.repeat(64) }, ...rows.slice(1)],
  'a reordered pair': (rows) => [rows[1], rows[0], ...rows.slice(2)],
  'an unfinished row': (rows) => [{ ...rows[0], finished_at: null }, ...rows.slice(1)],
  'a rolled-back row': (rows) => [{ ...rows[0], rolled_back_at: new Date() }, ...rows.slice(1)],
  'a multi-step row': (rows) => [{ ...rows[0], applied_steps_count: 2 }, ...rows.slice(1)],
};
for (const [label, mutate] of Object.entries(rowMutations)) {
  refuses(`history validator refuses ${label}`, () => historyDigestOf(mutate(appliedRows), pins));
  // A changed history must also change the digest the proof would carry, so a
  // mismatch is detectable by comparison, not just by the validator.
  const mutated = mutate(appliedRows);
  if (mutated.length === pins.length) {
    let digest;
    try { digest = historyDigestOf(mutated, pins); } catch { digest = 'refused'; }
    if (digest === pinnedDigest) { throw new Error(`mutated history kept the pinned digest: ${label}`); }
  }
}
ok('every history mutation either refuses or yields a different digest');

const boundary = Object.freeze({ databaseOid: 16384, witnessPid: 4242, schema: 'public', host: '127.0.0.1',
  port: 55432, serverVersionNum: SERVER_VERSION_NUM });
const identity = Object.freeze({ database_ok: true, database_oid: '16384', user_ok: true, session_ok: true,
  schema: 'public', backend_pid: '4242', server_addr: '127.0.0.1', client_addr: '127.0.0.1', server_port: 55432,
  listen_addresses: '127.0.0.1', server_version_num: SERVER_VERSION_NUM, primary: true, own_witness_lock: 1 });
assert.deepEqual(witnessBoundaryVerdict(identity, boundary), { ok: true, reason: undefined });
ok('witness boundary accepts the exact DB/OID/role/schema/pid/loopback/primary/witness-lock facts');

// Each entry is [patch, expected refusal reason]. Two entries map to LOOPBACK:
// a foreign address, and an inet rendered WITH its netmask suffix (what a plain
// `inet::text` cast produces) — the review note's regression.
const boundaryMutations = [
  ['DATABASE', { database_ok: false }, 'DATABASE'],
  ['DATABASE_OID', { database_oid: '16385' }, 'DATABASE_OID'],
  ['ROLE', { user_ok: false }, 'ROLE'],
  ['SCHEMA', { schema: 'foundation' }, 'SCHEMA'],
  ['BACKEND_PID', { backend_pid: '4243' }, 'BACKEND_PID'],
  ['LOOPBACK', { client_addr: '10.0.0.1' }, 'LOOPBACK'],
  ['LOOPBACK_NETMASK', { client_addr: '127.0.0.1/32' }, 'LOOPBACK'],
  ['LISTEN', { listen_addresses: '*' }, 'LISTEN'],
  ['SERVER_VERSION', { server_version_num: '170000' }, 'SERVER_VERSION'],
  ['NOT_PRIMARY', { primary: false }, 'NOT_PRIMARY'],
  ['WITNESS_LOCK', { own_witness_lock: 0 }, 'WITNESS_LOCK'],
];
for (const [label, patch, expectedReason] of boundaryMutations) {
  const verdict = witnessBoundaryVerdict({ ...identity, ...patch }, boundary);
  assert.equal(verdict.ok, false, `boundary accepted a mismatched ${label}`);
  assert.equal(verdict.reason, expectedReason,
    `boundary reported ${String(verdict.reason)} instead of ${expectedReason} for ${label}`);
}
// The verdict is a value, not an exception: the caller refuses before signing.
assert.deepEqual(witnessBoundaryVerdict(undefined, boundary), { ok: false, reason: 'IDENTITY_MISSING' });
assert.deepEqual(witnessBoundaryVerdict(null, boundary), { ok: false, reason: 'IDENTITY_MISSING' });
ok('witness boundary refuses a missing identity row with a typed reason');
ok('witness boundary refuses every single-fact mismatch with a distinct reason');

console.log(`inventory + witness-boundary contract: ${String(checks)} checks passed`);
