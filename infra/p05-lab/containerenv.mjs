/**
 * Container-local synthetic `.env` files — EXPLICIT, LAB-ONLY WORKAROUND.
 *
 * Why this exists: a few reviewed suites read the local tooling/dev `.env` files
 * directly instead of the lab process env. `apps/api/tests/form-session-http.test.ts`
 * (`FormSessionHttpFixture.runtimePassword`) is the one UNGUARDED reader; the
 * others only read those files when `FIXLEVELUP_SYNTHETIC_ORCHESTRATOR` is not
 * `1`. The runner image contains no `.env` and must not (source-only image, no
 * credentials baked in), so the lab writes container-local files with the SAME
 * synthetic credentials it already passes through the environment.
 *
 * Guarantees: the files live only in the disposable container's writable layer
 * (never in the image, never in git, never on the host), are mode 0600, and the
 * values are the lab's own generated secrets — no real dev/production credential
 * is read, copied or inferred. The product code, the test code and every
 * protection stay untouched.
 *
 * The proper fix (gating that one reader on the lab flag) belongs in the main
 * tree, owned by the lead; this module is the documented snapshot workaround.
 */
import { existsSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const HEX64 = /^[a-f0-9]{64}$/;

function secret(name) {
  const value = process.env[name] ?? '';
  if (!HEX64.test(value)) { throw new Error(`Lab credential unavailable: ${name}`); }
  return value;
}

/** Writes the synthetic env files inside the current (disposable) container. */
export function writeContainerEnv() {
  const workspace = resolve(import.meta.dirname, '../..');
  const tooling = resolve(workspace, 'packages/database-tooling/.env');
  const devPostgres = resolve(workspace, 'infra/dev-postgres/.env');
  const devS3 = resolve(workspace, 'infra/dev-s3/.env');
  for (const path of [tooling, devPostgres, devS3]) {
    // The image must contain no env file; refuse to clobber anything unexpected.
    if (existsSync(path)) { throw new Error('Refusing to overwrite an existing env file in the runner'); }
  }
  writeFileSync(tooling, `FIXLEVELUP_MIGRATOR_PASSWORD=${secret('FIXLEVELUP_MIGRATOR_PASSWORD')}\n`
    + `FIXLEVELUP_RUNTIME_PASSWORD=${secret('FIXLEVELUP_RUNTIME_PASSWORD')}\n`, { mode: 0o600 });
  writeFileSync(devPostgres, `POSTGRES_PASSWORD=${secret('FIXLEVELUP_LAB_FIXTURE_ADMIN_PASSWORD')}\n`, { mode: 0o600 });
  // S3 credentials are written ONLY when the isolated lab Garage is up; the
  // reviewed storage config reads exactly this file with these four keys.
  const s3 = {
    S3_ACCESS_KEY_ID: process.env['LAB_S3_ACCESS_KEY_ID'] ?? '',
    S3_SECRET_ACCESS_KEY: process.env['LAB_S3_SECRET_ACCESS_KEY'] ?? '',
    S3_READONLY_ACCESS_KEY_ID: process.env['LAB_S3_READONLY_ACCESS_KEY_ID'] ?? '',
    S3_READONLY_SECRET_ACCESS_KEY: process.env['LAB_S3_READONLY_SECRET_ACCESS_KEY'] ?? '',
  };
  if (Object.values(s3).every((value) => value.length > 0)) {
    writeFileSync(devS3, Object.entries(s3).map(([key, value]) => `${key}=${value}`).join('\n') + '\n', { mode: 0o600 });
  }
  // Ledger/floor credentials: written ONLY when the isolated ledger pair is up.
  // The reviewed fixtures read exactly `infra/file-ledger/.env` and expect one
  // 64-hex password per reviewed role.
  const ledgerKeys = ['FILE_LEDGER_ADMIN_PASSWORD', 'FILE_LEDGER_WRITER_PASSWORD',
    'FILE_LEDGER_WRITER_NEXT_PASSWORD', 'FILE_LEDGER_SIGNER_PASSWORD', 'FILE_LEDGER_OPERATOR_PASSWORD',
    'FILE_FLOOR_ADMIN_PASSWORD', 'FILE_FLOOR_VERIFIER_PASSWORD', 'FILE_FLOOR_OPERATOR_PASSWORD'];
  const ledger = Object.fromEntries(ledgerKeys.map((key) => [key, process.env[`LAB_${key}`] ?? '']));
  const ledgerPath = resolve(workspace, 'infra/file-ledger/.env');
  if (Object.values(ledger).every((value) => value.length > 0)) {
    if (existsSync(ledgerPath)) { throw new Error('Refusing to overwrite an existing ledger env file in the runner'); }
    writeFileSync(ledgerPath, Object.entries(ledger).map(([key, value]) => `${key}=${value}`).join('\n') + '\n', { mode: 0o600 });
  }
  // Reviewed file-restore lab branch: pinned client tools are baked into the
  // image at `/opt/p05-lab/bin`, but the Garage CLIENT config and node line carry
  // THIS run's RPC secret and node id, so they are written per container
  // (mode 0600, never in the image, never in git).
  const garageNode = process.env['LAB_GARAGE_NODE'] ?? '';
  const garageSecret = process.env['LAB_GARAGE_RPC_SECRET'] ?? '';
  const clientConfig = '/opt/p05-lab/garage-client.toml';
  const clientNode = '/opt/p05-lab/garage-node.txt';
  if (/^[0-9a-f]{64}@127\.0\.0\.1:3901$/.test(garageNode) && /^[a-f0-9]{64}$/.test(garageSecret)) {
    // Same reviewed shape as `test-results/.../lab/aux/garage.toml`, plus the
    // per-run `rpc_secret` the CLI needs to authenticate to the lab node.
    writeFileSync(clientConfig, `metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "sqlite"
metadata_fsync = true
data_fsync = true
replication_factor = 1
consistency_mode = "consistent"
rpc_secret = "${garageSecret}"
rpc_bind_addr = "127.0.0.1:3901"
rpc_public_addr = "127.0.0.1:3901"
[s3_api]
s3_region = "garage"
api_bind_addr = "0.0.0.0:3900"
public_endpoint = "http://127.0.0.1:3900"
public_endpoint_path_style = true
[admin]
api_bind_addr = "127.0.0.1:3903"
metrics_require_token = true
`, { mode: 0o600 });
    writeFileSync(clientNode, `${garageNode}\n`, { mode: 0o600 });
  }
  return { tooling, devPostgres, devS3, ledger: ledgerPath, clientConfig, clientNode };
}

if (process.argv[1]?.endsWith('containerenv.mjs')) { writeContainerEnv(); }
