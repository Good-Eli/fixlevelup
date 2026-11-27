/**
 * S3 (024) fingerprint measurement — task-1 lab capability.
 *
 * Read-only measurement of an ALREADY MIGRATED disposable 024 database. It runs
 * the reviewed measurement functions from the current working tree (not a copy
 * of their queries), and prints only hashes / booleans / an error stage. It
 * never prints credentials, connection strings or row data, and it never
 * creates, alters or drops anything.
 *
 * Deliberately a plain script (no test framework): this is an instrument for
 * pinning reviewed 024 fingerprints, not a build/PASS claim. `tsc` compiles only
 * this entry and its import graph, so unrelated WIP type errors cannot block the
 * measurement.
 */
import { createRequire } from 'node:module';
import { LegacyReadinessProbes } from '../../../apps/api/src/infrastructure/database/legacy-readiness.js';
import { readS3Metadata } from '../../../apps/api/src/infrastructure/database/p05-profile-catalog.js';

/**
 * Structural type of the pg client this script needs. `pg` is an api-package
 * dependency (not hoisted to the workspace root), so its declarations are not
 * resolvable from `infra/`; a structural interface keeps the script fully typed
 * without pulling the driver's types into this project.
 */
type MeasurementQueryClient = Parameters<typeof readS3Metadata>[0];
type ReadinessQueryClient = ConstructorParameters<typeof LegacyReadinessProbes>[0];
type LabClient = MeasurementQueryClient & ReadinessQueryClient & {
  connect(): Promise<void>;
  end(): Promise<void>;
};
interface PgModule { readonly Client: new (options: Record<string, unknown>) => LabClient }
const apiRequire = createRequire(new URL('../../../apps/api/package.json', import.meta.url));
const { Client } = apiRequire('pg') as PgModule;

const HEX64 = /^[a-f0-9]{64}$/;

async function main(): Promise<void> {
  const database = process.env['FIXLEVELUP_LAB_DATABASE'] ?? '';
  const password = process.env['FIXLEVELUP_MIGRATOR_PASSWORD'] ?? '';
  if (!/^fixlevelup_p05_[a-z0-9_]{1,48}$/.test(database) || database === 'fixlevelup_dev') {
    throw new Error('Invalid measurement database');
  }
  if (!HEX64.test(password)) { throw new Error('Measurement credential unavailable'); }

  const client = new Client({ host: '127.0.0.1', port: 55432, database, user: 'fixlevelup_migrator',
    password, connectionTimeoutMillis: 5000, statement_timeout: 60_000,
    application_name: 'p05lab-s3-measure' });
  await client.connect();
  try {
    const identity = (await client.query<{
      db: string;
      role: string;
      search_path: string;
      version: string;
    }>(`SELECT current_database() AS db, current_user AS role,
      current_setting('search_path') AS search_path, current_setting('server_version_num') AS version`)).rows[0];
    const probes = new LegacyReadinessProbes(client, database, false, 'fixlevelup_migrator');
    const result: Record<string, unknown> = { identity };
    try {
      result['s3'] = await readS3Metadata(client);
    } catch (error) {
      result['s3'] = { stage: 'readS3Metadata', error: error instanceof Error ? error.message.slice(0, 120) : 'unknown' };
    }
    for (const [name, call] of [
      ['settingsManagement', () => probes.measureSettingsManagement()],
      ['catalogManagement', () => probes.measureCatalogManagement()],
      ['legacyReady', () => probes.ready()],
    ] as const) {
      try {
        result[name] = await call();
      } catch (error) {
        result[name] = { stage: name, error: error instanceof Error ? error.message.slice(0, 120) : 'unknown' };
      }
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally { await client.end(); }
}

await main();
