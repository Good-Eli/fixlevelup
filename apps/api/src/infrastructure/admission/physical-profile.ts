import { Client } from 'pg';
import type { DatabaseConfig } from '../database/runtime-database.js';
import { LegacyReadinessProbes } from '../database/legacy-readiness.js';
import { probeP05Catalog } from '../database/p05-profile-catalog.js';
import type { AdmissionConnection } from './admission.js';
import type { ProofProfile } from './proof.js';
import { matchesRuntimeTarget } from './runtime-admission.js';
import type { RuntimeAdmission } from './runtime-admission.js';

/** Exact legacy/P04 and P05 checks on the caller's already pinned connection. */
export async function verifyPhysicalProfile(client: AdmissionConnection, target: Pick<DatabaseConfig, 'database'>,
  profile: ProofProfile): Promise<boolean> {
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try {
    const probes = new LegacyReadinessProbes(client, target.database, true);
    return await probes.ready() && await probes.catalogManagementReady() && await probeP05Catalog(client, profile);
  } finally {
    await client.query('ROLLBACK');
  }
}

export type ProfileVerifier = (admission: RuntimeAdmission, pinned?: AdmissionConnection) => Promise<boolean>;

/** Preflight never constructs a business Pool or Prisma instance. */
export function physicalProfileVerifier(database: DatabaseConfig): ProfileVerifier {
  const target = Object.freeze({ ...database });
  return async (admission, pinned) => {
    if (!matchesRuntimeTarget(admission, target)) { return false; }
    const own = pinned === undefined ? new Client({ ...target, connectionTimeoutMillis: 1000,
      statement_timeout: 1000, query_timeout: 2000,
      options: '-c default_transaction_read_only=on -c lock_timeout=1000',
      application_name: 'fixlevelup-profile-metadata' }) : undefined;
    const client = pinned ?? own;
    if (!client) { return false; }
    try {
      if (own) { await own.connect(); }
      await admission.gate.verifyConnection(client, new Date());
      if (!await verifyPhysicalProfile(client, target, admission.binding.profile)) { return false; }
      await admission.gate.verifyConnection(client, new Date());
      return true;
    } catch { return false; }
    finally { await own?.end().catch(() => undefined); }
  };
}
