/**
 * Exact physical-profile check for the process admission handshake (§7 item
 * 2): a correct identity and a live witness must NOT admit a drifted schema.
 * The profile is EXACT and POSITIVE in both directions (audit rounds 6–7):
 *
 *  - every profile requires the legacy readiness (P02/P03/P04 predicates)
 *    AND the separate P04 catalog gate — an S1 database that lost a legacy
 *    or P04 guard is refused exactly like a drifted 022;
 *  - S1 ADDITIONALLY requires requestIntakeReady (the exact 022 fingerprint);
 *  - S0 ADDITIONALLY requires the POSITIVE absence of every 022 object
 *    (preIntakeProfileAbsent): never inferred from a false S1 probe, which
 *    also means "drifted 022" or "probe error". A damaged 022 — tables
 *    present, a guard dropped — is neither profile and is refused.
 *
 * Both probes run through the guarded pool bound to the SAME admission, so
 * the witness is re-verified on acquire and a drifted fingerprint fails
 * closed.
 */
import { RuntimeDatabase } from '../database/runtime-database.js';
import type { DatabaseConfig } from '../database/runtime-database.js';
import type { RuntimeAdmission } from './runtime-admission.js';

export type ProfileVerifier = (admission: RuntimeAdmission) => Promise<boolean>;

/** Builds the exact profile verifier for the configured application database. */
export function physicalProfileVerifier(database: DatabaseConfig): ProfileVerifier {
  return async (admission: RuntimeAdmission): Promise<boolean> => {
    const runtime = new RuntimeDatabase(database, true, admission);
    try {
      const legacyReady = await runtime.ready();
      const catalogReady = await runtime.catalogManagementReady();
      if (!legacyReady || !catalogReady) { return false; }
      if (admission.binding.profile === 'S1') { return await runtime.requestIntakeReady(); }
      // S0: the pre-022 profile, verified by the positive absence of 022.
      return await runtime.preIntakeProfileAbsent();
    } finally {
      await runtime.onModuleDestroy();
    }
  };
}
