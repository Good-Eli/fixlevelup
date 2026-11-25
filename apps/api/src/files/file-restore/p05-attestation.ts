import { randomUUID } from 'node:crypto';

export type P05DrainFact = 'P05_EMPTY_AFTER_DRAIN' | 'P05_SCHEMA_ABSENT_AFTER_DRAIN';

/**
 * Typed P05 drain fact the future operator bridge will sign alongside the existing
 * snapshot/authority/approval records (records.ts integration is a later slice).
 * Only the exact attested identity fields and a fresh nonce cross; no P05 row, key or secret.
 *
 * MUST 11 (Astra round 1): the nonce is the handoff's CHALLENGE echoed back —
 * requireP05ProfileFact accepts an optional expectedChallenge and the source
 * handoff (requireP05SourceDrained) passes its own challenge, so the answer is
 * bound to this run, this manifest and this observation, never a self-minted
 * UUID.
 */
export interface P05RestoreAttestation {
  readonly kind: P05DrainFact;
  readonly sourceDatabase: string;
  readonly sourceSchemaProfile: 'S0' | 'S1' | 'S2';
  readonly nonce: string;
  readonly recordedAt: string;
}

export function buildP05Attestation(input: { sourceDatabase: string; sourceSchemaProfile: 'S0' | 'S1' | 'S2';
  fact: P05DrainFact; now: Date }): P05RestoreAttestation {
  return Object.freeze({ kind: input.fact, sourceDatabase: input.sourceDatabase,
    sourceSchemaProfile: input.sourceSchemaProfile, nonce: randomUUID(), recordedAt: input.now.toISOString() });
}

/** The fact a source profile can attest: schema absence only for the pre-P05 profile S0, emptiness only for S1/S2. */
function factForProfile(profile: 'S0' | 'S1' | 'S2'): P05DrainFact {
  return profile === 'S0' ? 'P05_SCHEMA_ABSENT_AFTER_DRAIN' : 'P05_EMPTY_AFTER_DRAIN';
}

/** Exact source database and schema profile, the profile-consistent drain fact, and a recording time within `maxAgeMs` of `now`. */
export function verifyP05Attestation(attestation: P05RestoreAttestation,
  input: { sourceDatabase: string; sourceSchemaProfile: 'S0' | 'S1' | 'S2'; fact?: P05DrainFact; maxAgeMs: number; now: Date }): boolean {
  const recordedAt = Date.parse(attestation.recordedAt);
  const verifyAt = input.now.getTime();
  return attestation.kind === factForProfile(attestation.sourceSchemaProfile)
    && (input.fact === undefined || input.fact === attestation.kind)
    && attestation.sourceDatabase === input.sourceDatabase
    && attestation.sourceSchemaProfile === input.sourceSchemaProfile
    && Number.isFinite(recordedAt) && recordedAt >= verifyAt - input.maxAgeMs && recordedAt <= verifyAt;
}
