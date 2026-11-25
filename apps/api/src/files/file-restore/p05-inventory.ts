import type { Client } from 'pg';
import { verifyClosedBase } from '../../infrastructure/database/closed-profile-base.js';
import { probeP05Catalog, S1_TABLES, S2_TABLES, S3_TABLES } from '../../infrastructure/database/p05-profile-catalog.js';
import type { P05Profile } from '../../infrastructure/database/p05-profile-catalog.js';
import type { RestorePolicyPin } from './contract.js';

export const P05_S1_TABLES: readonly string[] = S1_TABLES;
export const P05_S2_TABLES: readonly string[] = Object.freeze([...S1_TABLES, ...S2_TABLES]);
export const P05_S3_TABLES: readonly string[] = Object.freeze([...P05_S2_TABLES, ...S3_TABLES]);

type QueryClient = Pick<Client, 'query'>;
export type RestoreSchemaProfile = P05Profile;

export interface P05SourceState {
  readonly profile: Exclude<P05Profile, 'S0'>;
  readonly empty: boolean;
  readonly counts: Readonly<Record<string, number>>;
}

export class P05InventoryError extends Error {
  constructor(readonly code: 'SCHEMA_ABSENT' | 'PARTIAL_SCHEMA' | 'P05_ROWS_PRESENT') {
    super(code);
    this.name = 'P05InventoryError';
  }
}

export function p05Tables(profile: RestoreSchemaProfile): readonly string[] {
  switch (profile) {
    case 'S0': return [];
    case 'S1': return P05_S1_TABLES;
    case 'S2': return P05_S2_TABLES;
    case 'S3': return P05_S3_TABLES;
  }
}

async function requireProfile(client: QueryClient, expected?: RestoreSchemaProfile): Promise<RestoreSchemaProfile> {
  if (!(await verifyClosedBase(client))) { throw new P05InventoryError('PARTIAL_SCHEMA'); }
  for (const profile of expected === undefined ? ['S0', 'S1', 'S2', 'S3'] as const : [expected]) {
    if (await probeP05Catalog(client, profile)) { return profile; }
  }
  throw new P05InventoryError('PARTIAL_SCHEMA');
}

/** Count only reviewed, exactly verified relations. Never return row contents. */
export async function readP05SourceState(client: QueryClient, expected?: RestoreSchemaProfile): Promise<P05SourceState> {
  const profile = await requireProfile(client, expected);
  if (profile === 'S0') { throw new P05InventoryError('SCHEMA_ABSENT'); }
  const tables = p05Tables(profile);
  const projections = tables.map(table => `(SELECT count(*)::int FROM foundation.${table}) AS "${table}"`);
  const row = (await client.query<Record<string, number>>(`SELECT ${projections.join(', ')}`)).rows[0];
  const counts: Record<string, number> = {};
  for (const table of tables) {
    const count = row?.[table];
    if (count === undefined || !Number.isSafeInteger(count) || count < 0) {
      throw new P05InventoryError('PARTIAL_SCHEMA');
    }
    counts[table] = count;
  }
  return Object.freeze({ profile, empty: Object.values(counts).every(count => count === 0), counts: Object.freeze(counts) });
}

export interface P05TargetDrainState {
  readonly fact: 'P05_EMPTY_AFTER_DRAIN' | 'P05_SCHEMA_ABSENT_AFTER_DRAIN';
  readonly profile: RestoreSchemaProfile;
}

export async function readP05TargetDrainState(client: QueryClient, expected?: RestoreSchemaProfile): Promise<P05TargetDrainState> {
  let state: P05SourceState;
  try {
    state = await readP05SourceState(client, expected);
  } catch (error) {
    if (error instanceof P05InventoryError && error.code === 'SCHEMA_ABSENT') {
      return Object.freeze({ fact: 'P05_SCHEMA_ABSENT_AFTER_DRAIN', profile: 'S0' });
    }
    throw error;
  }
  if (!state.empty) { throw new P05InventoryError('P05_ROWS_PRESENT'); }
  return Object.freeze({ fact: 'P05_EMPTY_AFTER_DRAIN', profile: state.profile });
}

export interface CarriedRestorePolicy {
  readonly pin: RestorePolicyPin;
  readonly sha256: string;
}

/** Caller has verified the exact reviewed S3 schema on this connection. The sole
 * admissible package is independently pinned and physically supplied by the base.
 * Only digests leave SQL; pin validation hashes the canonical JSONB metadata, and
 * the preservation digest also covers the other columns and full timestamp. */
async function readPolicyDigest(client: QueryClient, pin: RestorePolicyPin): Promise<string> {
  if (!/^[a-z0-9][a-z0-9.-]*-v[0-9]+$/u.test(pin.workflowVersion) || pin.workflowVersion.length > 64
    || !/^[a-z0-9][a-z0-9.-]{2,67}$/u.test(pin.policyRevision) || !/^[a-f0-9]{64}$/u.test(pin.metadataSha256)) {
    throw new P05InventoryError('P05_ROWS_PRESENT');
  }
  const { rows } = await client.query<{ sha: string | null }>(`SELECT
    CASE WHEN workflow_version=$1 AND policy_revision=$2 AND metadata_sha256=$3
        AND octet_length(metadata::text)<=8192 THEN
      CASE WHEN metadata_sha256=encode(sha256(convert_to(metadata::text,'UTF8')),'hex') THEN
        encode(sha256(convert_to(jsonb_build_array('fixlevelup/restore/policy/v1',id,workflow_version,
          policy_revision,metadata_sha256,metadata,encode(timestamptz_send(created_at),'hex'))::text,'UTF8')),'hex')
      END
    END AS sha
    FROM foundation.request_policy_packages ORDER BY id LIMIT 2`, [pin.workflowVersion, pin.policyRevision, pin.metadataSha256]);
  const sha = rows[0]?.sha;
  if (rows.length !== 1 || typeof sha !== 'string' || !/^[a-f0-9]{64}$/u.test(sha)) {
    throw new P05InventoryError('P05_ROWS_PRESENT');
  }
  return sha;
}

/** Measure the pre-dump policy-only state for a new versioned snapshot. The
 * restore itself independently remeasures against the signed digest. This is
 * not the historical strict-empty inventory and never drops any table from it. */
export async function measureCarriedRestorePolicy(client: QueryClient, pin: RestorePolicyPin): Promise<string> {
  const state = await readP05SourceState(client, 'S3');
  if (state.counts['request_policy_packages'] !== 1
    || Object.entries(state.counts).some(([table, count]) => table !== 'request_policy_packages' && count !== 0)) {
    throw new P05InventoryError('P05_ROWS_PRESENT');
  }
  return readPolicyDigest(client, pin);
}

export async function readP05RestoreDrainState(client: QueryClient, profile: RestoreSchemaProfile,
  carried?: CarriedRestorePolicy): Promise<P05TargetDrainState> {
  if (carried === undefined) { return readP05TargetDrainState(client, profile); }
  if (profile !== 'S3' || await measureCarriedRestorePolicy(client, carried.pin) !== carried.sha256) {
    throw new P05InventoryError('P05_ROWS_PRESENT');
  }
  return Object.freeze({ fact: 'P05_EMPTY_AFTER_DRAIN', profile });
}

export async function assertP05AbsentAfterDrain(client: QueryClient): Promise<P05TargetDrainState['fact']> {
  return (await readP05TargetDrainState(client)).fact;
}
