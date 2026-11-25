import type { Client } from 'pg';
import { verifyClosedBase } from '../../infrastructure/database/closed-profile-base.js';
import { probeP05Catalog, S1_TABLES, S2_TABLES } from '../../infrastructure/database/p05-profile-catalog.js';

export const P05_S1_TABLES: readonly string[] = S1_TABLES;
export const P05_S2_TABLES: readonly string[] = Object.freeze([...S1_TABLES, ...S2_TABLES]);

type QueryClient = Pick<Client, 'query'>;
export type RestoreSchemaProfile = 'S0' | 'S1' | 'S2';

export interface P05SourceState {
  readonly profile: 'S1' | 'S2';
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
  }
}

async function requireProfile(client: QueryClient, expected?: RestoreSchemaProfile): Promise<RestoreSchemaProfile> {
  if (!(await verifyClosedBase(client))) { throw new P05InventoryError('PARTIAL_SCHEMA'); }
  for (const profile of expected === undefined ? ['S0', 'S1', 'S2'] as const : [expected]) {
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

export async function assertP05AbsentAfterDrain(client: QueryClient): Promise<P05TargetDrainState['fact']> {
  return (await readP05TargetDrainState(client)).fact;
}
