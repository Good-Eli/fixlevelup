import type { Pool } from 'pg';

/** Exact reviewed 022 relations of the P05 operational schema, unqualified like AUTHORITY_TABLES. */
export const P05_TABLES: readonly string[] = Object.freeze([
  'request_policy_packages', 'customers', 'requests', 'request_payload_cells', 'request_contact_revisions',
  'request_address_revisions', 'request_appliance_revisions', 'request_faults', 'request_preference_revisions',
  'request_events',
]);

export interface P05SourceState {
  readonly profile: 'S1';
  readonly empty: boolean;
  readonly counts: Readonly<Record<string, number>>;
}

export class P05InventoryError extends Error {
  constructor(readonly code: 'SCHEMA_ABSENT' | 'PARTIAL_SCHEMA' | 'P05_ROWS_PRESENT') {
    super(code);
    this.name = 'P05InventoryError';
  }
}

type QueryClient = Pick<Pool, 'query'>;

function isUndefinedTable(error: unknown): boolean {
  return error instanceof Error && 'code' in error && error.code === '42P01';
}

/** Relations of the closed P05 list that currently exist in foundation. */
async function presentP05Tables(client: QueryClient): Promise<readonly string[]> {
  const { rows } = await client.query<{ relname: string }>(
    'SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace'
    + ' WHERE n.nspname = \'foundation\' AND c.relname = ANY($1)',
    [[...P05_TABLES]],
  );
  return rows.map(row => row.relname);
}

/** Fresh post-drain fact about the closed source primary. Integer counts only: no P05 row ever crosses this boundary. */
export async function readP05SourceState(client: QueryClient): Promise<P05SourceState> {
  const present = await presentP05Tables(client);
  if (present.length === 0) {throw new P05InventoryError('SCHEMA_ABSENT');}
  // A proper pre-P05 source has none of the listed relations; anything between
  // none and all is unknown drift (e.g. a half-dropped P05 schema) and must be
  // refused, never downgraded to a positive drain fact (plan §5.3).
  if (present.length !== P05_TABLES.length) {throw new P05InventoryError('PARTIAL_SCHEMA');}
  const projections = P05_TABLES.map(table => `(SELECT count(*)::int FROM foundation.${table}) AS "${table}"`);
  let row: Partial<Record<string, number>> | undefined;
  try {
    const counted = await client.query<Record<string, number>>(`SELECT ${projections.join(', ')}`);
    row = counted.rows[0];
  } catch (error) {
    // Defensive re-check: the catalog probe above proved every table present, so
    // a missing relation here means concurrent DDL drift and must refuse.
    if (isUndefinedTable(error)) {throw new P05InventoryError('PARTIAL_SCHEMA');}
    throw error;
  }
  if (row === undefined) {throw new Error('P05 inventory query returned no row');}
  const counts: Record<string, number> = {};
  for (const table of P05_TABLES) {
    const count = row[table];
    if (typeof count !== 'number' || !Number.isSafeInteger(count) || count < 0) {
      throw new Error(`Malformed P05 count for ${table}`);
    }
    counts[table] = count;
  }
  return Object.freeze({ profile: 'S1', empty: Object.values(counts).every(count => count === 0), counts });
}

/** Attestation fact for the restore gate: activation is refused while any P05 operational row survives the drain. */
export async function assertP05AbsentAfterDrain(client: QueryClient): Promise<'P05_EMPTY_AFTER_DRAIN' | 'P05_SCHEMA_ABSENT_AFTER_DRAIN'> {
  let state: P05SourceState;
  try {
    state = await readP05SourceState(client);
  } catch (error) {
    if (error instanceof P05InventoryError && error.code === 'SCHEMA_ABSENT') {return 'P05_SCHEMA_ABSENT_AFTER_DRAIN';}
    throw error;
  }
  if (!state.empty) {throw new P05InventoryError('P05_ROWS_PRESENT');}
  return 'P05_EMPTY_AFTER_DRAIN';
}
