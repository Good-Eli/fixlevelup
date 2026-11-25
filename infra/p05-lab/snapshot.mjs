/**
 * P05 gateway (023) snapshot builder — task-1.
 *
 * The gateway image must contain EXACTLY the frozen P05-02 candidate state for
 * schema profile S2, not the current working tree: the lead is actively adding
 * S3 wiring to `p05-profile-catalog.ts` (S3 profile type, `S3_HEAD`, S3 tail of
 * `probeP05Layer`), and unfinished 024 SQL / bridge edits live next to it. None
 * of that may enter the gateway image or be mixed into a 023 measurement.
 *
 * So the one product file that differs is DERIVED here instead of copied:
 *
 *   base   = `git show <GATEWAY_COMMIT>:apps/api/src/infrastructure/database/p05-profile-catalog.ts`
 *   + only the two reviewed P05-02 (023) changes:
 *       1. `FORM_NAMESPACE_SQL` + `formNamespaceExact` and their use in the
 *          positive S2 branch of `probeP05Layer`;
 *       2. the `NO_S2` absence check also covering the separate
 *          `form_history_reject_truncate` routine of migration 023.
 *
 * Every replacement is exact-match and must occur exactly once, so a changed
 * base file fails loudly instead of silently producing a mixed snapshot.
 *
 * The two test files that assert the new reserved-object behaviour are copied
 * verbatim from the working tree (they contain no S3 wiring).
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

export const GATEWAY_COMMIT = 'f3cc8a0bc01bdf8dcc15b5230a34c161b6ee933c';
const CATALOG_PATH = 'apps/api/src/infrastructure/database/p05-profile-catalog.ts';

/** Verbatim copies of reviewed working-tree files (no S3 wiring in these). */
export const OVERLAY = [
  'apps/api/tests/runtime-database.test.ts',
  'apps/api/tests/file-restore-p05.test.ts',
];

const FORM_NAMESPACE = `// Positive S2 checks must also reject extension objects in the reserved namespace.
// The per-table hashes cannot see, for example, an independent view or table.
// Named objects on S2 tables are already checked by BASE/ENFORCEMENT; here only
// the reviewed relations/routines and their automatically created row types are
// allowed in the namespace, never a same-prefixed sibling outside those checks.
const FORM_NAMESPACE_SQL = \`WITH holders AS (
    SELECT c.oid,c.relname FROM pg_catalog.pg_class c
    WHERE c.relnamespace='foundation'::regnamespace AND c.relname=ANY($1::text[])
  ), objects(name, allowed) AS (
    SELECT c.relname, c.relname=ANY($2::text[]) FROM pg_catalog.pg_class c WHERE c.relnamespace='foundation'::regnamespace
    UNION ALL SELECT ltrim(t.typname, '_'), EXISTS (SELECT FROM holders h WHERE h.oid=t.typrelid OR h.oid=element.typrelid)
      FROM pg_catalog.pg_type t LEFT JOIN pg_catalog.pg_type element ON element.oid=t.typelem
      WHERE t.typnamespace='foundation'::regnamespace
    UNION ALL SELECT p.proname, p.proname=ANY($3::text[]) FROM pg_catalog.pg_proc p WHERE p.pronamespace='foundation'::regnamespace
    UNION ALL SELECT k.conname, EXISTS (SELECT FROM holders h WHERE h.oid=k.conrelid)
      FROM pg_catalog.pg_constraint k WHERE k.connamespace='foundation'::regnamespace
    UNION ALL SELECT g.tgname, EXISTS (SELECT FROM holders h WHERE h.oid=g.tgrelid)
      FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid=g.tgrelid
      WHERE c.relnamespace='foundation'::regnamespace AND NOT g.tgisinternal
  ) SELECT NOT EXISTS (SELECT FROM objects o CROSS JOIN unnest($4::text[]) AS stem(name)
    WHERE NOT o.allowed AND (o.name=stem.name OR starts_with(o.name,stem.name||'_'))) AS exact\`;

async function formNamespaceExact(client: CatalogClient): Promise<boolean> {
  const relations = [...S2_TABLES, ...S2_TABLES.map((name) => name + '_pkey'), ...formIndexes];
  return (await client.query<{ exact: boolean }>(FORM_NAMESPACE_SQL, [S2_TABLES, relations, S2_FUNCTIONS,
    [...S2_TABLES, 'form_history_reject_truncate']])).rows[0]?.exact === true;
}

`;

/** [anchor, replacement] pairs applied to the frozen HEAD file, each exactly once. */
const PATCHES = [
  // 1. The reserved-namespace guard itself, inserted before probeP05Layer.
  [
    'export async function probeP05Layer(client: CatalogClient, layer: Layer | \'NO_S1\' | \'NO_S2\'): Promise<boolean> {',
    FORM_NAMESPACE + 'export async function probeP05Layer(client: CatalogClient, layer: Layer | \'NO_S1\' | \'NO_S2\'): Promise<boolean> {',
  ],
  // 2. NO_S2 absence also covers the separate 023 history TRUNCATE routine.
  [
    `      return (await client.query<{ absent: boolean }>(ABSENCE_SQL, [names, first ? S1_FUNCTIONS : S2_FUNCTIONS, triggers, tables])).rows[0]?.absent === true;`,
    `      return (await client.query<{ absent: boolean }>(ABSENCE_SQL, [names, first ? S1_FUNCTIONS : S2_FUNCTIONS, triggers,
        first ? tables : [...tables, 'form_history_reject_truncate']])).rows[0]?.absent === true;`,
  ],
  // 3. Positive S2 additionally requires the exact reserved namespace.
  [
    `      && m.enforcement === ENFORCEMENT_PINS[layer];`,
    `      && m.enforcement === ENFORCEMENT_PINS[layer] && (layer !== 'S2' || await formNamespaceExact(client));`,
  ],
];

function frozenHeadFile(root, path) {
  return execFileSync('git', ['show', `${GATEWAY_COMMIT}:${path}`], { cwd: root, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
}

/** Builds the gateway 023 snapshot of `p05-profile-catalog.ts`. */
export function buildCatalogSnapshot(root) {
  let text = frozenHeadFile(root, CATALOG_PATH);
  for (const [anchor, replacement] of PATCHES) {
    const occurrences = text.split(anchor).length - 1;
    if (occurrences !== 1) {
      throw new Error(`Gateway snapshot anchor must occur exactly once (found ${String(occurrences)})`);
    }
    text = text.replace(anchor, replacement);
  }
  // The S3 wiring must NOT be present in the gateway snapshot.
  for (const forbidden of ['P05Profile', 'S3_HEAD', "'S3'", 'request_intake_effects']) {
    if (text.includes(forbidden)) { throw new Error(`Gateway snapshot leaked S3 wiring: ${forbidden}`); }
  }
  return text;
}

export function sha256(text) { return createHash('sha256').update(text).digest('hex'); }

/** Overlay/derived file map for the frozen tree. */
export function gatewayFiles(root) {
  const files = new Map();
  for (const path of OVERLAY) { files.set(path, readFileSync(resolve(root, path), 'utf8')); }
  files.set(CATALOG_PATH, buildCatalogSnapshot(root));
  return files;
}
