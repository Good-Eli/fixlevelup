/**
 * P05-03/P05-04 test-only request-intake seed (task-8).
 *
 * Purpose: give the HTTP/wire suites a *complete, authoritative* P05 basis on an
 * isolated disposable database — the exact same relations and writer fences the
 * real ports read — without inventing a second business schema and without any
 * contact with the working/dev database.
 *
 * What is seeded (all through reviewed DDL, never through the port under test):
 *  - one ACTIVE `SINGLE_CITY` city + reviewed city version, plus the published
 *    company settings revision the resolver reads;
 *  - one administrative district, one published service area version mapped to
 *    it (coverage basis), all under the unified GEO/CFG writer fence;
 *  - typed COMPANY references (REQUEST_SOURCE, CANCEL_REASON) and one CITY
 *    CALLBACK_INTERVAL, current pointers included;
 *  - a published CATEGORY + FAULT pair of the same category (P04 catalog
 *    writer fence, as a reviewed publisher would);
 *  - the current REQUEST_PROCESSING CONSENT_FORM document/version (and an
 *    optional POLICY document for the legal-document read surface);
 *  - the immutable `request_policy_packages` row for `wf-r2-p05-v1` /
 *    `p05-intake-r1`, whose `metadata_sha256` is computed by PostgreSQL over the
 *    exact stored `jsonb::text` — the same expression `RequestIntake.rules`
 *    re-checks at runtime.
 *
 * This module is test-only: it refuses to run unless the isolated-DB opt-in is
 * set and the connected database is one of the reviewed disposable fixture
 * names. It never targets `fixlevelup_dev` and never runs on a lab gateway
 * database. Everything it writes is synthetic public data ("Synthetic ...",
 * `+70000000000`, `synthetic:` source refs); no real personal data is used.
 */
import { randomUUID } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import { policyPairKey } from '../src/requests/workflow/registry.js';

/** The immutable workflow package this build supports (docs/P05-PLAN.md §6). */
export const REQUEST_WORKFLOW_VERSION = 'wf-r2-p05-v1' as const;
/** The technical policy revision paired with it (never a real business policy). */
export const REQUEST_POLICY_REVISION = 'p05-intake-r1' as const;
/** Historical second package for supported-vs-unsupported pair checks. */
export const HISTORICAL_WORKFLOW_VERSION = 'wf-r2-p05-v0' as const;
export const HISTORICAL_POLICY_REVISION = 'p05-intake-r0' as const;

const ISOLATED_FLAG = 'FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS';
/**
 * Reviewed disposable namespaces (the same allowlist the owned-database helper
 * enforces). The seeder must never touch a lab gateway database or the dev DB.
 */
const DISPOSABLE = /^fixlevelup_(?:configuration|rbac|legal|auth_e2e|bootstrap|recovery|tg_auth|web_auth)_test_[a-f0-9]{24}$/;

/** Unified GEO/CFG writer fence (022 `geo_cfg_fence_guard`). */
const GEO_CFG_FENCE = 'SELECT pg_catalog.pg_advisory_xact_lock(734305,1)';
/** P04 catalog writer fence (019 `catalog_lock_write`). */
const CATALOG_FENCE = 'SELECT pg_catalog.pg_advisory_xact_lock(77304,1)';

/** Minimal `RbacFixture` surface this seeder needs (`fixture.db` satisfies it). */
export interface RequestFixtureBase {
  readonly db: Pool;
}

export interface RequestFixtures {
  /** Reviewed staff identity used as `reviewed_by`/`created_by`/`published_by`. */
  readonly reviewerId: string;
  readonly timezone: string;
  /** ACTIVE city + reviewed current version (the `SINGLE_CITY` target). */
  readonly cityId: string;
  readonly cityVersionId: string;
  /** Published company settings revision that makes the city resolvable. */
  readonly settingsVersionId: string;
  readonly settingsVersion: number;
  /** Coverage basis: district + published area version + FULL coverage mapping. */
  readonly districtId: string;
  readonly areaId: string;
  readonly areaVersionId: string;
  /** COMPANY-scoped typed references (current pointers set). */
  readonly formSourceEntryId: string;
  readonly cancelReasonEntryId: string;
  /** CITY-scoped CALLBACK_INTERVAL (current pointer set). */
  readonly callbackIntervalEntryId: string;
  /** Published catalog CATEGORY and a FAULT of the same category. */
  readonly categoryId: string;
  readonly faultId: string;
  /** Current REQUEST_PROCESSING CONSENT_FORM document + exact current version. */
  readonly consentDocumentId: string;
  readonly consentDocumentVersionId: string;
  /** Optional REQUEST_PROCESSING POLICY document + current version. */
  readonly policyDocumentId: string;
  readonly policyDocumentVersionId: string;
  /** Immutable intake/workflow package: `wf-r2-p05-v1` / `p05-intake-r1`. */
  readonly policyId: string;
  readonly workflowVersion: typeof REQUEST_WORKFLOW_VERSION;
  readonly policyRevision: typeof REQUEST_POLICY_REVISION;
  /** `sha256` of the exact stored `metadata::text`, as PostgreSQL computes it. */
  readonly policyMetadataSha256: string;
}

export interface PolicyPackage {
  readonly id: string;
  readonly workflowVersion: string;
  readonly policyRevision: string;
  readonly metadataSha256: string;
}

export interface SeedRequestFixtureOptions {
  /** Reviewer/author staff id. Default: the oldest ACTIVE staff row. */
  readonly reviewerId?: string;
  readonly timezone?: string;
  readonly consentBody?: string;
  readonly policyMetadata?: Readonly<Record<string, unknown>>;
}

export function requireFixtureCluster(): string {
  const cluster = process.env['FIXLEVELUP_CLUSTER_NAME'] ?? '';
  if (process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] !== '1' || process.env[ISOLATED_FLAG] !== '1'
    || !/^fixlevelup_p05s4_lab_[a-z0-9_]{1,40}$/.test(cluster)) {
    throw new Error('P05 request fixtures require the isolated lab');
  }
  return cluster;
}

/** Check physical identity on the same connection before any fixture reads/writes. */
export async function attestDisposableFixture(client: Pick<PoolClient,'query'>, access: 'WRITE' | 'READ' = 'WRITE'): Promise<string> {
  const cluster = requireFixtureCluster();
  const { rows:[fact] } = await client.query<{ db: string; lab: boolean }>(`SELECT current_database() AS db,
    current_setting('cluster_name')=$1 AND current_setting('server_version_num')='180007'
    AND (current_user='fixlevelup_migrator' OR ($2::boolean AND current_user='fixlevelup_runtime'))
    AND session_user=current_user AND NOT pg_is_in_recovery()
    AND host(inet_server_addr())='127.0.0.1' AND inet_server_port()=55432 AS lab`, [cluster, access === 'READ']);
  if (!fact?.lab || !DISPOSABLE.test(fact.db)) { throw new Error('Refusing non-lab request fixture'); }
  return fact.db;
}

/** One explicit transaction on one pinned client; caller owns commit/rollback. */
async function transaction<T>(db: Pool, run: (client: PoolClient) => Promise<T>): Promise<T> {
  requireFixtureCluster();
  const client = await db.connect();
  let began = false;
  try {
    await attestDisposableFixture(client);
    await client.query('BEGIN');
    began = true;
    const result = await run(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    if (began) { await client.query('ROLLBACK').catch(() => undefined); }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * One writer transaction under the reviewed fences. Catalog DML is taken under
 * the P04 fence first (the 019 trigger would take it anyway) and the GEO/CFG
 * basis writes under the unified fence, matching the order the reviewed writer
 * paths use. The transaction wrapper first attests the actual connection.
 */
async function fenced<T>(db: Pool, run: (client: PoolClient) => Promise<T>): Promise<T> {
  return await transaction(db, async (client) => {
    await client.query(CATALOG_FENCE);
    await client.query(GEO_CFG_FENCE);
    return await run(client);
  });
}

/**
 * Seeds one complete P05 intake basis. Call once per isolated fixture, after the
 * fixture's own provisioning (e.g. `RbacFixture.start()`), with the migrator
 * pool as `base.db`; the ports under test then read it as `fixlevelup_runtime`.
 */
export async function seedRequestFixtures(
  base: RequestFixtureBase,
  options: SeedRequestFixtureOptions = {},
): Promise<RequestFixtures> {
  const timezone = options.timezone ?? 'Europe/Moscow';
  const consentBody = options.consentBody ?? 'Synthetic REQUEST_PROCESSING consent text.';
  const metadata = options.policyMetadata ?? {
    purpose: 'REQUEST_CONFIRMATION',
    source: 'synthetic-fixture',
    revision: 1,
  };
  const cityId = randomUUID();
  const cityVersionId = randomUUID();
  const settingsVersionId = randomUUID();
  const districtId = randomUUID();
  const areaId = randomUUID();
  const areaVersionId = randomUUID();
  const formSourceEntryId = randomUUID();
  const cancelReasonEntryId = randomUUID();
  const callbackIntervalEntryId = randomUUID();
  const categoryId = randomUUID();
  const faultId = randomUUID();
  const consentDocumentId = randomUUID();
  const consentDocumentVersionId = randomUUID();
  const policyDocumentId = randomUUID();
  const policyDocumentVersionId = randomUUID();
  const policyId = randomUUID();
  const officeHours = JSON.stringify(Array.from({ length: 7 }, () => [[540, 1080]]));

  const seeded = await fenced(base.db, async (client) => {
    const reviewerId = options.reviewerId ?? await defaultReviewer(client);
    // Exactly one ACTIVE city is a hard precondition of the SINGLE_CITY
    // resolver, so a second seed on the same database is refused instead of
    // silently making the city context unresolvable.
    const active = await client.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM foundation.service_cities WHERE lifecycle='ACTIVE'");
    if ((active.rows[0]?.n ?? 0) !== 0) {
      throw new Error('P05 request fixtures must be seeded once on an empty-city database');
    }
    // 1. ACTIVE single city with one reviewed version, then the published
    //    SINGLE_CITY settings revision that points at it.
    await client.query('INSERT INTO foundation.service_cities (id,code) VALUES ($1,$2)',
      [cityId, `p05-city-${cityId.slice(0, 8)}`]);
    await client.query(`INSERT INTO foundation.service_city_versions
      (id,city_id,version,display_name,timezone,public_contact,office_hours,reviewed_by)
      VALUES ($1,$2,1,'Synthetic P05 city',$3,'+70000000000',$4::jsonb,$5)`,
    [cityVersionId, cityId, timezone, officeHours, reviewerId]);
    await client.query("UPDATE foundation.service_cities SET current_version_id=$2,lifecycle='ACTIVE' WHERE id=$1",
      [cityId, cityVersionId]);
    const settings = await client.query<{ version: number }>(`INSERT INTO foundation.business_settings_versions
      (id,version,launch_mode,primary_city_id,reviewed_by)
      SELECT $1,COALESCE(max(version),0)+1,'SINGLE_CITY',$2,$3 FROM foundation.business_settings_versions
      RETURNING version`, [settingsVersionId, cityId, reviewerId]);

    // 2. Coverage basis: district, published area version, explicit FULL mapping.
    await client.query(`INSERT INTO foundation.administrative_districts (id,city_id,code,name)
      VALUES ($1,$2,'p05-district','Synthetic district')`, [districtId, cityId]);
    await client.query('INSERT INTO foundation.service_areas (id,city_id,code) VALUES ($1,$2,$3)',
      [areaId, cityId, 'p05-area']);
    // The reviewed lifecycle is: INSERT as a draft, map the districts while it
    // is still a draft, then publish with a content-preserving UPDATE.
    await client.query(`INSERT INTO foundation.service_area_versions
      (id,city_id,area_id,version,name,created_by)
      VALUES ($1,$2,$3,1,'Synthetic area',$4)`, [areaVersionId, cityId, areaId, reviewerId]);
    await client.query(`INSERT INTO foundation.service_area_district_coverage
      (city_id,area_version_id,district_id,relation) VALUES ($1,$2,$3,'FULL')`,
    [cityId, areaVersionId, districtId]);
    await client.query(`UPDATE foundation.service_area_versions
      SET published_at=clock_timestamp(), published_by=$2 WHERE id=$1`, [areaVersionId, reviewerId]);
    await client.query('UPDATE foundation.service_areas SET current_version_id=$2 WHERE id=$1',
      [areaId, areaVersionId]);

    // 3. Typed references: COMPANY source/cancel reason and one CITY interval.
    type ReferenceType = 'REQUEST_SOURCE' | 'CANCEL_REASON' | 'CALLBACK_INTERVAL';
    const references: readonly [string, ReferenceType, string | null, string, string | null][] = [
      [formSourceEntryId, 'REQUEST_SOURCE', null, 'P05_SOURCE', null],
      [cancelReasonEntryId, 'CANCEL_REASON', null, 'P05_CANCEL', null],
      [callbackIntervalEntryId, 'CALLBACK_INTERVAL', cityId, 'P05_CALLBACK_15', cityVersionId],
    ];
    for (const [entryId, type, entryCityId, code, cityVersion] of references) {
      await client.query(`INSERT INTO foundation.reference_entries (id,type,scope,city_id,code)
        VALUES ($1,$2,$3,$4,$5)`, [entryId, type, entryCityId === null ? 'COMPANY' : 'CITY', entryCityId, code]);
      const versionId = randomUUID();
      await client.query(`INSERT INTO foundation.reference_entry_versions
        (id,entry_id,type,city_id,version,label,valid_from,valid_until,source_ref,reviewed_by,
          city_version_id,start_minute,end_minute)
        VALUES ($1,$2,$3,$4,1,$5,clock_timestamp(),NULL,'synthetic:p05',$6,$7,$8,$9)`,
      [versionId, entryId, type, entryCityId,
        type === 'CALLBACK_INTERVAL' ? 'Synthetic 09:00-10:00' : `Synthetic ${type}`,
        reviewerId, cityVersion,
        type === 'CALLBACK_INTERVAL' ? 540 : null, type === 'CALLBACK_INTERVAL' ? 600 : null]);
      await client.query('UPDATE foundation.reference_entries SET current_version_id=$2 WHERE id=$1',
        [entryId, versionId]);
    }

    // 4. Catalog: published CATEGORY, then a FAULT of that same category.
    await client.query("INSERT INTO foundation.catalog_directory_entries (id,kind,code) VALUES ($1,'CATEGORY','p05-category')",
      [categoryId]);
    const categoryVersionId = randomUUID();
    await client.query(`INSERT INTO foundation.catalog_directory_versions (id,entry_id,version,title,reviewed_by)
      VALUES ($1,$2,1,'Synthetic category',$3)`, [categoryVersionId, categoryId, reviewerId]);
    await client.query('UPDATE foundation.catalog_directory_entries SET current_version_id=$2 WHERE id=$1',
      [categoryId, categoryVersionId]);
    await client.query("INSERT INTO foundation.catalog_directory_entries (id,kind,code,category_id) VALUES ($1,'FAULT','p05-fault',$2)",
      [faultId, categoryId]);
    const faultVersionId = randomUUID();
    await client.query(`INSERT INTO foundation.catalog_directory_versions (id,entry_id,version,title,reviewed_by)
      VALUES ($1,$2,1,'Synthetic fault',$3)`, [faultVersionId, faultId, reviewerId]);
    await client.query('UPDATE foundation.catalog_directory_entries SET current_version_id=$2 WHERE id=$1',
      [faultId, faultVersionId]);

    // 5. Legal: current CONSENT_FORM (core) and a POLICY document (optional
    //    read surface). The checksum is computed by PostgreSQL over the exact
    //    UTF-8 body, exactly as the 013 CHECK re-verifies it.
    const documents: readonly [string, string, string, string, string][] = [
      [consentDocumentId, 'CONSENT_FORM', consentDocumentVersionId, 'Synthetic consent form', consentBody],
      [policyDocumentId, 'POLICY', policyDocumentVersionId, 'Synthetic processing policy',
        'Synthetic REQUEST_PROCESSING policy text.'],
    ];
    for (const [documentId, kind, versionId, title, body] of documents) {
      await client.query("INSERT INTO foundation.legal_documents (id,purpose,kind) VALUES ($1,'REQUEST_PROCESSING',$2)",
        [documentId, kind]);
      await client.query(`INSERT INTO foundation.legal_document_versions
        (id,document_id,purpose,kind,version,title,body,checksum,legal_basis,source_ref,reviewed_by)
        VALUES ($1,$2,'REQUEST_PROCESSING',$3,1,$4,$5,
          encode(sha256(convert_to($5,'UTF8')),'hex'),'synthetic basis','synthetic:p05',$6)`,
      [versionId, documentId, kind, title, body, reviewerId]);
      await client.query('UPDATE foundation.legal_documents SET current_version_id=$2 WHERE id=$1',
        [documentId, versionId]);
    }

    // 6. Immutable workflow/policy package. The digest is produced by the same
    //    expression the runtime re-checks (`metadata_sha256 = sha256(metadata::text)`).
    const policy = await client.query<{ metadata_sha256: string }>(`INSERT INTO foundation.request_policy_packages
      (id,workflow_version,policy_revision,metadata_sha256,metadata)
      VALUES ($1,$2,$3,encode(sha256(convert_to($4::jsonb::text,'UTF8')),'hex'),$4::jsonb)
      RETURNING metadata_sha256`,
    [policyId, REQUEST_WORKFLOW_VERSION, REQUEST_POLICY_REVISION, JSON.stringify(metadata)]);

    return {
      reviewerId,
      settingsVersion: settings.rows[0]?.version,
      policyMetadataSha256: policy.rows[0]?.metadata_sha256,
    };
  });

  const settingsVersion = seeded.settingsVersion;
  const policyMetadataSha256 = seeded.policyMetadataSha256;
  if (typeof settingsVersion !== 'number' || typeof policyMetadataSha256 !== 'string') {
    throw new Error('P05 request fixture seed did not return its published facts');
  }
  return Object.freeze({
    reviewerId: seeded.reviewerId,
    timezone,
    cityId,
    cityVersionId,
    settingsVersionId,
    settingsVersion,
    districtId,
    areaId,
    areaVersionId,
    formSourceEntryId,
    cancelReasonEntryId,
    callbackIntervalEntryId,
    categoryId,
    faultId,
    consentDocumentId,
    consentDocumentVersionId,
    policyDocumentId,
    policyDocumentVersionId,
    policyId,
    workflowVersion: REQUEST_WORKFLOW_VERSION,
    policyRevision: REQUEST_POLICY_REVISION,
    policyMetadataSha256,
  });
}

/** Independently pinned sha256 of the exact jsonb text for the default
 * synthetic policy. Never learn the allowlist from the request database. */
export const REQUEST_POLICY_METADATA_SHA256 = 'dd8cefc974ab86ffd5294a523c668d9384db6aaefd1451e6759656015467893e';
export function supportedFixturePolicies(): ReadonlyMap<string,string> {
  return new Map([[policyPairKey(REQUEST_WORKFLOW_VERSION,REQUEST_POLICY_REVISION),REQUEST_POLICY_METADATA_SHA256]]);
}

/** The oldest ACTIVE staff row: the synthetic reviewer of every seeded revision. */
async function defaultReviewer(client: PoolClient): Promise<string> {
  const rows = await client.query<{ id: string }>(
    "SELECT id FROM foundation.staff WHERE employment_state='ACTIVE' ORDER BY created_at ASC LIMIT 1");
  const id = rows.rows[0]?.id;
  if (id === undefined) {
    throw new Error('P05 request fixtures need an ACTIVE staff row (start the fixture first)');
  }
  return id;
}

/**
 * Seeds one extra immutable policy package — the documented way to obtain the
 * *historical/second* supported-or-unsupported package for supported-vs-stale
 * pair checks (`classifyPolicyPair`). Nothing here chooses a business policy:
 * the caller states the exact workflow/revision pair and metadata.
 *
 * A package is immutable by DDL, so this only ever INSERTs a new row; reusing
 * the default `wf-r2-p05-v1` / `p05-intake-r1` pair fails on the unique key
 * instead of silently rewriting the current package.
 */
export async function seedPolicyPackage(
  base: RequestFixtureBase,
  options: {
    readonly workflowVersion?: string;
    readonly policyRevision?: string;
    readonly metadata?: Readonly<Record<string, unknown>>;
  } = {},
): Promise<PolicyPackage> {
  const workflowVersion = options.workflowVersion ?? HISTORICAL_WORKFLOW_VERSION;
  const policyRevision = options.policyRevision ?? HISTORICAL_POLICY_REVISION;
  const metadata = options.metadata ?? { purpose: 'REQUEST_CONFIRMATION', source: 'synthetic-history', revision: 0 };
  const id = randomUUID();
  return await transaction(base.db, async (client) => {
    const result = await client.query<{ metadata_sha256: string }>(`INSERT INTO foundation.request_policy_packages
      (id,workflow_version,policy_revision,metadata_sha256,metadata)
      VALUES ($1,$2,$3,encode(sha256(convert_to($4::jsonb::text,'UTF8')),'hex'),$4::jsonb)
      RETURNING metadata_sha256`, [id, workflowVersion, policyRevision, JSON.stringify(metadata)]);
    const metadataSha256 = result.rows[0]?.metadata_sha256;
    if (typeof metadataSha256 !== 'string') {
      throw new Error('P05 policy package fixture did not return its digest');
    }
    return Object.freeze({ id, workflowVersion, policyRevision, metadataSha256 });
  });
}
