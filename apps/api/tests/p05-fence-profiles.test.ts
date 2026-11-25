/** P05 §5.1: compatible production GEO/CFG ports, not the already-proved legacy 021 gap. */
import 'reflect-metadata';
import { randomBytes, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import type { Pool, PoolClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { probeP05Catalog } from '../src/infrastructure/database/p05-profile-catalog.js';
import type { P05Profile } from '../src/infrastructure/database/p05-profile-catalog.js';
import { activeReference, currentCity, geoFence } from '../src/requests/intake/basis.js';
import { COVERAGE_BASIS_DEFAULT_CAP, readCoverageBasis, reproofCoverageBasis } from '../src/requests/intake/coverage.js';
import type { CoverageMapping, CoverageZone } from '../src/requests/intake/coverage.js';
import { RequestFailure } from '../src/requests/intake/errors.js';
import { acquireCompanySettingsLock } from '../src/settings/configuration/company-lock.js';
import { archiveReferenceEntry, createReferenceEntry, publishReferenceVersion, readReferenceSnapshot } from '../src/settings/configuration/references.js';
import type { SingleCityContext } from '../src/settings/geography/city-context.js';
import type { GeographyAuthorizationApi, GeoReceipt, GeoTarget } from '../src/settings/geography/geo-contract.js';
import { GeoRunner } from '../src/settings/geography/geo-runner.js';
import type { GeoOperation } from '../src/settings/geography/geo-runner.js';
import { authFixtureMigrations } from './auth-db-fixture.js';
import { createConfigurationFixture, createSyntheticCity, createSyntheticSettingsBaseline } from './configuration-fixture.js';
import type { ConfigurationFixture, SyntheticCity } from './configuration-fixture.js';
import { attestDisposableFixture } from './p05-request-fixtures.js';

const lab = process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] === '1'
  && process.env['FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS'] === '1' ? describe : describe.skip;
const profiles = [
  { profile: 'S0', count: 21, capBefore: '20261123000100_request_intake_foundation' },
  { profile: 'S1', count: 22, capBefore: '20261124000100_form_session_foundation' },
  { profile: 'S2', count: 23, capBefore: '20261125000100_request_intake_effects' },
  { profile: 'S3', count: 24, capBefore: undefined },
] as const;
const schedules = ['writer-first rollback', 'writer-first commit', 'reader-first commit'] as const;
const writers = ['primary replacement', 'city version publish', 'new overlap publication',
  'reference republish', 'reference archive'] as const;
type Writer = typeof writers[number];
type Schedule = typeof schedules[number];
type Reference = Awaited<ReturnType<typeof publishReferenceVersion>>;
const cap = COVERAGE_BASIS_DEFAULT_CAP;
const validFrom = '2020-01-01T00:00:00.000Z';
const referenceType = 'CALLBACK_INTERVAL';
const originalInterval = { startMinute: 540, endMinute: 600 };
const revisedInterval = { startMinute: 660, endMinute: 750 };
const revisedLabel = 'Synthetic republished interval';

interface Address { requestId: string; addressId: string }
interface CitySeed {
  city: SyntheticCity;
  districtId: string;
  originalZone: CoverageZone;
  address: Address | null;
}
interface GeoFacts {
  zones: readonly CoverageZone[];
  mappings: readonly CoverageMapping[];
  basis: Awaited<ReturnType<typeof readCoverageBasis>> | null;
}
interface Facts extends GeoFacts {
  city: SingleCityContext;
  reference: {
    entryId: string;
    versionId: string;
    sequence: number;
    label: string;
    interval: { startMinute: number; endMinute: number } | null;
    timezone: string | null;
    timezoneCityVersionId: string | null;
    provenanceCityVersionId: string | null;
    archived: boolean;
    active: boolean;
  };
}

async function configureTransaction(client: PoolClient): Promise<void> {
  await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
  await client.query("SET LOCAL lock_timeout='8s'; SET LOCAL statement_timeout='12s'");
}

async function beginRuntime(client: PoolClient): Promise<number> {
  await configureTransaction(client);
  const { rows: [row] } = await client.query<{ pid: number; isolation: string; runtime: boolean }>(`SELECT
    pg_catalog.pg_backend_pid() AS pid, current_setting('transaction_isolation') AS isolation,
    current_user='fixlevelup_runtime' AND session_user=current_user AS runtime`);
  expect(row).toMatchObject({ isolation: 'read committed', runtime: true });
  if (!row) { throw new Error('Missing runtime backend'); }
  return row.pid;
}

async function transaction<T>(pool: Pool, operation: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await configureTransaction(client);
    const result = await operation(client);
    await client.query('COMMIT');
    return result;
  } finally {
    await client.query('ROLLBACK').catch(() => undefined);
    client.release();
  }
}

async function scalarVersion(client: PoolClient, sql: string, id: string): Promise<number> {
  const { rows: [row] } = await client.query<{ row_version: number }>(sql, [id]);
  if (!row) { throw new Error('Missing synthetic geography revision'); }
  return row.row_version;
}

const cityRevision = 'SELECT row_version FROM foundation.service_cities WHERE id=$1';
const areaRevision = 'SELECT row_version FROM foundation.service_areas WHERE id=$1';
const draftRevision = 'SELECT row_version FROM foundation.service_area_versions WHERE id=$1';

/** Only authorization/transaction ownership is adapted, not runner prelock,
 * checks, DML, audit, outbox or receipt. This is not an RBAC/HTTP proof. */
async function geoWrite(client: PoolClient, fixture: ConfigurationFixture, operation: GeoOperation,
  target: GeoTarget, body: object, expected: number): Promise<GeoReceipt> {
  const kind = 'staff-web';
  const auth: GeographyAuthorizationApi = {
    withGeography: async (proof, mode, _action, _cityId, command) => {
      expect(proof.kind).toBe(kind);
      expect(mode).toBe('write');
      return await command({ client, staffId: fixture.reviewer, cityIds: null, permissions: [],
        principal: { kind, staffId: fixture.reviewer, role: 'ADMIN', authVersion: 1 },
        role: { id: fixture.reviewer, code: 'ADMIN', type: 'SYSTEM' } });
    },
  };
  const result = await new GeoRunner(auth).execute({ kind, token: 'synthetic-fixture' }, operation,
    target, body, { key: randomUUID(), expected });
  expect(result.replayed).toBe(false);
  return result.data as GeoReceipt;
}

async function seedZone(client: PoolClient, fixture: ConfigurationFixture, cityId: string, districtId: string,
  relation: 'FULL' | 'PARTIAL', published: boolean): Promise<CoverageZone> {
  const areaId = randomUUID();
  const areaVersionId = randomUUID();
  await client.query('INSERT INTO foundation.service_areas(id,city_id,code) VALUES ($1,$2,$3)',
    [areaId, cityId, `zone-${areaId.slice(0, 8)}`]);
  await client.query(`INSERT INTO foundation.service_area_versions(id,city_id,area_id,version,name,created_by)
    VALUES ($1,$2,$3,1,'Synthetic overlapping coverage',$4)`, [areaVersionId, cityId, areaId, fixture.reviewer]);
  await client.query(`INSERT INTO foundation.service_area_district_coverage(city_id,area_version_id,district_id,relation)
    VALUES ($1,$2,$3,$4)`, [cityId, areaVersionId, districtId, relation]);
  if (published) {
    await client.query('UPDATE foundation.service_area_versions SET published_at=clock_timestamp(),published_by=$2 WHERE id=$1',
      [areaVersionId, fixture.reviewer]);
    await client.query('UPDATE foundation.service_areas SET current_version_id=$2 WHERE id=$1', [areaId, areaVersionId]);
  }
  return { areaId, areaVersionId };
}

async function seedAddress(client: PoolClient, fixture: ConfigurationFixture, profile: P05Profile,
  city: SyntheticCity, districtId: string): Promise<Address> {
  const customerId = randomUUID();
  const requestId = randomUUID();
  const addressId = randomUUID();
  const addressCell = randomUUID();
  const policyId = randomUUID();
  const s3 = profile === 'S3';
  const contactId = s3 ? randomUUID() : null;
  const applianceId = s3 ? randomUUID() : null;
  const preferenceId = s3 ? randomUUID() : null;
  await client.query(`INSERT INTO foundation.request_policy_packages(id,workflow_version,policy_revision,metadata_sha256)
    VALUES ($1,$2,$3,encode(sha256(convert_to('{}','UTF8')),'hex'))`,
  [policyId, `fence-fixture-${city.id}-v1`, `fence-fixture-${city.id}`]);
  await client.query('INSERT INTO foundation.customers(id) VALUES ($1)', [customerId]);
  await client.query(`INSERT INTO foundation.requests
      (id,type,status,customer_id,city_id,intake_city_version_id,workflow_package_id,intake_policy_revision_id,
       current_address_revision_id,current_contact_revision_id,current_appliance_revision_id,current_preference_revision_id)
    VALUES ($1,'REPAIR','NEW',$2,$3,$4,$5,$5,$6,$7,$8,$9)`,
  [requestId, customerId, city.id, city.versionId, policyId, addressId, contactId, applianceId, preferenceId]);
  // Typed provenance only; these opaque synthetic bytes are never opened.
  const payload = async (id: string, kind: string) => await client.query(`INSERT INTO foundation.request_payload_cells
    (id,request_id,kind,revision,key_id,wrapped_dek,nonce,ciphertext,auth_tag,aad_context)
    VALUES ($1,$2,$3,1,'k-fence-lab',$4,$5,$6,$7,'p05/lab/fence-fixture')`,
  [id, requestId, kind, Buffer.alloc(44), Buffer.alloc(12), Buffer.alloc(64), Buffer.alloc(16)]);
  await payload(addressCell, 'ADDRESS');
  await client.query(`INSERT INTO foundation.request_address_revisions(id,request_id,revision,district_id,district_row_version,payload_cell_id)
    SELECT $1,$2,1,id,row_version,$3 FROM foundation.administrative_districts WHERE id=$4`,
  [addressId, requestId, addressCell, districtId]);
  if (s3) {
    // 024 requires a complete durable CreateRepair even for synthetic data.
    // Keep triggers enabled; seed the reviewed PHONE form without sending/calling.
    const contactCell = randomUUID();
    const applianceCell = randomUUID();
    const categoryId = randomUUID();
    const categoryVersion = randomUUID();
    const evidenceId = randomUUID();
    const eventId = randomUUID();
    const auditId = randomUUID();
    const outboxId = randomUUID();
    await client.query("INSERT INTO foundation.catalog_directory_entries(id,kind,code) VALUES ($1,'CATEGORY',$2)",
      [categoryId, `fence-${categoryId.slice(0, 8)}`]);
    await client.query(`INSERT INTO foundation.catalog_directory_versions(id,entry_id,version,title,reviewed_by)
      VALUES ($1,$2,1,'Synthetic category',$3)`, [categoryVersion, categoryId, fixture.reviewer]);
    await client.query('UPDATE foundation.catalog_directory_entries SET current_version_id=$2 WHERE id=$1',
      [categoryId, categoryVersion]);
    await payload(contactCell, 'CONTACT');
    await payload(applianceCell, 'DETAILS');
    await client.query(`INSERT INTO foundation.request_contact_revisions(id,request_id,revision,mode,payload_cell_id)
      VALUES ($1,$2,1,'PHONE',$3)`, [contactId, requestId, contactCell]);
    await client.query(`INSERT INTO foundation.request_appliance_revisions(id,request_id,revision,category_id,category_version_id,payload_cell_id)
      VALUES ($1,$2,1,$3,$4,$5)`, [applianceId, requestId, categoryId, categoryVersion, applianceCell]);
    await client.query(`INSERT INTO foundation.request_preference_revisions(id,request_id,revision,urgency,preferred_windows,contact_mode)
      VALUES ($1,$2,1,'FLEXIBLE','[]'::jsonb,'PHONE')`, [preferenceId, requestId]);
    const source = await createReferenceEntry(client, fixture.reviewer, {
      type: 'REQUEST_SOURCE', code: `FENCE_${city.id.slice(0, 8).toUpperCase()}`,
    });
    const sourceVersion = await publishReferenceVersion(client, fixture.reviewer, {
      type: 'REQUEST_SOURCE', entryId: source.id, expectedVersion: source.version,
      label: 'Synthetic repair source', sourceRef: 'synthetic:fence', validFrom,
    });
    await client.query(`INSERT INTO foundation.request_intake_provenance(request_id,source_entry_id,source_version_id)
      VALUES ($1,$2,$3)`, [requestId, source.id, sourceVersion.id]);
    await client.query(`INSERT INTO foundation.request_staff_evidence(id,request_id,staff_id,purpose,procedure_revision,valid_until)
      VALUES ($1,$2,$3,'MANUAL_INTAKE','synthetic-fence-fixture',clock_timestamp()+interval '1 hour'),
             ($4,$2,$3,'PHONE_GIVE','synthetic-fence-fixture',clock_timestamp()+interval '1 hour')`,
    [randomUUID(), requestId, fixture.reviewer, evidenceId]);
    await client.query(`INSERT INTO foundation.request_events
      (id,request_id,command,principal,operation,idempotency_key,actor_type,actor_staff_id,resulting_version,correlation_id,details)
      VALUES ($1,$2,'CreateRepair',$3,'CreateRepair',$4,'STAFF',$5,1,$1,'{"status":"NEW"}')`,
    [eventId, requestId, `STAFF:${fixture.reviewer}`, randomUUID(), fixture.reviewer]);
    await client.query(`INSERT INTO foundation.audit_logs(id,operation,correlation_id,details)
      VALUES ($1,'CreateRepair',$2,jsonb_build_object('requestId',$3::text))`, [auditId, eventId, requestId]);
    await client.query(`INSERT INTO foundation.outbox_events(id,event_id,event_type,payload)
      VALUES ($1,$2,'REQUEST_EFFECT_RECORDED',jsonb_build_object('requestId',$3::text,'version',1))`,
    [outboxId, eventId, requestId]);
    await client.query(`INSERT INTO foundation.request_command_receipts
      (event_id,request_id,version,correlation_id,command,key_id,fingerprint,resulting_status,audit_id,outbox_id)
      VALUES ($1,$2,1,$1,'CreateRepair','k-fence-lab',$3,'NEW',$4,$5)`,
    [eventId, requestId, randomBytes(32), auditId, outboxId]);
    await client.query(`INSERT INTO foundation.phone_permission_events(id,request_id,contact_revision_id,action,event_id,staff_evidence_id)
      VALUES ($1,$2,$3,'GIVEN',$4,$5)`, [randomUUID(), requestId, contactId, eventId, evidenceId]);
  }
  return { requestId, addressId };
}

async function seedCity(fixture: ConfigurationFixture, profile: P05Profile, city: SyntheticCity): Promise<CitySeed> {
  return await transaction(fixture.migrator, async client => {
    // S3 fixture catalog DML follows the existing catalog -> GEO order.
    if (profile === 'S3') { await client.query('SELECT pg_catalog.pg_advisory_xact_lock(77304,1)'); }
    await acquireCompanySettingsLock(client);
    const districtId = randomUUID();
    await client.query(`INSERT INTO foundation.administrative_districts(id,city_id,code,name)
      VALUES ($1,$2,'fence-district','Synthetic shared district')`, [districtId, city.id]);
    const originalZone = await seedZone(client, fixture, city.id, districtId, 'FULL', true);
    const address = profile === 'S0' ? null : await seedAddress(client, fixture, profile, city, districtId);
    return { city, districtId, originalZone, address };
  });
}

async function seedCallback(fixture: ConfigurationFixture, client: PoolClient, city: SingleCityContext): Promise<Reference> {
  const entry = await createReferenceEntry(client, fixture.reviewer, {
    type: referenceType, cityId: city.cityId, code: `FENCE_${randomUUID().slice(0, 12).replace('-', '').toUpperCase()}`,
  });
  return await publishReferenceVersion(client, fixture.reviewer, {
    type: referenceType, entryId: entry.id, expectedVersion: entry.version, label: 'Synthetic original interval',
    cityVersionId: city.cityVersionId, interval: originalInterval, sourceRef: 'synthetic:fence', validFrom,
  });
}

/** S0 has no request/address relation. Probe only the legacy zone/mapping set,
 * with the same production GEO fence, current city and reference ports. */
async function legacyGeography(client: PoolClient, seed: CitySeed): Promise<GeoFacts> {
  const rows = (await client.query<CoverageZone & { relation: CoverageMapping['relation'] | null }>(`
    SELECT a.id AS "areaId",v.id AS "areaVersionId",m.relation
    FROM foundation.service_areas a JOIN foundation.service_area_versions v
      ON (v.id,v.area_id,v.city_id)=(a.current_version_id,a.id,a.city_id)
    LEFT JOIN foundation.service_area_district_coverage m
      ON (m.area_version_id,m.city_id,m.district_id)=(v.id,v.city_id,$2::uuid)
    WHERE a.city_id=$1 AND a.archived_at IS NULL AND v.published_at IS NOT NULL ORDER BY a.id,v.id`,
  [seed.city.id, seed.districtId])).rows;
  const zones = rows.map(({ areaId, areaVersionId }) => ({ areaId, areaVersionId }));
  const mappings = rows.flatMap(({ areaId, areaVersionId, relation }) => relation === null ? []
    : [{ areaId, areaVersionId, districtId: seed.districtId, relation }]);
  return { zones, mappings, basis: null };
}

async function geography(client: PoolClient, seed: CitySeed): Promise<GeoFacts> {
  if (!seed.address) { return await legacyGeography(client, seed); }
  // Match the production caller's order: GEO already held, then exact request lock.
  const lock = await client.query('SELECT id FROM foundation.requests WHERE id=$1 FOR UPDATE', [seed.address.requestId]);
  expect(lock.rowCount).toBe(1);
  const basis = await readCoverageBasis(client, seed.city.id, seed.address.addressId, cap);
  expect(basis.address).toMatchObject({ current: true, districtId: seed.districtId });
  expect(basis.district).toMatchObject({ districtId: seed.districtId, rowVersion: basis.address.districtRowVersion, archived: false });
  return { zones: basis.zones, mappings: basis.mappings, basis };
}

async function referenceFacts(client: PoolClient, city: SingleCityContext, ref: Reference): Promise<Facts['reference']> {
  const history = await readReferenceSnapshot(client, { type: referenceType, entryId: ref.entryId });
  const historical = { entryId: history.entry.id, versionId: history.version.id, sequence: history.version.version,
    label: history.version.label, interval: history.version.interval, provenanceCityVersionId: history.version.provenanceCityVersionId,
    archived: history.entry.archivedAt !== null };
  try {
    const active = await activeReference(client, referenceType, ref.entryId, city);
    expect(active).toMatchObject({ entryId: historical.entryId, versionId: historical.versionId,
      version: historical.sequence, label: historical.label, interval: historical.interval, cityId: city.cityId,
      timezone: city.timezone, timezoneCityVersionId: city.cityVersionId });
    expect(historical.archived).toBe(false);
    return { ...historical, active: true, timezone: active.timezone, timezoneCityVersionId: active.timezoneCityVersionId };
  } catch (error) {
    if (!(error instanceof RequestFailure) || error.code !== 'CONFLICT' || !historical.archived) { throw error; }
    return { ...historical, active: false, timezone: null, timezoneCityVersionId: null };
  }
}

interface EdgeRow { pid: number; mode: string; granted: boolean }
async function exactLocks(observer: PoolClient, pids: number[]): Promise<EdgeRow[]> {
  return (await observer.query<EdgeRow>(`SELECT pid,mode,granted FROM pg_catalog.pg_locks
    WHERE pid=ANY($1::int[]) AND locktype='advisory' AND classid=734305::oid AND objid=1::oid AND objsubid=2
      AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
    ORDER BY pid,mode,granted`, [pids])).rows;
}

async function waitForEdge(observer: PoolClient, waiter: number, blocker: number,
  waiterMode: 'ShareLock' | 'ExclusiveLock', blockerMode: 'ShareLock' | 'ExclusiveLock'): Promise<void> {
  const end = performance.now() + 5000;
  // Poll observable server state; do not sleep to manufacture or infer a wait.
  do {
    const { rows: [row] } = await observer.query<{ blockers: number[]; pending: number; domainLocks: number }>(`SELECT
      pg_catalog.pg_blocking_pids($1::int) AS blockers,
      (SELECT count(*)::int FROM pg_catalog.pg_locks WHERE pid=$1 AND NOT granted) AS pending,
      (SELECT count(*)::int FROM pg_catalog.pg_locks l JOIN pg_catalog.pg_class c ON c.oid=l.relation
       WHERE l.pid=$1 AND l.database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
         AND c.relnamespace='foundation'::regnamespace) AS "domainLocks"`, [waiter]);
    const locks = await exactLocks(observer, [waiter, blocker]);
    if (locks.some(lock => lock.pid === waiter && !lock.granted) && row?.blockers.includes(blocker)) {
      expect(row).toEqual({ blockers: [blocker], pending: 1, domainLocks: 0 });
      expect(locks).toHaveLength(2);
      expect(locks).toEqual(expect.arrayContaining([
        { pid: waiter, mode: waiterMode, granted: false }, { pid: blocker, mode: blockerMode, granted: true },
      ]));
      return;
    }
  } while (performance.now() < end);
  throw new Error(`No exact GEO/CFG wait edge ${String(waiter)}:${waiterMode} -> ${String(blocker)}:${blockerMode}`);
}

interface Race {
  write(client: PoolClient): Promise<unknown>;
  read: (client: PoolClient) => Promise<Facts>;
  verifyCommitted(after: Facts, before: Facts, effect: unknown): void;
}

function inZoneOrder<T extends CoverageZone>(rows: readonly T[]): T[] {
  return [...rows].sort((a, b) => a.areaId < b.areaId ? -1 : a.areaId > b.areaId ? 1 : 0);
}

function mapping(zone: CoverageZone, districtId: string, relation: 'FULL' | 'PARTIAL'): CoverageMapping {
  return { ...zone, districtId, relation };
}

async function prepareRace(fixture: ConfigurationFixture, cities: readonly [CitySeed, CitySeed], writer: Writer): Promise<Race> {
  const live = await transaction(fixture.runtime, async client => {
    await geoFence(client);
    return await currentCity(client);
  });
  const [seed, other] = cities[0].city.id === live.cityId ? cities : [cities[1], cities[0]];
  expect(seed.city.id).toBe(live.cityId);
  const replacement = writer === 'primary replacement';
  const cityPublish = writer === 'city version publish';
  const overlapPublish = writer === 'new overlap publication';
  const { revisedCity, beforeRef, otherRef, overlap, write } = await transaction(fixture.migrator, async client => {
    await acquireCompanySettingsLock(client);
    const nextTimezone = live.timezone === 'Asia/Tokyo' ? 'Europe/Moscow' : 'Asia/Tokyo';
    const { rows: [otherCurrent] } = await client.query<SingleCityContext>(`SELECT c.id AS "cityId",v.id AS "cityVersionId",v.timezone
      FROM foundation.service_cities c JOIN foundation.service_city_versions v ON (v.id,v.city_id)=(c.current_version_id,c.id)
      WHERE c.id=$1`, [other.city.id]);
    if (!otherCurrent) { throw new Error('Missing replacement city fixture'); }
    let revisedCity = replacement ? otherCurrent : live;
    if (cityPublish) {
      const nextId = randomUUID();
      await client.query(`INSERT INTO foundation.service_city_versions
        (id,city_id,version,display_name,timezone,public_contact,office_hours,reviewed_by)
        SELECT $1,$2,max(version)+1,'Synthetic next city version',$3,'office@example.test','[[],[],[],[],[],[],[]]'::jsonb,$4
        FROM foundation.service_city_versions WHERE city_id=$2`, [nextId, live.cityId, nextTimezone, fixture.reviewer]);
      revisedCity = { ...live, cityVersionId: nextId, timezone: nextTimezone };
    }
    const beforeRef = await seedCallback(fixture, client, live);
    const otherRef = replacement ? await seedCallback(fixture, client, revisedCity) : beforeRef;
    const overlap = overlapPublish ? await seedZone(client, fixture, live.cityId, seed.districtId, 'PARTIAL', false) : null;
    let write: Race['write'];
    if (replacement) {
      const expected = await scalarVersion(client, cityRevision, other.city.id);
      const old = await scalarVersion(client, cityRevision, live.cityId);
      write = async w => await geoWrite(w, fixture, 'cityActivate', { cityId: other.city.id },
        { replaceActiveCityId: live.cityId, replaceActiveCityVersion: old }, expected);
    } else if (cityPublish) {
      const expected = await scalarVersion(client, cityRevision, live.cityId);
      const target = { cityId: live.cityId, versionId: revisedCity.cityVersionId };
      write = async w => await geoWrite(w, fixture, 'cityPublish', target, {}, expected);
    } else if (overlap) {
      const expected = await scalarVersion(client, draftRevision, overlap.areaVersionId);
      const expectedAreaVersion = await scalarVersion(client, areaRevision, overlap.areaId);
      const target = { cityId: live.cityId, areaId: overlap.areaId, versionId: overlap.areaVersionId };
      write = async w => await geoWrite(w, fixture, 'areaPublish', target, { expectedAreaVersion }, expected);
    } else if (writer === 'reference archive') {
      write = async w => await archiveReferenceEntry(w, fixture.reviewer, { entryId: beforeRef.entryId, expectedVersion: beforeRef.entryVersion });
    } else {
      write = async w => await publishReferenceVersion(w, fixture.reviewer, {
        type: referenceType, entryId: beforeRef.entryId, expectedVersion: beforeRef.entryVersion,
        label: revisedLabel, interval: revisedInterval, cityVersionId: live.cityVersionId, sourceRef: 'synthetic:fence:v2', validFrom,
      });
    }
    return { revisedCity, beforeRef, otherRef, overlap, write };
  });
  const read = async (client: PoolClient): Promise<Facts> => {
    const city = await currentCity(client);
    const selected = city.cityId === seed.city.id ? seed : other;
    expect(city.cityId).toBe(selected.city.id);
    const geo = await geography(client, selected);
    if (geo.basis) { expect(geo.basis).toMatchObject(city); }
    const reference = await referenceFacts(client, city, selected === seed ? beforeRef : otherRef);
    return { city, ...geo, reference };
  };
  const verifyCommitted = (after: Facts, before: Facts, effect: unknown) => {
    const selected = replacement ? other : seed;
    const zones = replacement ? [other.originalZone] : overlap ? inZoneOrder([...before.zones, overlap]) : before.zones;
    const mappings = replacement ? [mapping(other.originalZone, other.districtId, 'FULL')]
      : overlap ? inZoneOrder([...before.mappings, mapping(overlap, seed.districtId, 'PARTIAL')]) : before.mappings;
    const reference = writer === 'reference archive'
      ? { ...before.reference, archived: true, active: false, timezone: null, timezoneCityVersionId: null }
      : writer === 'reference republish'
        ? { ...before.reference, versionId: (effect as Reference).id, sequence: 2, interval: revisedInterval, label: revisedLabel }
        : replacement
          ? { ...before.reference, entryId: otherRef.entryId, versionId: otherRef.id,
            timezone: revisedCity.timezone, timezoneCityVersionId: revisedCity.cityVersionId,
            provenanceCityVersionId: revisedCity.cityVersionId }
          : { ...before.reference, timezone: revisedCity.timezone, timezoneCityVersionId: revisedCity.cityVersionId };
    expect(after.city).toEqual(revisedCity);
    expect(after.reference).toEqual(reference);
    expect(after.zones).toEqual(zones);
    expect(after.mappings).toEqual(mappings);
    if (selected.address) {
      expect(after.basis?.request).toMatchObject({ requestId: selected.address.requestId, cityId: revisedCity.cityId });
      expect(after.basis?.address).toMatchObject({ addressRevisionId: selected.address.addressId, current: true });
      if (replacement || cityPublish || overlapPublish) { expect(after.basis?.basisDigest).not.toBe(before.basis?.basisDigest); }
      else { expect(after.basis).toEqual(before.basis); }
    } else { expect(after.basis).toBeNull(); }
    if (overlap) { expect(effect).toMatchObject({ id: overlap.areaVersionId }); }
    if (replacement || cityPublish) { expect(effect).toMatchObject({ id: revisedCity.cityId }); }
    if (writer === 'reference archive') { expect(effect).toMatchObject({ id: beforeRef.entryId, version: beforeRef.entryVersion + 1 }); }
  };
  return { write, read, verifyCommitted };
}

async function snapshot(pool: Pool, read: Race['read']): Promise<Facts> {
  return await transaction(pool, async client => {
    await geoFence(client);
    return await read(client);
  });
}

async function proveRace(fixture: ConfigurationFixture, race: Race, schedule: Schedule): Promise<void> {
  const before = await snapshot(fixture.runtime, race.read);
  const clients: PoolClient[] = [];
  const connect = async () => {
    const client = await fixture.runtime.connect();
    clients.push(client);
    return client;
  };
  let inFlight: Promise<unknown> | undefined;
  const start = <T>(operation: Promise<T>): Promise<T> => {
    inFlight = operation;
    void operation.catch(() => undefined); // surface rejection when awaited after observing
    return operation;
  };
  try {
    const writer = await connect();
    const reader = await connect();
    const observer = await connect();
    const writerPid = await beginRuntime(writer);
    const readerPid = await beginRuntime(reader);
    const { rows: [observerRow] } = await observer.query<{ pid: number }>('SELECT pg_catalog.pg_backend_pid() AS pid');
    expect(observerRow?.pid).toBeTypeOf('number');
    expect(new Set([writerPid, readerPid, observerRow?.pid]).size).toBe(3);
    let completed: Facts;
    if (schedule === 'reader-first commit') {
      await geoFence(reader);
      const pendingWrite = start(race.write(writer));
      await waitForEdge(observer, writerPid, readerPid, 'ExclusiveLock', 'ShareLock');
      // Even a reader's FIRST domain statement while X waits sees the whole OLD basis.
      expect(await race.read(reader)).toEqual(before);
      await reader.query('COMMIT');
      const effect = await pendingWrite;
      expect(await exactLocks(observer, [readerPid, writerPid])).toEqual([{ pid: writerPid, mode: 'ExclusiveLock', granted: true }]);
      await writer.query('COMMIT');
      completed = await snapshot(fixture.runtime, race.read);
      race.verifyCommitted(completed, before, effect);
    } else {
      const effect = await race.write(writer);
      const pendingRead = start((async () => {
        await geoFence(reader);
        return await race.read(reader);
      })());
      await waitForEdge(observer, readerPid, writerPid, 'ShareLock', 'ExclusiveLock');
      await writer.query(schedule === 'writer-first rollback' ? 'ROLLBACK' : 'COMMIT');
      completed = await pendingRead;
      expect(await exactLocks(observer, [readerPid, writerPid])).toEqual([{ pid: readerPid, mode: 'ShareLock', granted: true }]);
      if (schedule === 'writer-first rollback') { expect(completed).toEqual(before); }
      else { race.verifyCommitted(completed, before, effect); }
      await reader.query('COMMIT');
    }
    expect(await exactLocks(observer, [readerPid, writerPid])).toEqual([]);
    // Exercise the exact production stale-digest predicate on same-city changes.
    await transaction(fixture.runtime, async client => {
      await geoFence(client);
      expect(await race.read(client)).toEqual(completed);
      const original = before.basis;
      const current = completed.basis;
      if (!original || !current || original.cityId !== current.cityId) { return; }
      const reproof = reproofCoverageBasis(client, original.cityId, original.address.addressRevisionId, original.basisDigest, cap);
      if (original.basisDigest === current.basisDigest) { await expect(reproof).resolves.toEqual(current); }
      else { await expect(reproof).rejects.toMatchObject({ code: 'COVERAGE_ASSESSMENT_STALE' }); }
    });
  } finally {
    // Release the holder even when observation fails, then drain the pending query.
    await Promise.allSettled(clients.map(async client => await client.query('ROLLBACK')));
    await inFlight?.catch(() => undefined);
    for (const client of clients) { client.release(); }
  }
}

/** `test-request-intake-migration.mjs::proveFence` covers the metadata/owner no-X
 * path; `test-settings-migration.mjs::proveSettingsRuntimeDenials` already executes
 * the earlier ACL denial inputs, including forbidden history/identity and
 * TRUNCATE. Do not copy those inputs here: these are distinct, ACL-permitted
 * runtime statements, and must report the guard rather than ACL's own 42501. */
async function proveUnfencedRuntimeDml(fixture: ConfigurationFixture, seed: CitySeed): Promise<void> {
  const { draft, ref } = await transaction(fixture.migrator, async client => {
    await acquireCompanySettingsLock(client);
    const draft = await seedZone(client, fixture, seed.city.id, seed.districtId, 'PARTIAL', false);
    const ref = await seedCallback(fixture, client, { cityId: seed.city.id, cityVersionId: seed.city.versionId, timezone: seed.city.timezone });
    return { draft, ref };
  });
  const actor = fixture.reviewer;
  const city = seed.city.id;
  const freshId = randomUUID();
  const code = `fence-alt-${freshId.slice(0, 8)}`;
  const forms: readonly (readonly [string, unknown[]])[] = [
    [`INSERT INTO foundation.business_settings_versions(id,version,launch_mode,primary_city_id,reviewed_by)
      SELECT $1,max(version)+1,'SINGLE_CITY',$2,$3 FROM foundation.business_settings_versions`, [freshId, city, actor]],
    ['INSERT INTO foundation.service_cities(id,code) VALUES ($1,$2)', [freshId, code]],
    ['UPDATE foundation.service_cities SET current_version_id=$2 WHERE id=$1', [city, seed.city.versionId]],
    [`INSERT INTO foundation.service_city_versions(id,city_id,version,display_name,timezone,public_contact,office_hours,reviewed_by)
      SELECT $1,$2,max(version)+1,'Synthetic city alternative','Europe/Moscow','office@example.test','[[],[],[],[],[],[],[]]'::jsonb,$3
      FROM foundation.service_city_versions WHERE city_id=$2`, [freshId, city, actor]],
    ["INSERT INTO foundation.administrative_districts(id,city_id,code,name) VALUES ($1,$2,$3,'Synthetic district alternative')", [freshId, city, code]],
    ["UPDATE foundation.administrative_districts SET name='Synthetic rename' WHERE id=$1", [seed.districtId]],
    ['INSERT INTO foundation.service_areas(id,city_id,code) VALUES ($1,$2,$3)', [freshId, city, code]],
    ['UPDATE foundation.service_areas SET current_version_id=$2 WHERE id=$1', [seed.originalZone.areaId, seed.originalZone.areaVersionId]],
    [`INSERT INTO foundation.service_area_versions(id,city_id,area_id,version,name,created_by)
      VALUES ($1,$2,$3,2,'Synthetic draft alternative',$4)`, [freshId, city, draft.areaId, actor]],
    ["UPDATE foundation.service_area_versions SET name='Synthetic draft edit' WHERE id=$1", [draft.areaVersionId]],
    [`INSERT INTO foundation.service_area_district_coverage(city_id,area_version_id,district_id,relation)
      VALUES ($1,$2,$3,'FULL') ON CONFLICT (area_version_id,district_id) DO UPDATE SET relation=EXCLUDED.relation`,
    [city, draft.areaVersionId, seed.districtId]],
    ["UPDATE foundation.service_area_district_coverage SET relation='FULL' WHERE area_version_id=$1 AND district_id=$2", [draft.areaVersionId, seed.districtId]],
    ['DELETE FROM foundation.service_area_district_coverage WHERE area_version_id=$1 AND district_id=$2', [draft.areaVersionId, seed.districtId]],
    ["INSERT INTO foundation.reference_entries(id,type,scope,city_id,code) VALUES ($1,'CALLBACK_INTERVAL','CITY',$2,$3)",
      [freshId, city, `FENCE_ALT_${freshId.slice(0, 8).toUpperCase()}`]],
    ['UPDATE foundation.reference_entries SET archived_at=clock_timestamp() WHERE id=$1', [ref.entryId]],
    [`INSERT INTO foundation.reference_entry_versions(id,entry_id,type,city_id,version,label,valid_from,source_ref,reviewed_by,
        city_version_id,start_minute,end_minute)
      VALUES($1,$2,'CALLBACK_INTERVAL',$3,2,'Synthetic reference alternative',$4,'synthetic:fence',$5,$6,660,750)`,
    [freshId, ref.entryId, city, validFrom, actor, seed.city.versionId]],
  ];
  const client = await fixture.runtime.connect();
  try {
    const pid = await beginRuntime(client);
    expect(await exactLocks(client, [pid])).toEqual([]);
    for (const [sql, parameters] of forms) {
      await client.query('SAVEPOINT unfenced');
      await expect(client.query(sql, parameters), sql).rejects.toMatchObject({ code: '42501',
        message: 'GEO/CFG basis writes require the unified writer fence taken before the statement' });
      await client.query('ROLLBACK TO SAVEPOINT unfenced');
      await client.query('RELEASE SAVEPOINT unfenced');
    }
    expect(await exactLocks(client, [pid])).toEqual([]);
    // Positive control: the SAME forms are actually legal under X. Roll back
    // each form independently so no row fixture is altered for a later probe.
    await acquireCompanySettingsLock(client);
    for (const [sql, parameters] of forms) {
      await client.query('SAVEPOINT fenced');
      expect((await client.query(sql, parameters)).rowCount, sql).toBe(1);
      await client.query('ROLLBACK TO SAVEPOINT fenced');
      await client.query('RELEASE SAVEPOINT fenced');
    }
  } finally {
    await client.query('ROLLBACK').catch(() => undefined);
    client.release();
  }
}

for (const { profile, count, capBefore } of profiles) {
  lab(`P05 §5.1 GEO/CFG fence ${profile} (${String(count)} migrations)`, () => {
    let fixture: ConfigurationFixture | undefined;
    let cities: readonly [CitySeed, CitySeed];
    function db(): ConfigurationFixture {
      if (!fixture) { throw new Error('Missing isolated GEO/CFG fixture'); }
      return fixture;
    }
    beforeAll(async () => {
      fixture = await createConfigurationFixture(capBefore === undefined ? {} : { capBefore });
      const { rows: history } = await fixture.migrator.query<{ migration_name: string }>(`SELECT migration_name
        FROM foundation._prisma_migrations WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL ORDER BY migration_name`);
      expect(history.map(row => row.migration_name)).toEqual(authFixtureMigrations.slice(0, count));
      const client = await fixture.runtime.connect();
      try {
        expect(await attestDisposableFixture(client, 'READ')).toBe(fixture.database);
        expect(await probeP05Catalog(client, profile)).toBe(true);
      } finally { client.release(); }
      const primary = await createSyntheticCity(fixture);
      const standby = await createSyntheticCity(fixture, { lifecycle: 'INACTIVE', timezone: 'America/New_York' });
      await createSyntheticSettingsBaseline(fixture, primary);
      cities = [await seedCity(fixture, profile, primary), await seedCity(fixture, profile, standby)];
    }, 120_000);
    afterAll(async () => { await fixture?.close(); }, 60_000);

    if (profile !== 'S0') {
      it('refuses distinct ACL-permitted unfenced runtime DML on all nine GEO/CFG relations', async () => {
        await proveUnfencedRuntimeDml(db(), cities[0]);
      });
    }
    for (const writer of writers) {
      for (const schedule of schedules) {
        it(`${writer}: ${schedule}`, { timeout: 30_000 }, async () => {
          const race = await prepareRace(db(), cities, writer);
          await proveRace(db(), race, schedule);
        });
      }
    }
  });
}
