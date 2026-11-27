/**
 * P05-03 channel-offer fixture (task-8): an authoritative, test-only
 * `RequestOffers` port backed by a real PostgreSQL primary.
 *
 * Why a private schema in its own disposable database instead of `foundation`:
 * the reviewed `foundation` physical contract (S1/S2/S3 profile digests) pins
 * every relation/column/grant of the request surface. A test fixture must not
 * add objects there or the pin drifts for every other suite. The catalog
 * (`channel_offer_catalog_versions` / entries / readiness / live acceptance /
 * capability evidence, docs/DATABASE.md §3.6) is *future P07-ADM* scope and is
 * therefore modelled here in a fixture-owned schema — never in a commercial
 * schema and never as a runtime default.
 *
 * The fixture owns a SEPARATE disposable database (created and dropped through
 * the reviewed owned-database lifecycle). It never drops a schema of a database
 * somebody else owns, and `close()` is the single owner of its own database:
 * the parent test/afterEach must call it (no process-exit hooks, no DROP SCHEMA
 * while active).
 *
 * Concurrency contract reproduced here (docs/P05-PLAN.md §3, §5.1): the source
 * writer and this read share one advisory fence key, `(705025,1)` — the source
 * WRITER takes it EXCLUSIVE (every fixture mutator and `exclusive()`), the offer
 * reader takes it SHARED (`lock()` and `validateNewOffer()`, reentrant on the
 * same backend) — and the authoritative read of the current catalog pointer plus
 * the A/B/C-tech/C-live/D facts happens after that fence, in the CALLER's
 * transaction on the CALLER's `PoolClient` (`validateNewOffer`). `lock()` is the
 * reader fence the composition takes before the intake transaction reads
 * anything (`RequestIntake.submitForm`).
 * A caller client from another database is refused (`CHANNEL_NOT_READY`): there
 * is no cross-database fallback, because a second connection would not share the
 * caller's transaction. `validateDetached()` is a fixture-only observation
 * helper and is never invoked by a `RequestOffers` method.
 *
 * Refusals use the reviewed closed codes (docs/P05-PLAN.md §3):
 *  - stale current pointer / invalid membership / provider / purpose
 *    -> `CHANNEL_OPTIONS_CHANGED` (409);
 *  - current option version with `offer_enabled = false` -> `CHANNEL_OFFER_DISABLED` (409);
 *  - B (connection/credentials), C-tech (readiness), C-live (acceptance) or
 *    D (capability evidence) missing, failed, expired or revoked
 *    -> `CHANNEL_NOT_READY` (409).
 * Nothing is written and no provider is substituted on refusal.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { Pool } from 'pg';
import type { PoolClient } from 'pg';
import type { P05ChannelProvider, P05ChannelSelection } from '@fixlevelup/p03-contracts/p05';
import type { OfferBasis, RequestOffers } from '../src/requests/intake/basis.js';
import { deny } from '../src/requests/intake/errors.js';
import { fixtureCredentials, OwnedTestDatabase } from './owned-test-database.js';
import { attestDisposableFixture, requireFixtureCluster } from './p05-request-fixtures.js';
import type { RequestFixtureBase } from './p05-request-fixtures.js';

const connection = { host: '127.0.0.1' as const, port: 55432 };
const DATABASE_NAME = /^fixlevelup_configuration_test_[a-f0-9]{24}$/;
const SCHEMA_NAME = /^p05_offer_fixture(?:_[a-z0-9]{1,16})?$/;
const PROVIDERS: readonly P05ChannelProvider[] = Object.freeze(['TG', 'VK', 'MAX']);
const REQUIRED_CHECKS = Object.freeze(['CONFIG', 'CREDENTIAL', 'WEBHOOK', 'TLS', 'ADAPTER'] as const);
const REQUIRED_CAPABILITIES = Object.freeze(['SERVICE', 'INTERACTIVE', 'BINDING'] as const);

/** Shared source fence: writers EXCLUSIVE, the offer read SHARED (§5.1). */
const OFFER_FENCE = 'SELECT pg_catalog.pg_advisory_xact_lock(705025,1)';
const OFFER_READ_FENCE = 'SELECT pg_catalog.pg_advisory_xact_lock_shared(705025,1)';

export interface OfferFixtureIds {
  readonly catalogVersionId: string;
  readonly optionVersionId: string;
  readonly provider: P05ChannelProvider;
  readonly purpose: 'REQUEST_CONFIRMATION';
}

export interface RequestOfferFixtureOptions {
  /** Provider of the staged option; default `TG` (single-provider fixtures). */
  readonly provider?: P05ChannelProvider;
  /** Private schema name; defaults to `p05_offer_fixture_<provider>`. */
  readonly schema?: string;
  /** TTL of every staged readiness fact, in seconds (default one hour). */
  readonly ttlSeconds?: number;
}

export interface PublishedCatalog {
  readonly previousCatalogVersionId: string;
  readonly catalogVersionId: string;
  readonly optionVersionId: string;
  readonly offerEnabled: boolean;
}

interface PointerRow { readonly current_catalog_version_id: string }
interface EntryRow { readonly option_version_id: string; readonly provider: string; readonly purpose_bundle: string }
interface OptionRow { readonly offer_enabled: boolean; readonly connection_id: string | null }
interface ConnectionRow { readonly provider: string; readonly environment: string; readonly active: boolean }
interface ReadinessRow { readonly kind: string; readonly result: string; readonly revoked_at: Date | null; readonly valid_until: Date }
interface CapabilityRow { readonly capability: string; readonly status: string; readonly revoked_at: Date | null; readonly valid_until: Date }

/**
 * A real-PostgreSQL `RequestOffers` fixture.
 *
 *  - `RequestOfferFixture.attach(base, options)` provisions the private schema
 *    inside the caller's own disposable database (the T integration path: the
 *    port is read on the SAME `PoolClient`/transaction as the request write);
 *  - `RequestOfferFixture.create(options)` is the standalone variant that owns
 *    and drops its own separate disposable database.
 *
 * One instance covers one provider; distinct providers use distinct schema
 * names (`p05_offer_fixture_vk`, ...) so several can live side by side.
 */
export class RequestOfferFixture implements RequestOffers {
  readonly ids: OfferFixtureIds;
  readonly database: string;
  readonly schema: string;
  private closed = false;

  private constructor(
    database: string,
    schema: string,
    private readonly writer: Pool,
    private readonly reader: Pool,
    ids: OfferFixtureIds,
    /** Present only for the standalone `.create()` variant (owns its DB). */
    private readonly owned?: OwnedTestDatabase,
  ) {
    this.database = database;
    this.schema = schema;
    this.ids = ids;
  }

  /**
   * Standalone fixture: owns a SEPARATE disposable database and drops exactly
   * that database on `close()`. Use this when the offer catalog must be reached
   * by a test that does not own a request fixture.
   */
  static async create(options: RequestOfferFixtureOptions = {}): Promise<RequestOfferFixture> {
    requireFixtureCluster();
    const { provider, schema, ttlSeconds } = resolveOptions(options);
    const database = `fixlevelup_configuration_test_${randomBytes(12).toString('hex')}`;
    if (!DATABASE_NAME.test(database)) { throw new Error('Invalid offer fixture database name'); }
    const { migrator: migratorPassword, runtime: runtimePassword } = fixtureCredentials();
    // The reviewed owned-database lifecycle owns the disposable name; it only
    // ever reaches `postgres` for this one CREATE/REVOKE/GRANT block and drops
    // exactly this run's database on failure or on close().
    const owned = await OwnedTestDatabase.create({
      name: database,
      pattern: DATABASE_NAME,
      prepare: async (maintenance) => {
        await maintenance.query(`REVOKE ALL ON DATABASE "${database}" FROM PUBLIC`);
        await maintenance.query(`GRANT CONNECT ON DATABASE "${database}" TO fixlevelup_migrator, fixlevelup_runtime`);
      },
    });
    const writer = new Pool({ ...connection, database, user: 'fixlevelup_migrator', password: migratorPassword, max: 4 });
    const runtime = new Pool({ ...connection, database, user: 'fixlevelup_runtime', password: runtimePassword, max: 4 });
    const closePools = async (): Promise<void> => {
      await Promise.allSettled([runtime.end(), writer.end()]);
    };
    try {
      const provisioned = await provisionOfferSchema(writer, schema, provider, ttlSeconds, database);
      return new RequestOfferFixture(database, schema, writer, runtime, provisioned.ids, owned);
    } catch (error) {
      throw await owned.failure(error, closePools);
    }
  }

  /**
   * Attached fixture: provisions the private schema inside the CALLER's own
   * disposable database (`base.db`, the fixture's migrator pool) and uses that
   * pool for both sides. This is the variant T integration must use: the offer
   * read then runs on the SAME `PoolClient` and in the SAME transaction as the
   * request write, which is the reviewed same-primary-transaction contract.
   *
   * Ownership stays with the parent: `attach` never creates or drops a database
   * and `close()` never drops the schema while the parent is active — the
   * parent's own teardown drops the whole disposable database, so nothing here
   * can delete a schema somebody else still uses.
   */
  static async attach(base: RequestFixtureBase, options: RequestOfferFixtureOptions = {}): Promise<RequestOfferFixture> {
    requireFixtureCluster();
    const { provider, schema, ttlSeconds } = resolveOptions(options);
    const { database, ids } = await provisionOfferSchema(base.db, schema, provider, ttlSeconds);
    return new RequestOfferFixture(database, schema, base.db, base.db, ids);
  }

  /** Native T gets only a read port over its existing admitted business pool.
   * It never provisions or uses a second runtime/owner connection. */
  static readOnly(database: string, schema: string, ids: OfferFixtureIds, pool: Pool): RequestOffers {
    if (!DATABASE_NAME.test(database) || !SCHEMA_NAME.test(schema)) {
      throw new Error('Invalid compiled offer fixture binding');
    }
    const fixture = new RequestOfferFixture(database, schema, pool, pool, ids);
    return Object.freeze({ lock: fixture.lock.bind(fixture), validateNewOffer: fixture.validateNewOffer.bind(fixture) });
  }

  // -------------------------------------------------------------------------
  // RequestOffers port
  // -------------------------------------------------------------------------

  /**
   * Reader-side fence the composition takes before the intake transaction reads
   * anything (`RequestIntake.submitForm` / `submitStaff`). It is the SHARED side
   * of `(705025,1)`, exactly as docs/P05-PLAN.md §3/§5.1 requires: only the
   * source WRITER takes the EXCLUSIVE side (`exclusive()` and every fixture
   * mutator), so the readers never serialize against each other.
   *
   * Taking SHARED here and again inside `validateNewOffer` is reentrant in
   * PostgreSQL (a backend already holding the shared xact lock re-acquires it
   * without waiting and without a mode conversion), so the composition can call
   * both on the same `PoolClient` without a deadlock.
   *
   * A client from another database is refused: the fence would otherwise be
   * taken on a different primary and would not serialize against this catalog's
   * writers.
   */
  async lock(client: PoolClient): Promise<void> {
    if (this.closed) { throw new Error('Offer fixture is closed'); }
    if (!await this.detectDatabase(client)) { return deny('CHANNEL_NOT_READY'); }
    await client.query(OFFER_READ_FENCE);
  }

  /**
   * Authoritative allow-basis read, always in the CALLER's transaction and on
   * the CALLER's `PoolClient` (the reviewed same-primary-transaction contract,
   * docs/P05-PLAN.md §3). The SHARED fence and the read are the first two
   * statements, so an uncommitted writer move is visible and a stale selection is
   * refused without leaving the caller's transaction.
   *
   * The caller's client MUST be connected to this fixture's database. A client
   * from another database fails closed with `CHANNEL_NOT_READY`; there is no
   * cross-database fallback, because a second connection would not share the
   * caller's transaction/fence and could authorize a stale snapshot.
   * `validateDetached()` exists for fixture-only observation and is never called
   * from this port method.
   */
  async validateNewOffer(client: PoolClient, choice: P05ChannelSelection): Promise<OfferBasis> {
    if (this.closed) { throw new Error('Offer fixture is closed'); }
    if (!await this.detectDatabase(client)) { return deny('CHANNEL_NOT_READY'); }
    await client.query(OFFER_READ_FENCE);
    return await this.readBasis(client, choice);
  }

  /**
   * Fixture-only helper: the same fenced authoritative read on this fixture's own
   * connection, for tests that observe the catalog without a request transaction
   * (negative-state checks, snapshots). Never used by `RequestOffers` methods.
   */
  async validateDetached(choice: P05ChannelSelection): Promise<OfferBasis> {
    if (this.closed) { throw new Error('Offer fixture is closed'); }
    return await this.shared(async (client) => await this.readBasis(client, choice));
  }

  // -------------------------------------------------------------------------
  // Fixture-only writer side (X fence) and read side (S fence)
  // -------------------------------------------------------------------------

  /** Runs `run` in one writer transaction that holds the EXCLUSIVE fence. */
  async exclusive<T>(run: (client: PoolClient) => Promise<T>): Promise<T> {
    return await this.mutate(undefined, run);
  }

  /** Runs `run` in one reader transaction that holds the SHARED fence. */
  async shared<T>(run: (client: PoolClient) => Promise<T>): Promise<T> {
    if (this.closed) { throw new Error('Offer fixture is closed'); }
    requireFixtureCluster();
    const client = await this.reader.connect();
    let began = false;
    try {
      if (!await this.detectDatabase(client)) { return deny('CHANNEL_NOT_READY'); }
      await client.query('BEGIN');
      began = true;
      await client.query(OFFER_READ_FENCE);
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

  /** A frozen selection object for the seeded catalog (safe to spread overrides). */
  selection(overrides: Partial<P05ChannelSelection> = {}): P05ChannelSelection {
    return Object.freeze({ ...this.ids, ...overrides });
  }

  /** A-off for the current option version (independent of B–D). */
  async setOfferEnabled(enabled: boolean, client?: PoolClient): Promise<void> {
    await this.mutate(client, async (c) => {
      await c.query(`UPDATE ${this.q}.options SET offer_enabled=$2 WHERE id=$1`, [this.ids.optionVersionId, enabled]);
    });
  }

  async suspendConnection(client?: PoolClient): Promise<void> {
    await this.mutate(client, async (c) => {
      await c.query(`UPDATE ${this.q}.connections SET active=false WHERE provider=$1`, [this.ids.provider]);
    });
  }

  async resumeConnection(client?: PoolClient): Promise<void> {
    await this.mutate(client, async (c) => {
      await c.query(`UPDATE ${this.q}.connections SET active=true WHERE provider=$1`, [this.ids.provider]);
    });
  }

  async revokeCredentials(client?: PoolClient): Promise<void> {
    await this.mutate(client, async (c) => {
      await c.query(`UPDATE ${this.q}.credentials SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL`);
    });
  }

  async expireCredentials(client?: PoolClient): Promise<void> {
    await this.mutate(client, async (c) => {
      await c.query(`UPDATE ${this.q}.credentials SET valid_until=clock_timestamp() - interval '1 second'`);
    });
  }

  /** Appends a FAIL readiness check for `kind` (default: every kind). */
  async failReadiness(kind?: (typeof REQUIRED_CHECKS)[number], client?: PoolClient): Promise<void> {
    const kinds = kind === undefined ? REQUIRED_CHECKS : [kind];
    await this.mutate(client, async (c) => {
      for (const entry of kinds) {
        await c.query(`INSERT INTO ${this.q}.readiness_checks (id,connection_id,kind,result,valid_until)
          VALUES ($1,(SELECT id FROM ${this.q}.connections WHERE provider=$2),$3,'FAIL',clock_timestamp() + interval '1 hour')`,
        [randomUUID(), this.ids.provider, entry]);
      }
    });
  }

  async expireReadiness(kind?: (typeof REQUIRED_CHECKS)[number], client?: PoolClient): Promise<void> {
    await this.mutate(client, async (c) => {
      if (kind === undefined) {
        await c.query(`UPDATE ${this.q}.readiness_checks SET valid_until=clock_timestamp() - interval '1 second'`);
      } else {
        await c.query(`UPDATE ${this.q}.readiness_checks SET valid_until=clock_timestamp() - interval '1 second' WHERE kind=$1`, [kind]);
      }
    });
  }

  async revokeReadiness(kind?: (typeof REQUIRED_CHECKS)[number], client?: PoolClient): Promise<void> {
    await this.mutate(client, async (c) => {
      if (kind === undefined) {
        await c.query(`UPDATE ${this.q}.readiness_checks SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL`);
      } else {
        await c.query(`UPDATE ${this.q}.readiness_checks SET revoked_at=clock_timestamp() WHERE kind=$1 AND revoked_at IS NULL`, [kind]);
      }
    });
  }

  async revokeLiveAcceptance(client?: PoolClient): Promise<void> {
    await this.mutate(client, async (c) => {
      await c.query(`UPDATE ${this.q}.live_acceptances SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL`);
    });
  }

  async expireLiveAcceptance(client?: PoolClient): Promise<void> {
    await this.mutate(client, async (c) => {
      await c.query(`UPDATE ${this.q}.live_acceptances SET valid_until=clock_timestamp() - interval '1 second'`);
    });
  }

  async revokeCapability(capability?: (typeof REQUIRED_CAPABILITIES)[number], client?: PoolClient): Promise<void> {
    await this.mutate(client, async (c) => {
      if (capability === undefined) {
        await c.query(`UPDATE ${this.q}.capability_evidence SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL`);
      } else {
        await c.query(`UPDATE ${this.q}.capability_evidence SET revoked_at=clock_timestamp() WHERE capability=$1 AND revoked_at IS NULL`, [capability]);
      }
    });
  }

  async expireCapability(capability?: (typeof REQUIRED_CAPABILITIES)[number], client?: PoolClient): Promise<void> {
    await this.mutate(client, async (c) => {
      if (capability === undefined) {
        await c.query(`UPDATE ${this.q}.capability_evidence SET valid_until=clock_timestamp() - interval '1 second'`);
      } else {
        await c.query(`UPDATE ${this.q}.capability_evidence SET valid_until=clock_timestamp() - interval '1 second' WHERE capability=$1`, [capability]);
      }
    });
  }

  /** Expires every staged B/C/D fact at once (a real "live expiry" state). */
  async expireAll(client?: PoolClient): Promise<void> {
    await this.mutate(client, async (c) => {
      await c.query(`UPDATE ${this.q}.credentials SET valid_until=clock_timestamp() - interval '1 second'`);
      await c.query(`UPDATE ${this.q}.readiness_checks SET valid_until=clock_timestamp() - interval '1 second'`);
      await c.query(`UPDATE ${this.q}.live_acceptances SET valid_until=clock_timestamp() - interval '1 second'`);
      await c.query(`UPDATE ${this.q}.capability_evidence SET valid_until=clock_timestamp() - interval '1 second'`);
    });
  }

  /**
   * Publishes a new catalog revision (new option version + entry + pointer move)
   * under the EXCLUSIVE fence, exactly like the source writer would. The
   * previously returned selection then becomes stale (`CHANNEL_OPTIONS_CHANGED`)
   * while the returned selection is current; `offerEnabled: false` publishes a
   * current A-off option (`CHANNEL_OFFER_DISABLED`).
   */
  async publishCatalogVersion(
    options: { readonly offerEnabled?: boolean } = {},
    client?: PoolClient,
  ): Promise<PublishedCatalog> {
    const offerEnabled = options.offerEnabled ?? true;
    return await this.mutate(client, async (c) => {
      const pointer = await c.query<PointerRow>(`SELECT current_catalog_version_id FROM ${this.q}.pointer WHERE id`);
      const previousCatalogVersionId = pointer.rows[0]?.current_catalog_version_id;
      if (previousCatalogVersionId === undefined) { throw new Error('Offer fixture has no current catalog'); }
      const revision = await c.query<{ revision: number }>(
        `SELECT revision FROM ${this.q}.catalog_versions WHERE id=$1`, [previousCatalogVersionId]);
      const nextRevision = (revision.rows[0]?.revision ?? 0) + 1;
      const option = await c.query<OptionRow>(`SELECT offer_enabled,connection_id FROM ${this.q}.options WHERE id=$1`,
        [this.ids.optionVersionId]);
      const connectionId = option.rows[0]?.connection_id;
      if (connectionId === null || connectionId === undefined) { throw new Error('Offer fixture option has no connection'); }
      const optionVersionId = randomUUID();
      const catalogVersionId = randomUUID();
      await c.query(`INSERT INTO ${this.q}.options (id,provider,revision,offer_enabled,connection_id,purpose_bundle)
        VALUES ($1,$2,$3,$4,$5,'REQUEST_CONFIRMATION')`,
      [optionVersionId, this.ids.provider, nextRevision, offerEnabled, connectionId]);
      await c.query(`INSERT INTO ${this.q}.catalog_versions (id,revision,previous_id) VALUES ($1,$2,$3)`,
        [catalogVersionId, nextRevision, previousCatalogVersionId]);
      await c.query(`INSERT INTO ${this.q}.catalog_entries (catalog_version_id,option_version_id,provider,purpose_bundle)
        VALUES ($1,$2,$3,'REQUEST_CONFIRMATION')`, [catalogVersionId, optionVersionId, this.ids.provider]);
      await c.query(`UPDATE ${this.q}.pointer SET current_catalog_version_id=$1 WHERE id`, [catalogVersionId]);
      return Object.freeze({ previousCatalogVersionId, catalogVersionId, optionVersionId, offerEnabled });
    });
  }

  // -------------------------------------------------------------------------
  // Observation helpers
  // -------------------------------------------------------------------------

  /** Row counts of every fixture relation (proves a refused/allowed read writes nothing). */
  async snapshot(): Promise<Readonly<Record<string, number>>> {
    const tables = ['pointer', 'catalog_versions', 'catalog_entries', 'options', 'connections', 'credentials',
      'readiness_checks', 'live_acceptances', 'capability_evidence'];
    const counts: Record<string, number> = {};
    for (const table of tables) {
      const result = await this.reader.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${this.q}.${table}`);
      counts[table] = result.rows[0]?.n ?? -1;
    }
    return Object.freeze(counts);
  }

  /** The fixture's own database clock (never the test process clock). */
  async clock(): Promise<Date> {
    const result = await this.reader.query<{ now: Date }>('SELECT clock_timestamp() AS now');
    const now = result.rows[0]?.now;
    if (!(now instanceof Date)) { throw new Error('Offer fixture has no database clock'); }
    return now;
  }

  /** Backends currently waiting for the EXCLUSIVE fence (independent observer). */
  async blockedWaiters(): Promise<number> {
    const result = await this.writer.query<{ n: number }>(`SELECT count(*)::int AS n FROM pg_locks
      WHERE locktype='advisory' AND classid=705025::int::oid AND objid=1::oid AND objsubid=2 AND NOT granted`);
    return result.rows[0]?.n ?? -1;
  }

  /** Waits until at least one backend observably waits on the fence. */
  async waitForWaiter(timeoutMs = 5_000): Promise<void> {
    const deadline = performance.now() + timeoutMs;
    do {
      if (await this.blockedWaiters() > 0) { return; }
      await new Promise((resolve) => { setTimeout(resolve, 15); });
    } while (performance.now() < deadline);
    throw new Error('No backend reached the offer fence wait');
  }

  /**
   * Standalone variant: ends this fixture's pools and drops exactly its own
   * disposable database. Attached variant: marks the fixture closed and drops
   * NOTHING — the parent fixture still owns the database and its teardown.
   */
  async close(): Promise<void> {
    if (this.closed) { return; }
    this.closed = true;
    const owned = this.owned;
    if (owned === undefined) { return; }
    await owned.dispose(async () => {
      await Promise.allSettled([this.reader.end(), this.writer.end()]);
    });
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  private get q(): string {
    return `"${this.schema}"`;
  }

  private async detectDatabase(client: PoolClient): Promise<boolean> {
    try { return await attestDisposableFixture(client, 'READ') === this.database; }
    catch { return false; }
  }

  /**
   * Runs one fixture write.
   *
   *  - without `client`: a new writer transaction takes the EXCLUSIVE fence first,
   *    exactly like the source writer (`exclusive()` uses this path);
   *  - with `client`: the statements run on the caller's client and the CALLER
   *    owns the fence and the transaction. This is deliberate: taking EXCLUSIVE
   *    here could silently upgrade a SHARED lock the same backend already holds
   *    and deadlock against other readers, so a caller that wants a real writer
   *    uses `exclusive()` instead of passing a client.
   */
  private async mutate<T>(client: PoolClient | undefined, run: (c: PoolClient) => Promise<T>): Promise<T> {
    if (this.closed) { throw new Error('Offer fixture is closed'); }
    requireFixtureCluster();
    const check = async (writer: PoolClient): Promise<void> => {
      if (await attestDisposableFixture(writer) !== this.database) { throw new Error('Offer fixture database mismatch'); }
    };
    if (client !== undefined) {
      await check(client);
      return await run(client);
    }
    const own = await this.writer.connect();
    let began = false;
    try {
      await check(own);
      await own.query('BEGIN');
      began = true;
      await own.query(OFFER_FENCE);
      const result = await run(own);
      await own.query('COMMIT');
      return result;
    } catch (error) {
      if (began) { await own.query('ROLLBACK').catch(() => undefined); }
      throw error;
    } finally {
      own.release();
    }
  }

  /** The authoritative read: current pointer, membership, then A/B/C-tech/C-live/D. */
  private async readBasis(client: PoolClient, choice: P05ChannelSelection): Promise<OfferBasis> {
    const now = (await client.query<{ now: Date }>('SELECT clock_timestamp() AS now')).rows[0]?.now;
    if (!(now instanceof Date)) { return deny('CHANNEL_NOT_READY'); }

    const pointer = (await client.query<PointerRow>(
      `SELECT current_catalog_version_id FROM ${this.q}.pointer WHERE id`)).rows[0];
    if (pointer === undefined) { return deny('CHANNEL_NOT_READY'); }
    // A catalog that moved after the client saw the list is a stale choice, not
    // a technical outage: the client must re-read the offer list.
    if (pointer.current_catalog_version_id !== choice.catalogVersionId) { return deny('CHANNEL_OPTIONS_CHANGED'); }

    const entry = (await client.query<EntryRow>(`SELECT option_version_id,provider,purpose_bundle
      FROM ${this.q}.catalog_entries WHERE catalog_version_id=$1 AND option_version_id=$2`,
    [choice.catalogVersionId, choice.optionVersionId])).rows[0];
    if (entry === undefined || entry.provider !== choice.provider || entry.purpose_bundle !== choice.purpose) {
      return deny('CHANNEL_OPTIONS_CHANGED');
    }

    const option = (await client.query<OptionRow>(
      `SELECT offer_enabled,connection_id FROM ${this.q}.options WHERE id=$1`, [choice.optionVersionId])).rows[0];
    if (option === undefined) { return deny('CHANNEL_OPTIONS_CHANGED'); }
    if (!option.offer_enabled) { return deny('CHANNEL_OFFER_DISABLED'); }
    const connectionId = option.connection_id;
    if (connectionId === null) { return deny('CHANNEL_NOT_READY'); }

    // B: an actual active connection of the same provider plus live credentials.
    const connectionRow = (await client.query<ConnectionRow>(
      `SELECT provider,environment,active FROM ${this.q}.connections WHERE id=$1`, [connectionId])).rows[0];
    if (connectionRow === undefined || !connectionRow.active || connectionRow.provider !== choice.provider) {
      return deny('CHANNEL_NOT_READY');
    }
    const credentials = (await client.query<{ until: Date | null }>(`SELECT min(valid_until) AS until
      FROM ${this.q}.credentials WHERE connection_id=$1 AND revoked_at IS NULL`, [connectionId])).rows[0];
    const credentialsUntil = credentials?.until;
    if (!(credentialsUntil instanceof Date) || credentialsUntil.getTime() <= now.getTime()) {
      return deny('CHANNEL_NOT_READY');
    }

    // C-tech: the LATEST check of every required kind is a live PASS.
    const readiness = (await client.query<ReadinessRow>(`SELECT DISTINCT ON (kind) kind,result,revoked_at,valid_until
      FROM ${this.q}.readiness_checks WHERE connection_id=$1 ORDER BY kind, checked_at DESC`,
    [connectionId])).rows;
    const readinessUntil: Date[] = [];
    for (const kind of REQUIRED_CHECKS) {
      const row = readiness.find((candidate) => candidate.kind === kind);
      if (row === undefined || row.result !== 'PASS' || row.revoked_at !== null
        || row.valid_until.getTime() <= now.getTime()) {
        return deny('CHANNEL_NOT_READY');
      }
      readinessUntil.push(row.valid_until);
    }

    // C-live: a relevant, live acceptance for the same environment and purpose.
    const live = (await client.query<{ until: Date | null }>(`SELECT min(valid_until) AS until
      FROM ${this.q}.live_acceptances WHERE connection_id=$1 AND environment=$2 AND purpose_bundle=$3
        AND result='PASS' AND revoked_at IS NULL`, [connectionId, connectionRow.environment, choice.purpose])).rows[0];
    const liveUntil = live?.until;
    if (!(liveUntil instanceof Date) || liveUntil.getTime() <= now.getTime()) {
      return deny('CHANNEL_NOT_READY');
    }

    // D: live VERIFIED capability evidence for every required capability.
    const capability = (await client.query<CapabilityRow>(`SELECT DISTINCT ON (capability) capability,status,revoked_at,valid_until
      FROM ${this.q}.capability_evidence WHERE purpose_bundle=$1 ORDER BY capability, effective_at DESC`,
    [choice.purpose])).rows;
    const capabilityUntil: Date[] = [];
    for (const required of REQUIRED_CAPABILITIES) {
      const row = capability.find((candidate) => candidate.capability === required);
      if (row === undefined || row.status !== 'VERIFIED' || row.revoked_at !== null
        || row.valid_until.getTime() <= now.getTime()) {
        return deny('CHANNEL_NOT_READY');
      }
      capabilityUntil.push(row.valid_until);
    }

    const validUntil = new Date(Math.min(credentialsUntil.getTime(), liveUntil.getTime(),
      ...readinessUntil.map((value) => value.getTime()), ...capabilityUntil.map((value) => value.getTime())));
    return Object.freeze({
      provider: choice.provider,
      catalogVersionId: choice.catalogVersionId,
      optionVersionId: choice.optionVersionId,
      purpose: 'REQUEST_CONFIRMATION' as const,
      basisId: randomUUID(),
      validUntil,
    });
  }
}

/** Private fixture schema: the future P07-ADM catalog shape, test-owned only. */
function schemaDdl(schema: string): string {
  const s = `"${schema}"`;
  return `
    CREATE SCHEMA ${s};
    CREATE TABLE ${s}.pointer (
      id boolean PRIMARY KEY DEFAULT true CHECK (id),
      current_catalog_version_id uuid NOT NULL
    );
    CREATE TABLE ${s}.catalog_versions (
      id uuid PRIMARY KEY,
      revision integer NOT NULL UNIQUE CHECK (revision >= 1),
      previous_id uuid,
      published_at timestamptz NOT NULL DEFAULT clock_timestamp()
    );
    CREATE TABLE ${s}.connections (
      id uuid PRIMARY KEY,
      provider varchar(8) NOT NULL CHECK (provider IN ('TG','VK','MAX')),
      environment varchar(16) NOT NULL CHECK (environment IN ('TEST')),
      active boolean NOT NULL DEFAULT true
    );
    CREATE TABLE ${s}.options (
      id uuid PRIMARY KEY,
      provider varchar(8) NOT NULL CHECK (provider IN ('TG','VK','MAX')),
      revision integer NOT NULL CHECK (revision >= 1),
      offer_enabled boolean NOT NULL,
      connection_id uuid REFERENCES ${s}.connections(id),
      purpose_bundle varchar(32) NOT NULL CHECK (purpose_bundle = 'REQUEST_CONFIRMATION'),
      UNIQUE (id, provider)
    );
    CREATE TABLE ${s}.catalog_entries (
      catalog_version_id uuid NOT NULL REFERENCES ${s}.catalog_versions(id),
      option_version_id uuid NOT NULL,
      provider varchar(8) NOT NULL CHECK (provider IN ('TG','VK','MAX')),
      purpose_bundle varchar(32) NOT NULL CHECK (purpose_bundle = 'REQUEST_CONFIRMATION'),
      PRIMARY KEY (catalog_version_id, option_version_id),
      UNIQUE (catalog_version_id, provider),
      FOREIGN KEY (option_version_id, provider) REFERENCES ${s}.options(id, provider)
    );
    CREATE TABLE ${s}.credentials (
      id uuid PRIMARY KEY,
      connection_id uuid NOT NULL REFERENCES ${s}.connections(id),
      key_version integer NOT NULL CHECK (key_version >= 1),
      valid_until timestamptz NOT NULL,
      revoked_at timestamptz
    );
    CREATE TABLE ${s}.readiness_checks (
      id uuid PRIMARY KEY,
      connection_id uuid NOT NULL REFERENCES ${s}.connections(id),
      kind varchar(16) NOT NULL CHECK (kind IN ('CONFIG','CREDENTIAL','WEBHOOK','TLS','ADAPTER')),
      result varchar(8) NOT NULL CHECK (result IN ('PASS','FAIL','UNKNOWN')),
      checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
      valid_until timestamptz NOT NULL,
      revoked_at timestamptz
    );
    CREATE TABLE ${s}.live_acceptances (
      id uuid PRIMARY KEY,
      connection_id uuid NOT NULL REFERENCES ${s}.connections(id),
      environment varchar(16) NOT NULL CHECK (environment IN ('TEST')),
      purpose_bundle varchar(32) NOT NULL CHECK (purpose_bundle = 'REQUEST_CONFIRMATION'),
      result varchar(8) NOT NULL CHECK (result IN ('PASS','FAIL','UNKNOWN')),
      completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
      valid_until timestamptz NOT NULL,
      revoked_at timestamptz
    );
    CREATE TABLE ${s}.capability_evidence (
      id uuid PRIMARY KEY,
      purpose_bundle varchar(32) NOT NULL CHECK (purpose_bundle = 'REQUEST_CONFIRMATION'),
      capability varchar(32) NOT NULL CHECK (capability IN ('SERVICE','INTERACTIVE','BINDING')),
      source_type varchar(24) NOT NULL CHECK (source_type IN ('PLATFORM_CONFIG','REVIEWED_SOURCE','OWNER_ASSUMPTION')),
      status varchar(16) NOT NULL CHECK (status IN ('PENDING','VERIFIED','DENIED','REVOKED')),
      effective_at timestamptz NOT NULL DEFAULT clock_timestamp(),
      valid_until timestamptz NOT NULL,
      revoked_at timestamptz
    );`;
}

/** Validates and defaults the fixture options (provider/schema/TTL). */
function resolveOptions(options: RequestOfferFixtureOptions): {
  readonly provider: P05ChannelProvider; readonly schema: string; readonly ttlSeconds: number;
} {
  const provider = options.provider ?? 'TG';
  if (!PROVIDERS.includes(provider)) { throw new Error('Unsupported offer fixture provider'); }
  const schema = options.schema ?? `p05_offer_fixture_${provider.toLowerCase()}`;
  if (!SCHEMA_NAME.test(schema)) { throw new Error('Invalid offer fixture schema name'); }
  const ttlSeconds = options.ttlSeconds ?? 3600;
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 86_400) {
    throw new Error('Offer fixture TTL must be between 60 and 86400 seconds');
  }
  return { provider, schema, ttlSeconds };
}

/**
 * Creates the private schema, grants the runtime role read-only access (the port
 * validates, it never writes) and stages the A/B/C-tech/C-live/D facts.
 */
async function provisionOfferSchema(
  writer: Pool,
  schema: string,
  provider: P05ChannelProvider,
  ttlSeconds: number,
  expectedDatabase?: string,
): Promise<{ database: string; ids: OfferFixtureIds }> {
  const client = await writer.connect();
  let began = false;
  try {
    const database = await attestDisposableFixture(client);
    if (expectedDatabase !== undefined && database !== expectedDatabase) { throw new Error('Offer fixture database mismatch'); }
    await client.query('BEGIN');
    began = true;
    await client.query(OFFER_FENCE);
    await client.query(schemaDdl(schema));
    await client.query(`GRANT USAGE ON SCHEMA "${schema}" TO fixlevelup_runtime`);
    await client.query(`GRANT SELECT ON ALL TABLES IN SCHEMA "${schema}" TO fixlevelup_runtime`);
    const ids = await seedOfferFacts(client, schema, provider, ttlSeconds);
    if ((await client.query('COMMIT')).command !== 'COMMIT') { throw new Error('Offer fixture commit not confirmed'); }
    return { database, ids };
  } catch (error) {
    if (began) { await client.query('ROLLBACK').catch(() => undefined); }
    throw error;
  } finally { client.release(); }
}

/** Stages the A/B/C-tech/C-live/D facts and the first published catalog. */
async function seedOfferFacts(
  client: PoolClient,
  schema: string,
  provider: P05ChannelProvider,
  ttlSeconds: number,
): Promise<OfferFixtureIds> {
  const s = `"${schema}"`;
  const catalogVersionId = randomUUID();
  const optionVersionId = randomUUID();
  const connectionId = randomUUID();
  await client.query(`INSERT INTO ${s}.connections (id,provider,environment,active) VALUES ($1,$2,'TEST',true)`,
    [connectionId, provider]);
  await client.query(`INSERT INTO ${s}.credentials (id,connection_id,key_version,valid_until)
    VALUES ($1,$2,1,clock_timestamp() + make_interval(secs => $3::int))`,
  [randomUUID(), connectionId, ttlSeconds]);
  for (const kind of REQUIRED_CHECKS) {
    await client.query(`INSERT INTO ${s}.readiness_checks (id,connection_id,kind,result,valid_until)
      VALUES ($1,$2,$3,'PASS',clock_timestamp() + make_interval(secs => $4::int))`,
    [randomUUID(), connectionId, kind, ttlSeconds]);
  }
  await client.query(`INSERT INTO ${s}.live_acceptances
    (id,connection_id,environment,purpose_bundle,result,valid_until)
    VALUES ($1,$2,'TEST','REQUEST_CONFIRMATION','PASS',clock_timestamp() + make_interval(secs => $3::int))`,
  [randomUUID(), connectionId, ttlSeconds]);
  for (const capability of REQUIRED_CAPABILITIES) {
    await client.query(`INSERT INTO ${s}.capability_evidence
      (id,purpose_bundle,capability,source_type,status,valid_until)
      VALUES ($1,'REQUEST_CONFIRMATION',$2,$3,'VERIFIED',clock_timestamp() + make_interval(secs => $4::int))`,
    [randomUUID(), capability, provider === 'MAX' ? 'OWNER_ASSUMPTION' : 'REVIEWED_SOURCE', ttlSeconds]);
  }
  await client.query(`INSERT INTO ${s}.options (id,provider,revision,offer_enabled,connection_id,purpose_bundle)
    VALUES ($1,$2,1,true,$3,'REQUEST_CONFIRMATION')`, [optionVersionId, provider, connectionId]);
  await client.query(`INSERT INTO ${s}.catalog_versions (id,revision,previous_id) VALUES ($1,1,NULL)`,
    [catalogVersionId]);
  await client.query(`INSERT INTO ${s}.catalog_entries (catalog_version_id,option_version_id,provider,purpose_bundle)
    VALUES ($1,$2,$3,'REQUEST_CONFIRMATION')`, [catalogVersionId, optionVersionId, provider]);
  await client.query(`INSERT INTO ${s}.pointer (id,current_catalog_version_id) VALUES (true,$1)`,
    [catalogVersionId]);
  return Object.freeze({ catalogVersionId, optionVersionId, provider, purpose: 'REQUEST_CONFIRMATION' as const });
}
