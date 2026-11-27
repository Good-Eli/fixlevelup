/**
 * P05-02 form-session core business logic (docs/P05-PLAN.md §4.1, §5.1, §6.3).
 *
 * This module owns the F-session domain over the S2 schema (migration 023) and
 * the existing P03 legal ports: browser-group bootstrap, F anchor issue, the
 * read-only CSRF bootstrap, F logout, public legal documents, exact
 * GIVEN/REVOKED consent evidence and the district-only advisory coverage.
 *
 * Transaction and lock discipline (§5.1):
 *
 * - every business operation runs in one explicit `BEGIN ISOLATION LEVEL READ
 *   COMMITTED` transaction opened through `beginLegalTransaction`;
 * - geography/config reads (SINGLE_CITY, current legal document, advisory
 *   district coverage) always run *behind* the shared GEO/CFG fence
 *   `pg_advisory_xact_lock_shared(734305, 1)`, as the first statement of the
 *   transaction, and the authoritative read is the next statement;
 * - parallel issue of one browser group is serialized with an exclusive
 *   transaction-scoped advisory lock `pg_advisory_xact_lock(705021,
 *   hashtext(group_id))` (no `FOR UPDATE` is taken on the immutable
 *   `form_browser_groups` history table, whose runtime grants have no UPDATE);
 * - throttling is a one-statement atomic upsert executed in autocommit *before*
 *   the business transaction, so rejected attempts still count and a quota
 *   refusal never rolls the counter back;
 * - the DB clock (`clock_timestamp()`) is the only time authority; it is
 *   re-sampled after every lock wait and before COMMIT.
 *
 * No TTL, quota or policy value is invented here: everything technical is
 * supplied by `FormSessionConfig` and validated once at construction. No PII
 * is stored, logged or echoed; refusal messages are machine codes only.
 */
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import type { PoolClient, QueryConfig, QueryResult, QueryResultRow } from 'pg';
import {
  bindIdempotencyKey,
  consentBody,
  districtCheckBody,
  emptyObjectBody,
  F_COOKIE_PREFIX,
  F_GROUP_COOKIE,
  F_MAX_F_COOKIES,
  F_MAX_LIVE_ANCHORS_PER_GROUP,
  FormSessionError,
  idempotencyKey,
  rejectPersonalFields,
} from './contract.js';
import type { ConsentBody, DistrictCheckBody, LegalKindParam } from './contract.js';
import { formatHostCookie, parseCookieHeader, readFormCookies, readGroupCookie } from './cookies.js';
import { CSRF_KEY_ID_PATTERN } from './csrf.js';
import type { FormCsrfKeyring } from './csrf.js';
import { issueCsrfProof, verifyCsrfProof } from './csrf.js';
import { adviseDistrict } from './advisory.js';
import type { AdvisoryCoverage } from './advisory.js';
import {
  anchorState,
  beginLegalTransaction,
  createRequestSession,
  hashSessionSecret,
  LegalPortError,
  readCurrentLegalDocument,
  recordConsentGiven,
  recordConsentRevoked,
  requireLiveAnchor,
  revokeRequestSession,
  sessionSecretMatches,
} from '../settings/legal/index.js';
import type { ConsentReceipt, RequestSessionRow } from '../settings/legal/index.js';
import { CityContextError, readSingleCityContext } from '../settings/geography/city-context.js';
import type { SingleCityContext } from '../settings/geography/city-context.js';
import { AdmissionRequiredError, requireFormSessionPool } from '../infrastructure/admission/pool-guard.js';

/* ------------------------------ configuration ------------------------------ */

/** Bounded fixed-window rate budget for one throttle subject. */
export interface FormThrottleBudget {
  readonly windowSeconds: number;
  readonly maxHits: number;
}

/**
 * Validated technical configuration of the P05-02 surface. No live default
 * policy: every TTL and budget is an explicit configured value; the synthetic
 * harness owns policy/term checks.
 */
export interface FormSessionConfig {
  /** Exact allowed Origin (e.g. 'https://crm.example.test'). */
  readonly origin: string;
  /** Versioned CSRF keyring for P05_F_MUTATE. */
  readonly csrfKeyring: FormCsrfKeyring;
  /** HMAC secret (>= 32 bytes) for hashing throttle keys. Must differ from the CSRF secret. */
  readonly throttleSecret: Buffer;
  /** Browser group lifetime in milliseconds (> 0, <= 7 days). Must be >= anchorTtlMs. */
  readonly groupTtlMs: number;
  /** F anchor lifetime in milliseconds (> 0, <= groupTtlMs). */
  readonly anchorTtlMs: number;
  /** CSRF token lifetime in milliseconds (> 0, <= anchorTtlMs). Effective expiry is min(now + csrfTtlMs, anchor.expiresAt). */
  readonly csrfTtlMs: number;
  /** Bounded rate limits for source, global issuance and per-anchor operations. */
  readonly throttles: {
    readonly source: FormThrottleBudget;
    readonly global: FormThrottleBudget;
    readonly anchor: FormThrottleBudget;
  };
}

/** Throttle subjects, matching the closed S2 `kind` vocabulary. */
type ThrottleKind = 'SOURCE' | 'GLOBAL' | 'ANCHOR';

/** Minimal guarded-pool surface this service consumes (a `pg.Pool` satisfies it). */
export interface FormSessionPool {
  connect(): Promise<PoolClient>;
  query<R extends QueryResultRow = QueryResultRow>(queryTextOrConfig: string | QueryConfig): Promise<QueryResult<R>>;
  query<R extends QueryResultRow = QueryResultRow>(queryTextOrConfig: string, values?: readonly unknown[]): Promise<QueryResult<R>>;
}

const MAX_TTL_MS = 7 * 86_400_000;
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const GEO_CFG_FENCE_SQL = 'SELECT pg_catalog.pg_advisory_xact_lock_shared(734305, 1)';

/**
 * PostgreSQL/driver error codes classified as operational unavailability
 * (MUST 12): lock timeout, query cancel/statement timeout, serialization,
 * deadlock, cannot-connect, shutdowns and connection exceptions.
 */
const OPERATIONAL_CODES: ReadonlySet<string> = new Set([
  '55P03', '57014', '40001', '40P01', '53300',
  'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'EPIPE', 'ENETDOWN', 'ENETUNREACH',
  'EHOSTUNREACH', 'ENOTFOUND', 'EAI_AGAIN',
]);
const OPERATIONAL_SQLSTATE = /^(?:08[0-9A-Z]{3}|57P[0-9A-Z]{2})$/;

/** Socket-level failure fragments classified the same way. */
const OPERATIONAL_SOCKET_MESSAGES: readonly string[] = [
  'ECONNRESET', 'ETIMEDOUT', 'EPIPE', 'Query read timeout', 'Connection terminated',
  'socket hang up', 'Connection ended', 'Connection closed',
];

function invalidConfiguration(): never {
  // No configuration value (origin text, secret bytes) is ever echoed.
  throw new Error('Invalid form session configuration');
}

function validateConfig(config: FormSessionConfig): void {
  let url: URL;
  try {
    url = new URL(config.origin);
  } catch {
    invalidConfiguration();
  }
  if (url.protocol !== 'https:' || url.origin !== config.origin || url.username !== '' || url.password !== '') {
    invalidConfiguration();
  }
  const csrfSecret = config.csrfKeyring.current.secret;
  // MUST 8: the CSRF key id grammar and the proof wire format are one-to-one.
  // A key id with a dot would pass issue but could never verify (the dot is the
  // proof's field separator), so an invalid key id fails the configuration
  // before any group or anchor is ever created.
  if (!CSRF_KEY_ID_PATTERN.test(config.csrfKeyring.current.keyId)) {
    invalidConfiguration();
  }
  if (csrfSecret.length < 32 || config.throttleSecret.length < 32) {
    invalidConfiguration();
  }
  if (config.throttleSecret.equals(csrfSecret)) {
    invalidConfiguration();
  }
  for (const ttl of [config.groupTtlMs, config.anchorTtlMs, config.csrfTtlMs]) {
    if (!Number.isSafeInteger(ttl) || ttl <= 0 || ttl > MAX_TTL_MS) {
      invalidConfiguration();
    }
  }
  if (config.groupTtlMs < config.anchorTtlMs || config.anchorTtlMs < config.csrfTtlMs) {
    invalidConfiguration();
  }
  for (const budget of [config.throttles.source, config.throttles.global, config.throttles.anchor]) {
    if (!Number.isSafeInteger(budget.windowSeconds) || budget.windowSeconds < 1 || budget.windowSeconds > 86_400) {
      invalidConfiguration();
    }
    if (!Number.isSafeInteger(budget.maxHits) || budget.maxHits < 1 || budget.maxHits > 1_000_000) {
      invalidConfiguration();
    }
  }
}

/* --------------------------------- results --------------------------------- */

/** `POST /public/form-session/browser` outcome. `setCookie` is emitted only on creation. */
export interface BrowserBootstrapResult {
  readonly groupId: string;
  readonly expiresAt: string;
  readonly created: boolean;
  /** Exact `Set-Cookie` value for the new group secret, or null when an existing live group was returned. */
  readonly setCookie: string | null;
}

/** `POST /public/form-sessions` outcome. */
export interface IssueSessionResult {
  /** Public F selector (the request_sessions.id; also the cookie name suffix and X-Form-Session-Id). */
  readonly sessionId: string;
  readonly setCookie: string;
  readonly csrfToken: string;
  readonly csrfExpiresAt: string;
  readonly intakeCityId: string;
  readonly intakeCityVersionId: string;
  readonly timezone: string;
  readonly createdAt: string;
  readonly expiresAt: string;
}

/** `POST /public/form-session/csrf` outcome. The anchor is never extended. */
export interface CsrfBootstrapResult {
  readonly sessionId: string;
  readonly expiresAt: string;
  readonly csrfToken: string;
  readonly csrfExpiresAt: string;
}

/** `POST /public/form-session/revoke` outcome. */
export interface RevokeResult {
  readonly revoked: boolean;
  /** Addressed `Max-Age=0` clearing for this exact proof cookie. */
  readonly setCookie: string;
}

/** Public projection of the current REQUEST_PROCESSING document. No operator fields. */
export interface LegalDocumentPublic {
  readonly documentId: string;
  readonly versionId: string;
  readonly purpose: 'REQUEST_PROCESSING';
  readonly kind: LegalKindParam;
  readonly version: number;
  readonly title: string;
  readonly body: string;
  readonly checksum: string;
  readonly legalBasis: string;
  readonly publishedAt: string;
}

/** `POST /public/form-session/consents` outcome. */
export interface ConsentResult {
  readonly receipt: ConsentReceipt;
  readonly replayed: boolean;
}

/** `POST /public/coverage/check` outcome: advisory only, never IN_ZONE. */
export interface CoverageResult {
  readonly cityId: string;
  readonly cityVersionId: string;
  readonly districtId: string;
  readonly outcome: 'AREA_REVIEW_REQUIRED';
  readonly hints: AdvisoryCoverage['hints'];
}

/* ------------------------------- typed inputs ------------------------------- */

export interface FormSessionBaseInput {
  readonly cookieHeader: string | undefined;
  readonly body: unknown;
  readonly source: string;
}

export interface FormSessionSelectorInput extends FormSessionBaseInput {
  /** X-Form-Session-Id value, already duplicate-checked by the transport. */
  readonly selector: string | undefined;
  /** X-CSRF-Token value for mutating operations; unused on the read-only bootstrap. */
  readonly csrf: string | undefined;
}

/**
 * Consent mutation input. `Idempotency-Key` is mandatory on this operation and is
 * bound to the F-session by the append-only evidence identity: the key must equal
 * the body `evidenceRef`, which `consent_records` scopes by
 * `unique(session_id,evidence_ref)`. A repeated key therefore replays exactly one
 * stored event instead of creating a second one, and the same key with a
 * different intent is a conflict, never a silent second write.
 */
export interface FormSessionConsentInput extends FormSessionSelectorInput {
  /** Raw `Idempotency-Key` header value; validated and bound inside the service. */
  readonly idempotencyKey: string | undefined;
}

/* -------------------------------- refusals --------------------------------- */

/**
 * `UNAUTHENTICATED` refusal that additionally names the exact proof cookie the
 * transport must clear with an addressed `Max-Age=0`: only a provably dead
 * *own* cookie (expired or revoked anchor) is cleared; a foreign or unknown
 * proof never is, so the endpoint is not an oracle.
 */
export class FormSessionAuthError extends FormSessionError {
  readonly clearCookieName: string | null;

  constructor(clearCookieName: string | null) {
    super('UNAUTHENTICATED');
    this.clearCookieName = clearCookieName;
  }
}

/** Service surface consumed by the HTTP controller (and by unit tests). */
export interface FormSessionApi {
  browserBootstrap(input: FormSessionBaseInput): Promise<BrowserBootstrapResult>;
  issueSession(input: FormSessionBaseInput): Promise<IssueSessionResult>;
  csrfBootstrap(input: FormSessionSelectorInput): Promise<CsrfBootstrapResult>;
  revokeSession(input: FormSessionSelectorInput): Promise<RevokeResult>;
  readLegalDocument(kind: LegalKindParam, input: { readonly source: string }): Promise<LegalDocumentPublic>;
  recordConsent(input: FormSessionConsentInput): Promise<ConsentResult>;
  checkCoverage(input: FormSessionSelectorInput): Promise<CoverageResult>;
}

/* ------------------------------ internal rows ------------------------------- */

type GroupRow = { id: string; created_at: Date; expires_at: Date; db_now: Date };
type InsertedGroupRow = { id: string; expires_at: Date; db_now: Date };
type MembershipRow = { session_id: string; group_id: string; created_at: Date };
type CountRow = { live_count: number };
type ClockRow = { db_now: Date };
type GivenRow = { id: string; document_id: string; document_version_id: string };
type ConsentIntentRow = GivenRow & { action: string; purpose: string; supersedes_id: string | null };
type ThrottleRow = { hit_count: number };

/**
 * One-statement atomic throttle upsert, in autocommit, by the database clock.
 *
 * The `DO UPDATE ... WHERE hit_count < $5` guard makes the increment saturating
 * and atomic: while the bucket is below the budget the conflicting row is
 * incremented (never past the budget) and returned; once it has reached the
 * budget the guard is false, the row is *not* updated (the counter stays at
 * exactly `maxHits`, never touching the 1..1_000_000 CHECK or producing a
 * driver exception) and the statement returns no row, which the caller maps to
 * the 429 quota refusal. A saturated source therefore creates no new rows and
 * keeps answering 429 on the upper boundary.
 */
const THROTTLE_UPSERT_SQL = `INSERT INTO foundation.form_throttle_buckets
  (id, kind, key_hash, window_started_at, window_seconds, hit_count)
  SELECT $1, $2, $3, to_timestamp(floor(extract(epoch from clock_timestamp()) / $4) * $4), $4, 1
  ON CONFLICT (kind, key_hash, window_started_at)
  DO UPDATE SET hit_count = foundation.form_throttle_buckets.hit_count + 1
    WHERE foundation.form_throttle_buckets.hit_count < $5
  RETURNING hit_count`;

/** Selected proof cookie after the full cookie set was validated. */
interface SelectedProof {
  readonly selector: string;
  readonly secret: string;
}

/* --------------------------------- service --------------------------------- */

export class FormSessionService implements FormSessionApi {
  private readonly config: FormSessionConfig;
  private readonly schema: 'S2' | 'S3';

  constructor(private readonly pool: FormSessionPool, config: FormSessionConfig) {
    this.schema = requireFormSessionPool(pool);
    validateConfig(config);
    this.config = config;
  }

  /** Reuse the same F proof and quota on downstream commands. Preparation has
   * no business authority; only lock() inside the caller's own transaction does. */
  async prepareRequestProof(input: Omit<FormSessionSelectorInput, 'body'>, mutation: boolean) {
    const cookies = parseCookieHeader(input.cookieHeader);
    readFormCookies(cookies);
    const proof = this.selectFormCookie(cookies, input.selector);
    await this.throttleProvenAnchor(input.source, proof);
    return Object.freeze({ selector: proof.selector, secret: proof.secret,
      lock: async (client: PoolClient) => {
        const anchor = await this.liveAnchor(client, proof.selector, proof.secret);
        const recheck = async (): Promise<Date> => {
          const now = await this.dbClock(client);
          this.assertAnchorUnexpired(anchor, now);
          if (mutation) { this.verifyCsrf(anchor.id, proof.secret, input.csrf, now.getTime(), anchor.expires_at.getTime()); }
          return now;
        };
        await recheck();
        return Object.freeze({ anchor, recheck });
      },
    });
  }

  /* ------------------------------ throttle core ----------------------------- */

  /**
   * Counts one hit against a fixed window in a single autocommit statement, so
   * the increment survives a later refusal and parallel hits serialize on the
   * unique (kind, key_hash, window_started_at) identity. The subject is HMAC'd
   * with the dedicated throttle secret; no raw source text is stored.
   */
  private async consumeThrottle(kind: ThrottleKind, rawSubject: string, budget: FormThrottleBudget): Promise<void> {
    const keyHash = createHmac('sha256', this.config.throttleSecret)
      .update(kind)
      .update('\0')
      .update(rawSubject)
      .digest('hex');
    let rows: ThrottleRow[];
    try {
      ({ rows } = await this.pool.query<ThrottleRow>(THROTTLE_UPSERT_SQL, [
        randomUUID(), kind, keyHash, budget.windowSeconds, budget.maxHits,
      ]));
    } catch (error) {
      // A driver/admission failure of the throttle table is a safe
      // unavailability, never an untyped 500 (MUST 12).
      throw this.mapOperationalError(error);
    }
    const hits = rows[0]?.hit_count;
    // No row returned: the WHERE guard of the upsert did not fire, which means
    // the bucket has already reached its budget — a saturated 429, with no new
    // row created and no increment past the CHECK boundary.
    if (hits === undefined) {
      throw new FormSessionError('QUOTA');
    }
    if (!Number.isSafeInteger(hits) || hits < 1) {
      throw new FormSessionError('UNAVAILABLE');
    }
    if (hits > budget.maxHits) {
      throw new FormSessionError('QUOTA');
    }
  }

  /**
   * Cheap common/source admission before any irreversible allocation (MUST 7).
   * `GLOBAL` is one fixed key per window, so an exhausted global budget
   * creates no new SOURCE rows at all; a saturated SOURCE bucket also creates
   * none (the upsert guard skips the update). Only when both pass is any
   * durable business state allowed to be produced.
   */
  private async throttleGlobalThenSource(source: string): Promise<void> {
    await this.consumeThrottle('GLOBAL', 'global', this.config.throttles.global);
    await this.consumeThrottle('SOURCE', source, this.config.throttles.source);
  }

  /**
   * Operational-error classification shared by every database touch point
   * (MUST 12). Typed F refusals pass through; admission denials and
   * PostgreSQL/driver/socket-level failures (lock timeout, statement timeout,
   * serialization, deadlock, shutdown, connection loss) become the safe
   * `UNAVAILABLE` 503 refusal instead of an untyped 500.
   */
  private mapOperationalError(error: unknown): Error {
    if (error instanceof FormSessionError) {
      return error;
    }
    // The legacy port collapses lock/serialization/deadlock failures and
    // unexpected invariant failures to CONFLICT. It does not use that code
    // for legal business conflicts (which have their own typed reasons).
    if (error instanceof AdmissionRequiredError || (error instanceof LegalPortError && error.code === 'CONFLICT')) {
      return new FormSessionError('UNAVAILABLE');
    }
    if (typeof error === 'object' && error !== null) {
      const code: unknown = (error as { readonly code?: unknown }).code;
      if (typeof code === 'string' && (OPERATIONAL_CODES.has(code) || OPERATIONAL_SQLSTATE.test(code))) {
        return new FormSessionError('UNAVAILABLE');
      }
      const message: unknown = (error as { readonly message?: unknown }).message;
      if (typeof message === 'string' && OPERATIONAL_SOCKET_MESSAGES.some((m) => message.includes(m))) {
        return new FormSessionError('UNAVAILABLE');
      }
    }
    return error instanceof Error ? error : new Error(String(error));
  }

  /* ---------------------------- transaction frame --------------------------- */

  private async withTransaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
    let client: PoolClient;
    try {
      client = await this.pool.connect();
    } catch {
      throw new FormSessionError('UNAVAILABLE');
    }
    let inTransaction = false;
    let commitAttempted = false;
    let discard = false;
    try {
      await beginLegalTransaction(client);
      inTransaction = true;
      const result = await work(client);
      commitAttempted = true;
      const completion = await client.query('COMMIT');
      if (completion.command !== 'COMMIT') {
        throw new FormSessionError('UNAVAILABLE');
      }
      inTransaction = false;
      return result;
    } catch (error) {
      if (commitAttempted) {
        // Unknown COMMIT outcome (MUST 12): the transaction may or may not be
        // durable. No ROLLBACK is attempted (it could fail on an already
        // finished transaction and mask the real state), there is no automatic
        // retry/write, and the connection is discarded from the pool.
        discard = true;
        throw new FormSessionError('UNAVAILABLE');
      }
      if (inTransaction) {
        try {
          await client.query('ROLLBACK');
        } catch {
          discard = true;
        }
      }
      throw this.mapOperationalError(error);
    } finally {
      client.release(discard);
    }
  }

  /** Shared GEO/CFG fence; every current-geography read follows it immediately. */
  private async fenceGeography(client: PoolClient): Promise<void> {
    await client.query(GEO_CFG_FENCE_SQL);
  }

  private async readCity(client: PoolClient): Promise<SingleCityContext> {
    try {
      return await readSingleCityContext(client);
    } catch (error) {
      if (error instanceof CityContextError) {
        throw new FormSessionError('UNAVAILABLE');
      }
      throw error;
    }
  }

  /* ------------------------------ proof helpers ----------------------------- */

  /** Only pre-admission: no business checkout is held while charging ANCHOR.
   * The locked transaction must prove everything again after this snapshot. */
  private async throttleProvenAnchor(source: string, proof: SelectedProof): Promise<void> {
    await this.throttleGlobalThenSource(source);
    let anchor: RequestSessionRow | undefined;
    try {
      const { rows } = await this.pool.query<RequestSessionRow>(
        `SELECT s.id, s.secret_hash, s.intake_city_id, s.intake_city_version_id,
                s.created_at, s.expires_at, s.revoked_at, clock_timestamp() AS db_now
         FROM foundation.request_sessions s
         JOIN foundation.form_session_group_memberships m ON m.session_id=s.id
         WHERE s.id=$1`, [proof.selector],
      );
      anchor = rows[0];
    } catch (error) {
      throw this.mapOperationalError(error);
    }
    if (anchor === undefined || !sessionSecretMatches(proof.secret, anchor.secret_hash)) {
      throw new FormSessionAuthError(null);
    }
    if (anchorState(anchor) !== 'LIVE') {
      throw new FormSessionAuthError(`${F_COOKIE_PREFIX}${proof.selector}`);
    }
    await this.consumeThrottle('ANCHOR', proof.selector, this.config.throttles.anchor);
  }

  private assertAnchorUnexpired(anchor: RequestSessionRow, now: Date): void {
    if (anchor.expires_at.getTime() <= now.getTime()) {
      throw new FormSessionAuthError(`${F_COOKIE_PREFIX}${anchor.id}`);
    }
  }

  /** Anchor ownership/revocation is already proved under its row lock. For
   * logout that lock protects our own revoke; only expiry can invalidate it. */
  private async reproveMutation(
    client: PoolClient, anchor: RequestSessionRow, secret: string, csrf: string | undefined,
  ): Promise<void> {
    const now = await this.dbClock(client);
    this.assertAnchorUnexpired(anchor, now);
    this.verifyCsrf(anchor.id, secret, csrf, now.getTime(), anchor.expires_at.getTime());
  }

  private selectFormCookie(cookies: ReadonlyMap<string, string>, selector: string | undefined): SelectedProof {
    if (selector === undefined) {
      throw new FormSessionError('UNAUTHENTICATED');
    }
    if (!CANONICAL_UUID.test(selector)) {
      throw new FormSessionError('MALFORMED');
    }
    const secret = cookies.get(`${F_COOKIE_PREFIX}${selector}`);
    if (secret === undefined) {
      throw new FormSessionError('UNAUTHENTICATED');
    }
    return { selector, secret };
  }

  /**
   * Immutable membership mapping read: proves this request_sessions.id was
   * issued through the F protocol with a browser group. Liveness, expiry and
   * the secret proof live only in request_sessions and are checked by
   * `requireLiveAnchor` (behind `FOR UPDATE`, secret first).
   */
  private async readMembership(client: PoolClient, selector: string): Promise<MembershipRow | null> {
    const { rows } = await client.query<MembershipRow>(
      `SELECT session_id, group_id, created_at
       FROM foundation.form_session_group_memberships WHERE session_id=$1`,
      [selector],
    );
    return rows[0] ?? null;
  }

  /**
   * Anchor proof + liveness with the F cookie semantics. The membership is
   * checked first (unknown/foreign selector → plain UNAUTHENTICATED), then
   * `requireLiveAnchor` verifies the secret in constant time under `FOR
   * UPDATE`: a wrong secret is NOT_FOUND (no cookie clearing), while only a
   * correct secret on a revoked/expired anchor yields the addressed clearing.
   */
  private async liveAnchor(client: PoolClient, selector: string, secret: string): Promise<RequestSessionRow> {
    const membership = await this.readMembership(client, selector);
    if (membership === null) {
      throw new FormSessionAuthError(null);
    }
    try {
      return await requireLiveAnchor(client, { sessionId: selector, token: secret });
    } catch (error) {
      this.mapAnchorError(error, selector);
    }
  }

  private mapAnchorError(error: unknown, selector: string): never {
    if (error instanceof LegalPortError) {
      if (error.code === 'NOT_FOUND') {
        throw new FormSessionAuthError(null);
      }
      if (error.code === 'SESSION_REVOKED' || error.code === 'SESSION_EXPIRED') {
        throw new FormSessionAuthError(`${F_COOKIE_PREFIX}${selector}`);
      }
      if (error.code === 'CONFLICT') {
        throw new FormSessionError('UNAVAILABLE');
      }
    }
    throw error;
  }

  private verifyCsrf(
    selector: string, secret: string, proof: string | undefined, nowEpochMs: number, anchorExpiresAtEpochMs?: number,
  ): void {
    if (proof === undefined) {
      throw new FormSessionError('CSRF');
    }
    verifyCsrfProof(this.config.csrfKeyring, selector, secret, proof, nowEpochMs, anchorExpiresAtEpochMs);
  }

  /**
   * Database clock sampled in its own statement, *after* the lock that made the
   * caller's proof relevant. The host clock (`Date.now()`) is never a time
   * authority here: a CSRF proof, an anchor expiry and a consent decision must all
   * be judged on the same database clock the schema uses, otherwise a skewed
   * application host could extend or shorten a proof's life.
   */
  private async dbClock(client: PoolClient): Promise<Date> {
    const { rows } = await client.query<ClockRow>('SELECT clock_timestamp() AS db_now');
    const now = rows[0]?.db_now;
    if (now === undefined) {
      throw new FormSessionError('UNAVAILABLE');
    }
    return now;
  }

  /* ------------------------------- operations ------------------------------- */

  /** `POST /public/form-session/browser`: group bootstrap, never an F anchor. */
  async browserBootstrap(input: FormSessionBaseInput): Promise<BrowserBootstrapResult> {
    rejectPersonalFields(input.body);
    emptyObjectBody(input.body);
    const cookies = parseCookieHeader(input.cookieHeader);
    readFormCookies(cookies);
    const groupSecret = readGroupCookie(cookies);
    await this.throttleGlobalThenSource(input.source);
    return await this.withTransaction(async (client) => {
      if (groupSecret !== undefined) {
        const { rows } = await client.query<GroupRow>(
          `SELECT id, created_at, expires_at, clock_timestamp() AS db_now
           FROM foundation.form_browser_groups WHERE secret_hash=$1`,
          [hashSessionSecret(groupSecret)],
        );
        const existing = rows[0];
        if (existing === undefined) {
          // §4.1: a presented unknown group cookie is never silently replaced
          // with a fresh group. The bootstrap either confirms an existing group
          // or (with no cookie at all) creates one; an unproven presentation is
          // refused without any Set-Cookie, so the endpoint is no oracle and a
          // foreign cookie cannot mint a new identity over it.
          throw new FormSessionAuthError(null);
        }
        if (Math.floor((existing.expires_at.getTime() - existing.db_now.getTime()) / 1000) < 1) {
          // A confirmed exact expired (or sub-second-to-expiry) own group
          // cookie: addressed Max-Age=0 for that one cookie only, no
          // substitution, no fresh group in the same request. The client
          // re-runs the bootstrap without the cookie.
          throw new FormSessionAuthError(F_GROUP_COOKIE);
        }
        // Existing live group: return it unchanged, no re-issued cookie.
        return {
          groupId: existing.id,
          expiresAt: existing.expires_at.toISOString(),
          created: false,
          setCookie: null,
        };
      }
      const rawSecret = randomBytes(32).toString('base64url');
      const { rows } = await client.query<InsertedGroupRow>(
        `INSERT INTO foundation.form_browser_groups (id, secret_hash, expires_at)
         VALUES ($1, $2, clock_timestamp() + ($3::double precision * interval '1 millisecond'))
         RETURNING id, expires_at, clock_timestamp() AS db_now`,
        [randomUUID(), hashSessionSecret(rawSecret), this.config.groupTtlMs],
      );
      const created = rows[0];
      if (created === undefined) {
        throw new FormSessionError('CONFLICT');
      }
      // Conservative Max-Age: the floor of the true remaining DB lifetime, so
      // the cookie can never outlive the database expiry by even a
      // millisecond. With less than one second left no credential is issued at
      // all (a Max-Age >= 1 would exceed the DB TTL).
      const maxAgeSeconds = Math.floor((created.expires_at.getTime() - created.db_now.getTime()) / 1000);
      if (maxAgeSeconds < 1) {
        throw new FormSessionError('CONFLICT');
      }
      return {
        groupId: created.id,
        expiresAt: created.expires_at.toISOString(),
        created: true,
        setCookie: formatHostCookie(F_GROUP_COOKIE, rawSecret, maxAgeSeconds),
      };
    });
  }

  /** `POST /public/form-sessions`: F anchor issue under the group slot budget. */
  async issueSession(input: FormSessionBaseInput): Promise<IssueSessionResult> {
    rejectPersonalFields(input.body);
    emptyObjectBody(input.body);
    const cookies = parseCookieHeader(input.cookieHeader);
    const formCookies = readFormCookies(cookies);
    if (formCookies.length >= F_MAX_F_COOKIES) {
      // The request already carries the protocol maximum of proof cookies:
      // exhausted *slot* budget of the client-side jar (429), distinct from
      // the input transport cap (>8 presented cookies is a 413 of
      // `readFormCookies`).
      throw new FormSessionError('QUOTA');
    }
    const groupSecret = readGroupCookie(cookies);
    if (groupSecret === undefined) {
      throw new FormSessionError('UNAUTHENTICATED');
    }
    // Cheap global/source admission before the transaction and any durable
    // anchor allocation (MUST 7).
    await this.throttleGlobalThenSource(input.source);
    const groupSecretHash = hashSessionSecret(groupSecret);
    return await this.withTransaction(async (client) => {
      await this.fenceGeography(client);
      const city = await this.readCity(client);
      const { rows: groupRows } = await client.query<GroupRow>(
        `SELECT id, created_at, expires_at, clock_timestamp() AS db_now
         FROM foundation.form_browser_groups WHERE secret_hash=$1`,
        [groupSecretHash],
      );
      const group = groupRows[0];
      if (group === undefined) {
        throw new FormSessionError('UNAUTHENTICATED');
      }
      // Serialize parallel issue of this group (no UPDATE privilege exists on
      // the immutable groups table, so the row itself cannot be locked).
      await client.query('SELECT pg_catalog.pg_advisory_xact_lock(705021, hashtext($1))', [group.id]);
      const clock = await client.query<ClockRow>('SELECT clock_timestamp() AS db_now');
      const dbNow = clock.rows[0]?.db_now;
      if (dbNow === undefined) {
        throw new FormSessionError('UNAVAILABLE');
      }
      if (group.expires_at.getTime() <= dbNow.getTime()) {
        throw new FormSessionAuthError(F_GROUP_COOKIE);
      }
      // Check group expiry before checking slot quota to enforce 401+clear over 429.
      const anchorExpiresAtMs = Math.min(dbNow.getTime() + this.config.anchorTtlMs, group.expires_at.getTime());
      if (anchorExpiresAtMs - dbNow.getTime() < 1000) {
        if (group.expires_at.getTime() - dbNow.getTime() < 1000) {
          throw new FormSessionAuthError(F_GROUP_COOKIE);
        }
        throw new FormSessionError('CONFLICT');
      }

      // Count ALL live anchors of the group from the database, not the cookies.
      const live = await client.query<CountRow>(
        `SELECT count(*)::int AS live_count
         FROM foundation.form_session_group_memberships m
         JOIN foundation.request_sessions s ON s.id = m.session_id
         WHERE m.group_id=$1
           AND s.revoked_at IS NULL
           AND s.expires_at > clock_timestamp()`,
        [group.id],
      );
      const liveCount = live.rows[0]?.live_count;
      if (liveCount === undefined || !Number.isSafeInteger(liveCount) || liveCount < 0) {
        throw new FormSessionError('UNAVAILABLE');
      }
      if (liveCount >= F_MAX_LIVE_ANCHORS_PER_GROUP) {
        throw new FormSessionError('QUOTA');
      }

      const anchorExpiresAt = new Date(anchorExpiresAtMs);
      const rawToken = randomBytes(32).toString('base64url');
      const tokenHash = hashSessionSecret(rawToken);
      const session = await createRequestSession(client, {
        secretHash: tokenHash,
        intakeCityId: city.cityId,
        intakeCityVersionId: city.cityVersionId,
        expiresAt: anchorExpiresAt,
      });
      // The membership is the thin immutable 1:1 mapping of the P03 anchor id
      // to its browser group: session_id is the public F selector itself.
      await client.query(
        `INSERT INTO foundation.form_session_group_memberships (session_id, group_id) VALUES ($1, $2)`,
        [session.sessionId, group.id],
      );
      const final = await client.query<ClockRow>('SELECT clock_timestamp() AS db_now');
      const finalNow = final.rows[0]?.db_now;
      if (finalNow === undefined) {
        throw new FormSessionError('UNAVAILABLE');
      }
      if (finalNow.getTime() >= anchorExpiresAt.getTime()) {
        throw new FormSessionError('CONFLICT');
      }
      const csrfExpiresAtMs = Math.min(finalNow.getTime() + this.config.csrfTtlMs, anchorExpiresAt.getTime());
      const csrfToken = issueCsrfProof(this.config.csrfKeyring.current, session.sessionId, rawToken, csrfExpiresAtMs);
      // Conservative Max-Age: the floor of the true remaining anchor lifetime
      // (no `Math.max(1, ...)`), so the cookie never outlives the DB expiry. A
      // sub-second remainder was already refused above; the final clock sample
      // here re-checks it after all lock waits.
      const maxAgeSeconds = Math.floor((anchorExpiresAt.getTime() - finalNow.getTime()) / 1000);
      if (maxAgeSeconds < 1) {
        if (group.expires_at.getTime() - finalNow.getTime() < 1000) {
          throw new FormSessionAuthError(F_GROUP_COOKIE);
        }
        throw new FormSessionError('CONFLICT');
      }
      return {
        sessionId: session.sessionId,
        setCookie: formatHostCookie(`${F_COOKIE_PREFIX}${session.sessionId}`, rawToken, maxAgeSeconds),
        csrfToken,
        csrfExpiresAt: new Date(csrfExpiresAtMs).toISOString(),
        intakeCityId: city.cityId,
        intakeCityVersionId: city.cityVersionId,
        timezone: city.timezone,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
      };
    });
  }

  /** `POST /public/form-session/csrf`: read-only proof bootstrap, no anchor extension. */
  async csrfBootstrap(input: FormSessionSelectorInput): Promise<CsrfBootstrapResult> {
    rejectPersonalFields(input.body);
    emptyObjectBody(input.body);
    const cookies = parseCookieHeader(input.cookieHeader);
    readFormCookies(cookies);
    const proof = this.selectFormCookie(cookies, input.selector);
    const { selector, secret } = proof;
    await this.throttleProvenAnchor(input.source, proof);
    return await this.withTransaction(async (client) => {
      const anchor = await this.liveAnchor(client, selector, secret);
      // MUST 3: judge the anchor against a *fresh* database clock sampled in
      // its own statement after the lock wait, never the clock of the locking
      // statement (which may have been evaluated during the wait).
      const now = await this.dbClock(client);
      this.assertAnchorUnexpired(anchor, now);
      const csrfExpiresAtMs = Math.min(
        now.getTime() + this.config.csrfTtlMs,
        anchor.expires_at.getTime(),
      );
      const csrfToken = issueCsrfProof(this.config.csrfKeyring.current, selector, secret, csrfExpiresAtMs);
      return {
        sessionId: selector,
        expiresAt: anchor.expires_at.toISOString(),
        csrfToken,
        csrfExpiresAt: new Date(csrfExpiresAtMs).toISOString(),
      };
    });
  }

  /** `POST /public/form-session/revoke`: logout; no disclosure, no resurrection. */
  async revokeSession(input: FormSessionSelectorInput): Promise<RevokeResult> {
    rejectPersonalFields(input.body);
    emptyObjectBody(input.body);
    const cookies = parseCookieHeader(input.cookieHeader);
    readFormCookies(cookies);
    const proof = this.selectFormCookie(cookies, input.selector);
    const { selector, secret } = proof;
    await this.throttleProvenAnchor(input.source, proof);
    return await this.withTransaction(async (client) => {
      // Membership + secret + liveness under the anchor lock: a wrong secret
      // is a plain UNAUTHENTICATED, a dead own anchor is the addressed clearing.
      const anchor = await this.liveAnchor(client, selector, secret);
      // The CSRF window is evaluated on the database clock sampled *after* the
      // anchor lock (never on the host clock), so a lock wait cannot let an
      // expired proof through. Ownership/liveness is proven first: a live own
      // anchor with a bad/absent CSRF is 403 without clearing the live cookie,
      // while a dead own anchor is 401 with the addressed clearing even when
      // the CSRF expired at the same moment.
      await this.reproveMutation(client, anchor, secret, input.csrf);
      // Revoke lives in request_sessions.revoked_at; the membership table is
      // immutable history, so no membership UPDATE exists here.
      try {
        await revokeRequestSession(client, { sessionId: selector, token: secret });
      } catch (error) {
        this.mapAnchorError(error, selector);
      }
      // Recheck both credentials after the UPDATE and audit; a late refusal
      // rolls them back together. A dead own anchor takes priority over CSRF.
      await this.reproveMutation(client, anchor, secret, input.csrf);
      return {
        revoked: true,
        setCookie: formatHostCookie(`${F_COOKIE_PREFIX}${selector}`, '', 0),
      };
    });
  }

  /** `GET /public/legal-documents/{kind}`: current published REQUEST_PROCESSING document. */
  async readLegalDocument(kind: LegalKindParam, input: { readonly source: string }): Promise<LegalDocumentPublic> {
    await this.throttleGlobalThenSource(input.source);
    return await this.withTransaction(async (client) => {
      await this.fenceGeography(client);
      const doc = await readCurrentLegalDocument(client, 'REQUEST_PROCESSING', kind);
      if (doc === null) {
        throw new FormSessionError('NOT_FOUND');
      }
      // Public projection: no reviewedBy, no sourceRef (operator-only fields).
      return {
        documentId: doc.documentId,
        versionId: doc.id,
        purpose: 'REQUEST_PROCESSING',
        kind: doc.kind === 'POLICY' || doc.kind === 'CONSENT_FORM' ? doc.kind : kind,
        version: doc.sequence,
        title: doc.title,
        body: doc.body,
        checksum: doc.checksum,
        legalBasis: doc.legalBasis,
        publishedAt: doc.publishedAt,
      };
    });
  }

  /** `POST /public/form-session/consents`: exact GIVEN/REVOKED evidence. */
  async recordConsent(input: FormSessionConsentInput): Promise<ConsentResult> {
    rejectPersonalFields(input.body);
    const parsed = consentBody(input.body);
    // Shape check of the mandatory Idempotency-Key is pure and happens before any
    // database work; its *binding* to this session and intent is checked below,
    // only after the anchor proof, so a business refusal never precedes auth.
    const key = idempotencyKey(input.idempotencyKey);
    const cookies = parseCookieHeader(input.cookieHeader);
    readFormCookies(cookies);
    const proof = this.selectFormCookie(cookies, input.selector);
    const { selector, secret } = proof;
    await this.throttleProvenAnchor(input.source, proof);
    return await this.withTransaction(async (client) => {
      await this.fenceGeography(client);
      const anchor = await this.liveAnchor(client, selector, secret);
      // CSRF is verified on the database clock sampled after the anchor lock,
      // never on the host clock. The anchor proof comes first: a live own
      // anchor with a bad CSRF is 403 without clearing, a dead own anchor is
      // the addressed 401 clearing.
      await this.reproveMutation(client, anchor, secret, input.csrf);
      // The key is bound to this F-session and this operation: it must be the
      // evidence identity of the single append-only event, so a repeat replays
      // that event and a reused key with another intent is a conflict instead of
      // a second write.
      bindIdempotencyKey(key, parsed.evidenceRef);
      if (parsed.action === 'GIVEN' && this.schema === 'S3' && (await client.query(
        'SELECT session_id FROM foundation.request_session_submits WHERE session_id=$1', [selector])).rowCount !== 0) {
        throw new FormSessionError('CONFLICT');
      }
      await this.requireSameConsentIntent(client, selector, parsed);
      if (parsed.action === 'GIVEN') {
        // A new GIVEN requires the current city/version the anchor was issued with.
        await this.requireAnchorCity(client, anchor);
      }
      let receipt: ConsentReceipt;
      try {
        receipt = parsed.action === 'GIVEN'
          ? await recordConsentGiven(client, {
            session: { sessionId: selector, token: secret },
            purpose: 'REQUEST_PROCESSING',
            documentId: parsed.documentId,
            documentVersionId: parsed.documentVersionId,
            evidenceRef: parsed.evidenceRef,
            accepted: true,
          })
          : await this.revokeConsentWithTarget(client, selector, parsed, secret);
      } catch (error) {
        this.mapConsentError(error, selector);
      }
      // The legal port's document lock may have waited past a city/version
      // publish. The event is already written inside this transaction, so a
      // mismatch now refuses the whole transaction: no evidence, no audit and no
      // outbox row survives a decision taken on stale geography.
      if (parsed.action === 'GIVEN') {
        await this.requireAnchorCity(client, anchor);
      }
      await this.reproveMutation(client, anchor, secret, input.csrf);
      return { receipt, replayed: receipt.replayed };
    });
  }

  /**
   * The anchor's intake city/version must still be the single current context.
   * Read as a fresh statement after the GEO/CFG fence (and, on the post-lock
   * call, after the legal port's document lock), so a concurrent publish is
   * observed instead of being served from a snapshot taken before the wait.
   */
  private async requireAnchorCity(
    client: PoolClient, anchor: { readonly intake_city_id: string; readonly intake_city_version_id: string },
  ): Promise<void> {
    const city = await this.readCity(client);
    if (city.cityId !== anchor.intake_city_id || city.cityVersionId !== anchor.intake_city_version_id) {
      throw new FormSessionError('CONFLICT');
    }
  }

  /** Look at the caller's own key after locked F+CSRF proof, never at the
   * requested target to decide whether that key was reused. Replays still go
   * through the legacy port's current-document/revocation checks. */
  private async requireSameConsentIntent(client: PoolClient, selector: string, parsed: ConsentBody): Promise<void> {
    const { rows } = await client.query<ConsentIntentRow>(
      `SELECT id, action, purpose, document_id, document_version_id, supersedes_id
       FROM foundation.consent_records WHERE session_id=$1 AND evidence_ref=$2`,
      [selector, parsed.evidenceRef],
    );
    const existing = rows[0];
    if (existing === undefined) { return; }
    const same = existing.purpose === 'REQUEST_PROCESSING' && existing.action === parsed.action
      && (parsed.documentId === undefined || existing.document_id === parsed.documentId)
      && (parsed.documentVersionId === undefined || existing.document_version_id === parsed.documentVersionId)
      && (parsed.action === 'GIVEN' ? existing.supersedes_id === null
        : existing.supersedes_id === parsed.supersedesEvidenceId);
    if (!same) { throw new FormSessionError('CONFLICT'); }
  }

  /**
   * REVOKED names the exact GIVEN event; the requested document/version pair
   * must match the stored event before the legal port supersedes it.
   */
  private async revokeConsentWithTarget(
    client: PoolClient, selector: string, parsed: ConsentBody & { action: 'REVOKED' }, secret: string,
  ): Promise<ConsentReceipt> {
    const { rows } = await client.query<GivenRow>(
      `SELECT id, document_id, document_version_id FROM foundation.consent_records
       WHERE id=$1 AND session_id=$2 AND purpose='REQUEST_PROCESSING' AND action='GIVEN'`,
      [parsed.supersedesEvidenceId, selector],
    );
    const given = rows[0];
    if (given === undefined) {
      throw new LegalPortError('NOT_FOUND');
    }
    if ((parsed.documentId !== undefined && given.document_id !== parsed.documentId)
      || (parsed.documentVersionId !== undefined && given.document_version_id !== parsed.documentVersionId)) {
      throw new LegalPortError('REPLAY_MISMATCH');
    }
    return await recordConsentRevoked(client, {
      session: { sessionId: selector, token: secret },
      purpose: 'REQUEST_PROCESSING',
      evidenceRef: parsed.evidenceRef,
      supersedesEvidenceId: parsed.supersedesEvidenceId,
    });
  }

  private mapConsentError(error: unknown, selector: string): never {
    if (!(error instanceof LegalPortError)) {
      throw error;
    }
    switch (error.code) {
      case 'SESSION_EXPIRED':
      case 'SESSION_REVOKED':
        throw new FormSessionAuthError(`${F_COOKIE_PREFIX}${selector}`);
      case 'DOCUMENT_NOT_CURRENT':
      case 'DOCUMENT_NOT_PUBLISHED':
      case 'CONSENT_ALREADY_ACTIVE':
      case 'CONSENT_REVOKED':
      case 'REPLAY_MISMATCH':
      case 'STALE_VERSION':
      case 'ALREADY_EXISTS':
        throw new FormSessionError('CONFLICT');
      case 'KIND_NOT_CONSENT_FORM':
      case 'INVALID_REFERENCE':
        throw new FormSessionError('UNPROCESSABLE');
      case 'NOT_FOUND':
        throw new FormSessionError('NOT_FOUND');
      case 'INVALID_INPUT':
        throw new FormSessionError('MALFORMED');
      default:
        throw error;
    }
  }

  /** `POST /public/coverage/check`: district-only advisory before consent. */
  async checkCoverage(input: FormSessionSelectorInput): Promise<CoverageResult> {
    const parsed: DistrictCheckBody = districtCheckBody(input.body);
    const cookies = parseCookieHeader(input.cookieHeader);
    readFormCookies(cookies);
    const proof = this.selectFormCookie(cookies, input.selector);
    const { selector, secret } = proof;
    await this.throttleProvenAnchor(input.source, proof);
    return await this.withTransaction(async (client) => {
      await this.fenceGeography(client);
      const anchor = await this.liveAnchor(client, selector, secret);
      // CSRF is verified on the database clock sampled after the anchor lock.
      // The anchor proof precedes the CSRF decision, so a dead own anchor is
      // the addressed 401 clearing even when its CSRF expired too.
      await this.reproveMutation(client, anchor, secret, input.csrf);
      const city = await this.readCity(client);
      if (city.cityId !== anchor.intake_city_id || city.cityVersionId !== anchor.intake_city_version_id) {
        throw new FormSessionError('CONFLICT');
      }
      const advisory = await adviseDistrict(client, anchor.intake_city_id, parsed.districtId);
      await this.reproveMutation(client, anchor, secret, input.csrf);
      return {
        cityId: anchor.intake_city_id,
        cityVersionId: anchor.intake_city_version_id,
        districtId: advisory.districtId,
        outcome: advisory.outcome,
        hints: advisory.hints,
      };
    });
  }
}
