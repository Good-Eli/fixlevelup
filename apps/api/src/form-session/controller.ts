/**
 * P05-02 F surface HTTP controller (docs/P05-PLAN.md §4.1, §6.3).
 *
 * Transport shell over `FormSessionApi`: exact-Origin / JSON / marker-header
 * checks, refusal-to-HTTP mapping, addressed cookie clearing and the envelope
 * serialization. It owns no business rule: every decision comes from the
 * service, whose typed refusals are translated 1:1 into the §6.3 status
 * classification (malformed→400; missing/dead auth→401; denied
 * capability/CSRF/origin→403; foreign target→404; business/state→409;
 * semantic→422; quota→429; safe unavailable→503).
 *
 * Same-origin discipline for the F surface:
 *
 * - every F route requires the exact configured `Origin` (a missing or
 *   different one is 403; a duplicated header is 400);
 * - `Authorization` (a staff/TG bearer) is never an F credential: its presence
 *   is refused before anything else;
 * - `X-Form-Session-Id` selects the proof cookie on the selector routes, and
 *   its absence on `browser`/`form-sessions` routes is enforced as a 400,
 *   because the selector must not be chosen yet;
 * - `/form-session/browser` additionally requires a non-simple custom marker
 *   header (`x-form-session-bootstrap` or `x-requested-with`), so the group
 *   bootstrap cannot be issued by a plain cross-site form post;
 * - `/form-session/consents` requires the mandatory `Idempotency-Key` header (a
 *   canonical UUID). The key is bound to the F-session and to the exact intent by
 *   the service, so a repeat of the same key and intent replays the stored event
 *   (`200`) instead of creating a second one, while the same key with a different
 *   intent is a `409` refusal;
 * - a CRM `__Host-fixlevelup_session` cookie is ignored, never honoured as an
 *   F proof and never cleared;
 * - a provably dead own proof cookie is cleared with an addressed `Max-Age=0`
 *   `Set-Cookie`; a foreign or unknown one never is (no oracle).
 *
 * Refusal classification keeps the two "too much" refusals apart (§6.3): a body
 * that exceeds the JSON contract (byte/depth/node cap) is `413 Payload Too Large`,
 * while a rate-limit/quota refusal (throttle budget, live-anchor slot, proof-cookie
 * cap) is `429 Too Many Requests`. Neither is ever reported as the other, and
 * neither is collapsed into the `400` of a malformed body.
 *
 * All responses (success and problem) carry `Cache-Control: no-store`.
 */
import {
  BadRequestException,
  Controller,
  ForbiddenException,
  Get,
  HttpException,
  Inject,
  NotFoundException,
  Post,
  Req,
  Res,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { envelope, header } from '../auth/http.js';
import { F_CSRF_HEADER, F_IDEMPOTENCY_HEADER, F_SELECTOR_HEADER, FormSessionError, idempotencyKey, legalKindParam } from './contract.js';
import type { FormSessionErrorCode, LegalKindParam } from './contract.js';
import { formatHostCookie, parseCookieHeader, readFormCookies } from './cookies.js';
import { matchP05FormSessionRoute, P05_F_JSON_RESPONSE_LIMIT_BYTES, P05_F_RESPONSE_LIMIT_BYTES } from './routes.js';
import type { P05FormSessionOperation, P05FormSessionRoute } from './routes.js';
import { FormSessionAuthError } from './service.js';
import type {
  BrowserBootstrapResult, ConsentResult, CoverageResult, CsrfBootstrapResult, FormSessionApi, IssueSessionResult,
  LegalDocumentPublic, RevokeResult,
} from './service.js';

/** DI token: bind the service + database readiness + origin in the module. */
export const FORM_SESSION_HTTP_DEPS = Symbol('FORM_SESSION_HTTP_DEPS');

/** Mechanical readiness gates the controller refuses to serve without. */
export interface FormSessionReadiness {
  requestIntakeReady(): Promise<boolean>;
  formSessionReady(): Promise<boolean>;
}

export async function requireFormSessionReady(database: FormSessionReadiness): Promise<void> {
  let ready: boolean;
  try {
    ready = await database.requestIntakeReady() && await database.formSessionReady();
  } catch {
    ready = false;
  }
  if (!ready) { throw new ServiceUnavailableException(); }
}

export interface FormSessionHttpConfig {
  /** Exact allowed browser Origin, same value the service was built with. */
  readonly origin: string;
}

export interface FormSessionHttpDeps {
  readonly service: FormSessionApi;
  readonly database: FormSessionReadiness;
  readonly config: FormSessionHttpConfig;
}

/** Raw HTTP request as shaped by the shared bounded JSON middleware. */
type FormSessionRequest = IncomingMessage & { body?: unknown };

const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const JSON_CONTENT_TYPE = /^application\/json(?:\s*;\s*charset\s*=\s*utf-8)?$/i;
const BOOTSTRAP_MARKER_VALUES = new Set(['1', 'true']);

/**
 * Security-relevant headers whose uniqueness is enforced on *every* P05-02
 * route, regardless of whether that particular route uses the header: a
 * duplicated `Cookie`, `Origin`, `Content-Type`, selector/CSRF/idempotency or
 * conditional header must be refused 400 before any effect, on the public GET
 * as well (MUST 5).
 */
const SECURITY_HEADERS: readonly string[] = [
  'origin',
  'cookie',
  'authorization',
  'content-encoding',
  'content-type',
  'content-length',
  'transfer-encoding',
  'x-form-session-id',
  'x-csrf-token',
  'idempotency-key',
  'x-form-session-bootstrap',
  'x-requested-with',
  'if-match',
  'if-none-match',
];

function validateFormSessionHeaders(req: FormSessionRequest): void {
  const seen = new Set<string>();
  for (let index = 0; index < req.rawHeaders.length; index += 2) {
    const name = req.rawHeaders[index]?.toLowerCase();
    if (name === undefined || !SECURITY_HEADERS.includes(name)) { continue; }
    if (seen.has(name)) { throw new BadRequestException(); }
    seen.add(name);
  }
}

/** §6.3 classification of the closed P05-02 refusal vocabulary.
 * `PII_REJECTED` is deliberately 400, matching the project-wide treatment of
 * forbidden/unknown JSON body fields; the service-level code stays distinct
 * so unit tests can assert it exactly. */
const STATUS_BY_CODE: Readonly<Record<FormSessionErrorCode, number>> = Object.freeze({
  MALFORMED: 400,
  ORIGIN: 403,
  CSRF: 403,
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  PAYLOAD_TOO_LARGE: 413,
  UNSUPPORTED_MEDIA: 415,
  UNPROCESSABLE: 422,
  QUOTA: 429,
  UNAVAILABLE: 503,
  PII_REJECTED: 400,
});

function statusOf(code: FormSessionErrorCode): number {
  // The frozen Record covers the whole closed vocabulary; an unknown key is
  // impossible by type, and the map itself is 1:1 with the §6.3 classification.
  return STATUS_BY_CODE[code];
}

@Controller('api/v1/public')
export class FormSessionController {
  private readonly service: FormSessionApi;
  private readonly database: FormSessionReadiness;
  private readonly origin: string;

  constructor(@Inject(FORM_SESSION_HTTP_DEPS) deps: FormSessionHttpDeps) {
    let parsed: URL;
    try {
      parsed = new URL(deps.config.origin);
    } catch {
      throw new Error('Invalid form session HTTP configuration');
    }
    if (parsed.protocol !== 'https:' || parsed.origin !== deps.config.origin) {
      throw new Error('Invalid form session HTTP configuration');
    }
    this.service = deps.service;
    this.database = deps.database;
    this.origin = deps.config.origin;
  }

  /* --------------------------- transport primitives -------------------------- */

  /** Recheck after streamed-body handling; readiness can change as it arrives. */
  private async ready(req: FormSessionRequest): Promise<void> {
    await requireFormSessionReady(this.database);
    validateFormSessionHeaders(req);
  }

  /** Exact configured Origin; a missing one is also denied (403). */
  private expectExactOrigin(req: FormSessionRequest): void {
    if (header(req, 'origin') !== this.origin) {
      throw new ForbiddenException();
    }
  }

  /**
   * JSON-only bodies, mirroring the shared middleware: a non-JSON type is 400;
   * `application/json` with an unsupported parameter (charset) is 415.
   */
  private expectJsonContentType(req: FormSessionRequest): void {
    const type = header(req, 'content-type');
    if (JSON_CONTENT_TYPE.test(type ?? '')) {
      return;
    }
    if (type !== undefined && /^application\/json\s*;/i.test(type)) {
      throw new HttpException('Unsupported Media Type', 415);
    }
    throw new BadRequestException();
  }

  /** A staff/TG bearer is never an F credential; refuse it before anything. */
  private rejectAuthorization(req: FormSessionRequest): void {
    if (header(req, 'authorization') !== undefined) {
      throw new UnauthorizedException();
    }
  }

  /** No query string on any F route. */
  private rejectQuery(req: FormSessionRequest): void {
    const search = new URL(req.url ?? '/', 'http://localhost').searchParams;
    if (search.size > 0) {
      throw new BadRequestException();
    }
  }

  /** The selector must not be chosen yet on `browser`/`form-sessions`. */
  private rejectSelectorHeader(req: FormSessionRequest): void {
    if (header(req, F_SELECTOR_HEADER) !== undefined) {
      throw new BadRequestException();
    }
  }

  /**
   * Non-simple same-origin marker for the group bootstrap: either
   * `x-form-session-bootstrap: 1|true` or a non-empty `x-requested-with`.
   * Duplicates are refused by the duplicate-aware header reader (400).
   */
  private expectBootstrapMarker(req: FormSessionRequest): void {
    const marker = header(req, 'x-form-session-bootstrap');
    const requestedWith = header(req, 'x-requested-with');
    const markerOk = marker !== undefined && BOOTSTRAP_MARKER_VALUES.has(marker);
    const requestedOk = requestedWith !== undefined && requestedWith.length > 0;
    if (!markerOk && !requestedOk) {
      throw new ForbiddenException();
    }
  }

  private selectorHeader(req: FormSessionRequest): string | undefined {
    const selector = header(req, F_SELECTOR_HEADER);
    if (selector !== undefined && !CANONICAL_UUID.test(selector)) {
      throw new BadRequestException();
    }
    return selector;
  }

  private csrfHeader(req: FormSessionRequest): string | undefined {
    return header(req, F_CSRF_HEADER);
  }

  /**
   * Mandatory `Idempotency-Key` of a consent mutation. It is a canonical lowercase
   * UUID; a missing or malformed key is a `400` before any cookie, throttle or
   * database work, and a duplicated header is already a `400` in the reader. The
   * service binds the key to the F-session and to the exact intent.
   */
  private idempotencyHeader(req: FormSessionRequest): string {
    return idempotencyKey(header(req, F_IDEMPOTENCY_HEADER));
  }

  private sourceOf(req: FormSessionRequest): string {
    const source = req.socket.remoteAddress;
    if (source === undefined || source.length === 0) {
      throw new BadRequestException();
    }
    return source;
  }

  /**
   * MUST 4: binds a handler to the exact canonical route from the raw method
   * and path. Express's default non-strict routing also dispatches case
   * variants, trailing slashes and automatic `HEAD → GET` to the same handler;
   * this check runs first in every one of the seven handlers, so a
   * non-canonical spelling (or a query string smuggled past earlier checks)
   * gets a 404 *before* any effect — never the fallback interpretation.
   */
  private requireExactRoute(req: FormSessionRequest, expected: P05FormSessionOperation): P05FormSessionRoute {
    const raw = req.url ?? '';
    const qIndex = raw.indexOf('?');
    if (qIndex >= 0) {
      throw new BadRequestException();
    }
    const matched = matchP05FormSessionRoute(req.method ?? '', raw);
    if (matched === null || matched.operation !== expected) {
      throw new NotFoundException();
    }
    return matched;
  }

  /** Transport caps and F cookie syntax, including optional cookies on GET. */
  private validateCookies(req: FormSessionRequest): void {
    const cookieHeader = header(req, 'cookie');
    if (cookieHeader !== undefined) {
      const cookies = parseCookieHeader(cookieHeader);
      readFormCookies(cookies);
    }
  }

  /**
   * `Idempotency-Key` belongs to the consent mutation only; presenting it on
   * any other F route is a 400 protocol error.
   */
  private rejectIdempotencyHeader(req: FormSessionRequest): void {
    if (header(req, F_IDEMPOTENCY_HEADER) !== undefined) {
      throw new BadRequestException();
    }
  }

  /**
   * Sends the final envelope as exact UTF-8 JSON. The byte cap mirrors the
   * route table's response limit, so a hostile document body cannot stream an
   * unbounded answer.
   */
  private send(res: ServerResponse, statusCode: number, data: unknown, limit: number, setCookie?: string | null): void {
    const payload = JSON.stringify(envelope(data));
    const bytes = Buffer.byteLength(payload, 'utf8');
    if (bytes > limit) {
      // SHOULD: a response over the route cap is a predictable safe
      // unavailability. Serving a truncated body would break the checksum
      // contract of the legal document, and a 500 would misclassify a
      // bounded-cap condition as an internal error.
      throw new ServiceUnavailableException();
    }
    res.setHeader('Cache-Control', 'no-store');
    if (setCookie !== undefined && setCookie !== null) {
      res.setHeader('Set-Cookie', setCookie);
    }
    res.statusCode = statusCode;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(payload);
  }

  /**
   * Translates a typed service refusal. `FormSessionAuthError` may carry the
   * name of one provably dead own proof cookie: the addressed `Max-Age=0`
   * clearing is attached to the response headers before the problem is sent,
   * so the filter keeps it (it only adds its own headers).
   */
  private refuse(res: ServerResponse, error: unknown): never {
    if (error instanceof FormSessionAuthError) {
      if (error.clearCookieName !== null) {
        res.setHeader('Set-Cookie', formatHostCookie(error.clearCookieName, '', 0));
      }
      throw new UnauthorizedException();
    }
    if (error instanceof FormSessionError) {
      const status = statusOf(error.code);
      if (status === 404) {
        throw new NotFoundException();
      }
      if (status === 503) {
        throw new ServiceUnavailableException();
      }
      throw new HttpException('Error', status);
    }
    throw error;
  }

  /* -------------------------------- routes --------------------------------- */

  @Post('form-session/browser')
  async browserBootstrap(@Req() req: FormSessionRequest, @Res() res: ServerResponse): Promise<void> {
    this.requireExactRoute(req, 'browserBootstrap');
    await this.ready(req);
    this.expectExactOrigin(req);
    this.expectJsonContentType(req);
    this.rejectAuthorization(req);
    this.rejectSelectorHeader(req);
    this.expectBootstrapMarker(req);
    try {
      this.validateCookies(req);
    } catch (error) {
      this.refuse(res, error);
    }
    this.rejectIdempotencyHeader(req);
    this.rejectQuery(req);
    try {
      const result: BrowserBootstrapResult = await this.service.browserBootstrap({
        cookieHeader: header(req, 'cookie'),
        body: req.body,
        source: this.sourceOf(req),
      });
      this.send(res, 200, { groupId: result.groupId, expiresAt: result.expiresAt, created: result.created },
        P05_F_JSON_RESPONSE_LIMIT_BYTES, result.setCookie);
    } catch (error) {
      this.refuse(res, error);
    }
  }

  @Post('form-sessions')
  async issueSession(@Req() req: FormSessionRequest, @Res() res: ServerResponse): Promise<void> {
    this.requireExactRoute(req, 'issueSession');
    await this.ready(req);
    this.expectExactOrigin(req);
    this.expectJsonContentType(req);
    this.rejectAuthorization(req);
    this.rejectSelectorHeader(req);
    try {
      this.validateCookies(req);
    } catch (error) {
      this.refuse(res, error);
    }
    this.rejectIdempotencyHeader(req);
    this.rejectQuery(req);
    try {
      const result: IssueSessionResult = await this.service.issueSession({
        cookieHeader: header(req, 'cookie'),
        body: req.body,
        source: this.sourceOf(req),
      });
      res.setHeader('X-Form-Session-Id', result.sessionId);
      this.send(res, 201, {
        sessionId: result.sessionId,
        intakeCityId: result.intakeCityId,
        intakeCityVersionId: result.intakeCityVersionId,
        timezone: result.timezone,
        createdAt: result.createdAt,
        expiresAt: result.expiresAt,
        csrfToken: result.csrfToken,
        csrfExpiresAt: result.csrfExpiresAt,
      }, P05_F_JSON_RESPONSE_LIMIT_BYTES, result.setCookie);
    } catch (error) {
      this.refuse(res, error);
    }
  }

  @Post('form-session/csrf')
  async csrfBootstrap(@Req() req: FormSessionRequest, @Res() res: ServerResponse): Promise<void> {
    this.requireExactRoute(req, 'csrfBootstrap');
    await this.ready(req);
    this.expectExactOrigin(req);
    this.expectJsonContentType(req);
    this.rejectAuthorization(req);
    try {
      this.validateCookies(req);
    } catch (error) {
      this.refuse(res, error);
    }
    this.rejectIdempotencyHeader(req);
    this.rejectQuery(req);
    try {
      const result: CsrfBootstrapResult = await this.service.csrfBootstrap({
        cookieHeader: header(req, 'cookie'),
        body: req.body,
        source: this.sourceOf(req),
        selector: this.selectorHeader(req),
        csrf: undefined,
      });
      this.send(res, 200, {
        sessionId: result.sessionId,
        expiresAt: result.expiresAt,
        csrfToken: result.csrfToken,
        csrfExpiresAt: result.csrfExpiresAt,
      }, P05_F_JSON_RESPONSE_LIMIT_BYTES);
    } catch (error) {
      this.refuse(res, error);
    }
  }

  @Post('form-session/revoke')
  async revokeSession(@Req() req: FormSessionRequest, @Res() res: ServerResponse): Promise<void> {
    this.requireExactRoute(req, 'revokeSession');
    await this.ready(req);
    this.expectExactOrigin(req);
    this.expectJsonContentType(req);
    this.rejectAuthorization(req);
    try {
      this.validateCookies(req);
    } catch (error) {
      this.refuse(res, error);
    }
    this.rejectIdempotencyHeader(req);
    this.rejectQuery(req);
    try {
      const result: RevokeResult = await this.service.revokeSession({
        cookieHeader: header(req, 'cookie'),
        body: req.body,
        source: this.sourceOf(req),
        selector: this.selectorHeader(req),
        csrf: this.csrfHeader(req),
      });
      this.send(res, 200, { revoked: result.revoked }, P05_F_JSON_RESPONSE_LIMIT_BYTES, result.setCookie);
    } catch (error) {
      this.refuse(res, error);
    }
  }

  @Get('legal-documents/:kind')
  async readLegalDocument(@Req() req: FormSessionRequest, @Res() res: ServerResponse): Promise<void> {
    const matched = this.requireExactRoute(req, 'readLegalDocument');
    await this.ready(req);
    // A GET may legitimately arrive without an Origin header; any supplied one
    // must still match exactly. Duplicates stay a 400 via the header reader.
    const suppliedOrigin = header(req, 'origin');
    if (suppliedOrigin !== undefined && suppliedOrigin !== this.origin) {
      throw new ForbiddenException();
    }
    this.rejectAuthorization(req);
    // MUST 5: the public GET enforces the same security-header uniqueness and
    // cookie transport caps (8 KiB / ≤8 F-cookies → 413, syntax → 400) as the
    // rest of the surface, without ever *requiring* an F cookie.
    try {
      this.validateCookies(req);
    } catch (error) {
      this.refuse(res, error);
    }
    this.rejectIdempotencyHeader(req);
    this.rejectQuery(req);
    if (req.body !== undefined) {
      throw new BadRequestException();
    }
    const rawKind = matched.params['kind'] ?? '';
    try {
      // An unknown kind narrows to the same NOT_FOUND inside the guarded block,
      // so the typed refusal reaches `refuse()` instead of the generic 500.
      const kind: LegalKindParam = legalKindParam(rawKind);
      const doc: LegalDocumentPublic = await this.service.readLegalDocument(kind, { source: this.sourceOf(req) });
      this.send(res, 200, {
        documentId: doc.documentId,
        versionId: doc.versionId,
        purpose: doc.purpose,
        kind: doc.kind,
        version: doc.version,
        title: doc.title,
        body: doc.body,
        checksum: doc.checksum,
        legalBasis: doc.legalBasis,
        publishedAt: doc.publishedAt,
      }, P05_F_RESPONSE_LIMIT_BYTES);
    } catch (error) {
      this.refuse(res, error);
    }
  }

  @Post('form-session/consents')
  async recordConsent(@Req() req: FormSessionRequest, @Res() res: ServerResponse): Promise<void> {
    this.requireExactRoute(req, 'recordConsent');
    await this.ready(req);
    this.expectExactOrigin(req);
    this.expectJsonContentType(req);
    this.rejectAuthorization(req);
    try {
      this.validateCookies(req);
    } catch (error) {
      this.refuse(res, error);
    }
    this.rejectQuery(req);
    try {
      // The mandatory key is checked first: a protocol error must surface as its
      // own 400 and never be hidden behind a later 401/403 of the proof checks.
      const key = this.idempotencyHeader(req);
      const result: ConsentResult = await this.service.recordConsent({
        cookieHeader: header(req, 'cookie'),
        body: req.body,
        source: this.sourceOf(req),
        selector: this.selectorHeader(req),
        csrf: this.csrfHeader(req),
        idempotencyKey: key,
      });
      // An exact replay of the same key and intent is not a new event: 200, the
      // first write is 201. A reused key with a different intent is a 409 refusal
      // raised by the service, never a second evidence row.
      this.send(res, result.replayed ? 200 : 201, {
        evidenceId: result.receipt.evidenceId,
        sessionId: result.receipt.sessionId,
        documentId: result.receipt.documentId,
        documentVersionId: result.receipt.documentVersionId,
        purpose: result.receipt.purpose,
        action: result.receipt.action,
        occurredAt: result.receipt.occurredAt,
        replayed: result.receipt.replayed,
      }, P05_F_JSON_RESPONSE_LIMIT_BYTES);
    } catch (error) {
      this.refuse(res, error);
    }
  }

  @Post('coverage/check')
  async checkCoverage(@Req() req: FormSessionRequest, @Res() res: ServerResponse): Promise<void> {
    this.requireExactRoute(req, 'checkCoverage');
    await this.ready(req);
    this.expectExactOrigin(req);
    this.expectJsonContentType(req);
    this.rejectAuthorization(req);
    try {
      this.validateCookies(req);
    } catch (error) {
      this.refuse(res, error);
    }
    this.rejectIdempotencyHeader(req);
    this.rejectQuery(req);
    try {
      const result: CoverageResult = await this.service.checkCoverage({
        cookieHeader: header(req, 'cookie'),
        body: req.body,
        source: this.sourceOf(req),
        selector: this.selectorHeader(req),
        csrf: this.csrfHeader(req),
      });
      this.send(res, 200, {
        cityId: result.cityId,
        cityVersionId: result.cityVersionId,
        districtId: result.districtId,
        outcome: result.outcome,
        hints: result.hints,
      }, P05_F_JSON_RESPONSE_LIMIT_BYTES);
    } catch (error) {
      this.refuse(res, error);
    }
  }
}
