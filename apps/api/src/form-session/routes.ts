/**
 * P05-02 F surface: exact route table and bounded request-body decoder for the
 * seven public operations of docs/P05-PLAN.md §6.3.
 *
 * The matcher is a transport primitive, not a router: it answers only "is this
 * raw method + canonical pathname one of the P05-02 F endpoints, and which body
 * and response caps apply". It never percent-decodes, never normalises case,
 * never accepts a trailing slash, an alias, a duplicate slash or a query string
 * (the caller strips the query first), and every other shape returns `null`.
 * That exactness is what keeps a P05 spelling from being dispatched to a P03 or
 * P04 handler that happens to sit under the same prefix.
 *
 * The decoder reuses the duplicate-aware P04 JSON grammar
 * (`@fixlevelup/p03-contracts/p04-json`) instead of `JSON.parse`: decoded
 * duplicate members, lone surrogates, `-0`, non-integer/unsafe numbers and a
 * document over the grammar's own depth/node bounds are refused there before
 * any member is lost. This module only adds the tighter P05-02 caps (16 KiB
 * body before parse, depth 16, 256 nodes), the strict UTF-8 byte decode and the
 * plain-object root rule.
 *
 * Refusal classification (§6.3) is deliberately split here, not collapsed:
 *
 * - exceeding a *size/complexity* cap of the JSON contract (byte cap, depth cap,
 *   node cap) is `413 Payload Too Large`, because the body was never interpreted
 *   as JSON and no member of it can be blamed;
 * - a body that is syntactically or structurally invalid (bad UTF-8, duplicate
 *   members, non-object root, grammar refusal) is `400`, and a request that is
 *   over a rate-limit/quota budget stays `429` in the service — the three
 *   refusals never share a status.
 */
import { BadRequestException, HttpException } from '@nestjs/common';
import type { Buffer } from 'node:buffer';
import { TextDecoder } from 'node:util';
import { parseP04JsonText } from '@fixlevelup/p03-contracts/p04-json';
import type { P04Json } from '@fixlevelup/p03-contracts/p04-json';

/** The seven P05-02 F operations. Names are wire-stable and never re-spelled. */
export type P05FormSessionOperation =
  | 'browserBootstrap'
  | 'issueSession'
  | 'csrfBootstrap'
  | 'revokeSession'
  | 'readLegalDocument'
  | 'recordConsent'
  | 'checkCoverage';

/** Shared prefix of every P05-02 route; paths below are absolute and exact. */
export const P05_FORM_SESSION_PREFIX = '/api/v1/public' as const;

/** Byte cap of a P05-02 JSON body, enforced before any parse (§6.3). */
export const P05_F_BODY_LIMIT_BYTES = 16_384;

/** JSON nesting cap of a P05-02 body; the root object is depth 1. */
export const P05_F_JSON_MAX_DEPTH = 16;

/** JSON value cap of a P05-02 body; every scalar, array item and member value counts once. */
export const P05_F_JSON_MAX_NODES = 256;

/**
 * Response cap of the bounded legal-document text (1 MiB). The legal input
 * contract allows a document body of up to 200 000 characters; a correct
 * Russian UTF-8 document of that size plus JSON escaping and metadata needs up
 * to ~1 MiB, so the cap admits every legal publication whole. Should a response
 * still exceed it, the controller refuses predictably with 503 — a truncated
 * body would no longer match the document checksum.
 */
export const P05_F_RESPONSE_LIMIT_BYTES = 1_048_576;

/** Response cap of every other P05-02 F endpoint (16 KiB, matching its body cap). */
export const P05_F_JSON_RESPONSE_LIMIT_BYTES = 16_384;

/** Raw pathname cap before any matching work; mirrors the P04 matcher bound. */
const MAX_PATH_LENGTH = 256;

/**
 * §6.3: a request that exceeds a JSON-contract cap is `413 Payload Too Large`,
 * never the `400` of an uninterpretable body. Exported so the shared body reader
 * can preserve the exact status instead of flattening it to `400`.
 */
export function payloadTooLarge(): never {
  throw new HttpException('Payload Too Large', 413);
}

/** One matched P05-02 route: operation, caps and the captured path parameters. */
export interface P05FormSessionRoute {
  readonly operation: P05FormSessionOperation;
  readonly bodyLimit: number;
  readonly responseLimit: number;
  readonly params: Readonly<Record<string, string>>;
}

interface P05FormSessionLimits {
  readonly bodyLimit: number;
  readonly responseLimit: number;
}

const LIMITS: Readonly<Record<P05FormSessionOperation, P05FormSessionLimits>> = Object.freeze({
  browserBootstrap: Object.freeze({ bodyLimit: P05_F_BODY_LIMIT_BYTES, responseLimit: P05_F_JSON_RESPONSE_LIMIT_BYTES }),
  issueSession: Object.freeze({ bodyLimit: P05_F_BODY_LIMIT_BYTES, responseLimit: P05_F_JSON_RESPONSE_LIMIT_BYTES }),
  csrfBootstrap: Object.freeze({ bodyLimit: P05_F_BODY_LIMIT_BYTES, responseLimit: P05_F_JSON_RESPONSE_LIMIT_BYTES }),
  revokeSession: Object.freeze({ bodyLimit: P05_F_BODY_LIMIT_BYTES, responseLimit: P05_F_JSON_RESPONSE_LIMIT_BYTES }),
  readLegalDocument: Object.freeze({ bodyLimit: 0, responseLimit: P05_F_RESPONSE_LIMIT_BYTES }),
  recordConsent: Object.freeze({ bodyLimit: P05_F_BODY_LIMIT_BYTES, responseLimit: P05_F_JSON_RESPONSE_LIMIT_BYTES }),
  checkCoverage: Object.freeze({ bodyLimit: P05_F_BODY_LIMIT_BYTES, responseLimit: P05_F_JSON_RESPONSE_LIMIT_BYTES }),
});

/** Exact `POST` paths of the P05-02 F surface; no template, alias or trailing slash. */
const POST_ROUTES: Readonly<Record<string, P05FormSessionOperation>> = Object.freeze({
  [`${P05_FORM_SESSION_PREFIX}/form-session/browser`]: 'browserBootstrap',
  [`${P05_FORM_SESSION_PREFIX}/form-sessions`]: 'issueSession',
  [`${P05_FORM_SESSION_PREFIX}/form-session/csrf`]: 'csrfBootstrap',
  [`${P05_FORM_SESSION_PREFIX}/form-session/revoke`]: 'revokeSession',
  [`${P05_FORM_SESSION_PREFIX}/form-session/consents`]: 'recordConsent',
  [`${P05_FORM_SESSION_PREFIX}/coverage/check`]: 'checkCoverage',
});

/**
 * `GET /api/v1/public/legal-documents/{kind}`: exactly one non-empty segment of
 * canonical URL characters, no second slash, no trailing slash and no empty
 * segment. The character class is deliberately narrower than "anything but a
 * slash": it excludes `%` (a percent-encoded spelling is never decoded and never
 * matched), `?`/`#` (the caller strips the query, the matcher never guesses),
 * whitespace and control bytes. The captured text is the raw segment;
 * `legalKindParam` narrows it to the two public kinds, so an unknown spelling
 * cannot become an oracle for internal document kinds.
 */
const LEGAL_DOCUMENT_PATH = new RegExp(`^${P05_FORM_SESSION_PREFIX}/legal-documents/([A-Za-z0-9._~-]+)$`);

const EMPTY_PARAMS: Readonly<Record<string, string>> = Object.freeze({});

function route(
  operation: P05FormSessionOperation, params: Readonly<Record<string, string>>,
): P05FormSessionRoute {
  const limits = LIMITS[operation];
  return Object.freeze({ operation, bodyLimit: limits.bodyLimit, responseLimit: limits.responseLimit,
    params: Object.freeze(params) });
}

/**
 * Matches the raw request method and the already query-stripped pathname against
 * the exact P05-02 F surface. Inputs are never coerced: a lowercase/aliased
 * method, `%`-encoded spelling, trailing slash, extra segment, query string or
 * unknown path all yield `null`, so the caller falls back to its existing P03/P04
 * handling instead of borrowing a P05 cap.
 */
export function matchP05FormSessionRoute(method: string, path: string): P05FormSessionRoute | null {
  if (method !== 'POST' && method !== 'GET') { return null; }
  if (path.length > MAX_PATH_LENGTH) { return null; }
  if (!path.startsWith(`${P05_FORM_SESSION_PREFIX}/`)) { return null; }
  if (method === 'POST') {
    const operation = POST_ROUTES[path];
    return operation === undefined ? null : route(operation, EMPTY_PARAMS);
  }
  const legal = LEGAL_DOCUMENT_PATH.exec(path);
  if (legal === null) { return null; }
  // `$` also matches before a final newline; require the match to span the whole path.
  if (legal[0] !== path) { return null; }
  const kind = legal[1];
  if (kind === undefined || kind.length === 0) { return null; }
  return route('readLegalDocument', { kind });
}

/** Cut off structural nesting before the reused grammar's own depth guard.
 * This scan does not accept JSON; the full duplicate-aware grammar still does
 * that. Brackets in strings (including escaped quotes) never count. */
function requireP05ContainerDepth(text: string): void {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (inString) {
      if (char === '\\') { i += 1; }
      else if (char === '"') { inString = false; }
    } else if (char === '"') {
      inString = true;
    } else if (char === '[' || char === '{') {
      depth += 1;
      if (depth > P05_F_JSON_MAX_DEPTH) { payloadTooLarge(); }
    } else if (char === ']' || char === '}') {
      depth -= 1;
    }
  }
}

interface PendingJsonValue {
  readonly value: P04Json;
  readonly depth: number;
}

/**
 * Iterative depth/node walk over an already-parsed P04 tree. The grammar bounded
 * its own limits, but P05-02 is tighter; the walk is explicit (no recursion, no
 * `JSON.stringify`) so a hostile nesting cannot consume the call stack.
 */
function withinP05JsonBounds(root: P04Json): boolean {
  const pending: PendingJsonValue[] = [{ value: root, depth: 1 }];
  let nodes = 0;
  while (pending.length > 0) {
    const frame = pending.pop();
    if (frame === undefined) { return false; }
    nodes += 1;
    if (nodes > P05_F_JSON_MAX_NODES || frame.depth > P05_F_JSON_MAX_DEPTH) { return false; }
    const { value } = frame;
    if (Array.isArray(value)) {
      for (const item of value) { pending.push({ value: item, depth: frame.depth + 1 }); }
    } else if (value !== null && typeof value === 'object') {
      for (const key of Object.keys(value)) {
        const child = value[key];
        if (child === undefined) { return false; }
        pending.push({ value: child, depth: frame.depth + 1 });
      }
    }
  }
  return true;
}

/**
 * Strict P05-02 request-body decoder: byte cap, fatal UTF-8, duplicate-aware
 * grammar, tighter depth/node bounds and a plain-object root.
 *
 * Exceeding the byte, depth or node cap is `413 Payload Too Large` (the body is
 * over the JSON contract and was not interpreted); every other refusal is the
 * `400` of an invalid body. A rejected body never reaches a route, controller or
 * database and its bytes are not echoed back.
 */
export function parseStrictP05Json(buffer: Buffer): Record<string, unknown> {
  if (buffer.length > P05_F_BODY_LIMIT_BYTES) { payloadTooLarge(); }
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch {
    throw new BadRequestException();
  }
  requireP05ContainerDepth(text);
  let parsed: P04Json;
  try {
    parsed = parseP04JsonText(text);
  } catch {
    throw new BadRequestException();
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) { throw new BadRequestException(); }
  if (!withinP05JsonBounds(parsed)) { payloadTooLarge(); }
  return parsed;
}
