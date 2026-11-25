/**
 * P05-02 cookie wire helpers: parsing of an incoming `Cookie` header and
 * formatting of a single `Set-Cookie` value.
 *
 * The module is pure transport data handling: it never reads a request object,
 * never sends a header and never touches a database. It also never percent-
 * decodes a value: the cookie value is opaque proof material, and decoding it
 * would create a second, ambiguous representation of the same secret.
 *
 * Shape rules are strict because a proof cookie is a credential: a duplicate
 * name, a non-canonical selector or a wrong secret length is refused rather than
 * repaired. Formatting is the only place a cookie string is produced; it emits
 * exactly the `__Host-` attributes (no `Domain`) so the browser cannot widen the
 * cookie to a parent domain.
 */
import {
  F_COOKIE_PREFIX,
  F_GROUP_COOKIE,
  F_MAX_COOKIE_BYTES,
  F_MAX_F_COOKIES,
  FormSessionError,
} from './contract.js';

/** Canonical lowercase UUID text of the form-session selector. */
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** 32 random bytes in unpadded base64url: exactly 43 characters. */
const BASE64URL_43 = /^[A-Za-z0-9_-]{43}$/;

/** RFC 6265 cookie-octet: no whitespace, `"`, `,`, `;`, `\`, controls or non-ASCII. */
const COOKIE_OCTETS = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/;

/** RFC 7230 header token, used only to keep a name from breaking the header. */
const COOKIE_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/** Hard protocol bound of `Max-Age`, independent of any policy TTL. */
const MAX_AGE_SECONDS = 86400 * 7;

function malformed(): never {
  throw new FormSessionError('MALFORMED');
}

/**
 * Parses a raw `Cookie` header into a name→value map. The raw header is bounded
 * in bytes before any split; a missing/empty header yields an empty map, a
 * duplicated name is `MALFORMED`. Values stay opaque: no percent-decoding, no
 * unquoting and no normalisation beyond trimming optional whitespace around the
 * pair, as the browser grammar allows it only there.
 */
export function parseCookieHeader(raw: string | undefined): ReadonlyMap<string, string> {
  const cookies = new Map<string, string>();
  if (raw === undefined) {
    return cookies;
  }
  if (Buffer.byteLength(raw, 'utf8') > F_MAX_COOKIE_BYTES) {
    throw new FormSessionError('PAYLOAD_TOO_LARGE');
  }
  for (const segment of raw.split(';')) {
    if (segment.trim().length === 0) {
      continue;
    }
    const separator = segment.indexOf('=');
    if (separator < 0) {
      malformed();
    }
    const name = segment.slice(0, separator).trim();
    const value = segment.slice(separator + 1).trim();
    if (name.length === 0 || cookies.has(name)) {
      malformed();
    }
    cookies.set(name, value);
  }
  return cookies;
}

/**
 * Group cookie value, or `undefined` when the cookie is absent. A present cookie
 * with any other shape is `MALFORMED`: the group id is a 32-byte opaque value and
 * a malformed one must not be treated as "no group".
 */
export function readGroupCookie(cookies: ReadonlyMap<string, string>): string | undefined {
  const value = cookies.get(F_GROUP_COOKIE);
  if (value === undefined) {
    return undefined;
  }
  if (!BASE64URL_43.test(value)) {
    malformed();
  }
  return value;
}

/** One parsed form-session proof cookie. */
export interface FormCookie {
  readonly selector: string;
  readonly secret: string;
}

/**
 * All proof cookies of the form prefix, in header order. More than the protocol
 * cap is `PAYLOAD_TOO_LARGE`: it is the *input* transport cap of one request
 * (§6.3 classifies caps as 413), not an exhausted server-side slot or rate
 * budget (which stay `QUOTA`/429 in the service). A non-canonical selector or a
 * non-32-byte secret is `MALFORMED`. Other cookies (including the group cookie)
 * are ignored.
 */
export function readFormCookies(cookies: ReadonlyMap<string, string>): FormCookie[] {
  const names: string[] = [];
  for (const name of cookies.keys()) {
    if (name.startsWith(F_COOKIE_PREFIX)) {
      names.push(name);
    }
  }
  if (names.length > F_MAX_F_COOKIES) {
    throw new FormSessionError('PAYLOAD_TOO_LARGE');
  }
  const result: FormCookie[] = [];
  for (const name of names) {
    const selector = name.slice(F_COOKIE_PREFIX.length);
    if (!CANONICAL_UUID.test(selector)) {
      malformed();
    }
    const secret = cookies.get(name);
    if (secret === undefined || !BASE64URL_43.test(secret)) {
      malformed();
    }
    result.push({ selector, secret });
  }
  return result;
}

/**
 * Selects the one proof cookie named by the `X-Form-Session-Id` header. The whole
 * prefix set is validated first (cap and every selector/secret pair), so a
 * malformed foreign cookie is refused even when the requested one is well-formed.
 * A missing header or a header naming no presented cookie is `UNAUTHENTICATED`;
 * a header that is not a canonical UUID is `MALFORMED`. A header is never an
 * identity by itself: it only picks one of the cookies the browser sent.
 */
export function selectFormCookie(
  cookies: ReadonlyMap<string, string>,
  selectorHeader: string | undefined,
): FormCookie {
  const formCookies = readFormCookies(cookies);
  if (selectorHeader === undefined) {
    throw new FormSessionError('UNAUTHENTICATED');
  }
  if (!CANONICAL_UUID.test(selectorHeader)) {
    malformed();
  }
  const selected = formCookies.find((cookie) => cookie.selector === selectorHeader);
  if (selected === undefined) {
    throw new FormSessionError('UNAUTHENTICATED');
  }
  return selected;
}

/**
 * Formats one `Set-Cookie` value for the group cookie or a form proof cookie.
 * The name must be the group cookie or carry the form prefix (and remain a valid
 * header token); `maxAgeSeconds` is an integer in `0..604800`, where `0` is the
 * addressed clearing form. `Path=/`, `Secure`, `HttpOnly` and `SameSite=Strict`
 * are always present and `Domain` is never emitted, as required by `__Host-`.
 */
export function formatHostCookie(name: string, value: string, maxAgeSeconds: number): string {
  if (!isFormCookieName(name)) {
    malformed();
  }
  if (!Number.isSafeInteger(maxAgeSeconds) || maxAgeSeconds < 0 || maxAgeSeconds > MAX_AGE_SECONDS) {
    malformed();
  }
  if (!COOKIE_OCTETS.test(value)) {
    malformed();
  }
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${String(maxAgeSeconds)}`;
}

/**
 * Addressed clearing form (`Max-Age=0`, empty value) for exactly one cookie.
 * Used for revocation or an exact expired presentation; it never replaces the
 * form and never clears the CRM or group cookies.
 */
export function formatClearHostCookie(name: string): string {
  return formatHostCookie(name, '', 0);
}

function isFormCookieName(name: string): boolean {
  if (name !== F_GROUP_COOKIE && !name.startsWith(F_COOKIE_PREFIX)) {
    return false;
  }
  return COOKIE_NAME.test(name);
}
