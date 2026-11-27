import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { BadRequestException, ForbiddenException, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import type { WebAuthHttpConfig } from './web-auth.controller.js';

/** Shared HTTP-boundary helpers for authenticated staff routes; extracted from the
 * P02-03 patterns in web-auth.controller.ts without changing that accepted controller.
 * The host must keep enforcing a size-limited strict JSON parser and no untrusted CORS.
 */
export type StaffRequest = IncomingMessage & { body?: unknown };

/** Reject duplicate security-sensitive headers instead of relying on Node's header merging. */
export function header(req: StaffRequest, name: string): string | undefined {
  let value: string | undefined;
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i]?.toLowerCase() === name) {
      if (value !== undefined) { throw new BadRequestException(); }
      value = req.rawHeaders[i + 1];
    }
  }
  return value;
}

export const SESSION_COOKIE_NAME = '__Host-fixlevelup_session';
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

/** Reads the single session cookie; duplicates or a malformed token fail with 401. */
export function sessionToken(req: StaffRequest): string {
  const cookies = header(req, 'cookie');
  let token: string | undefined;
  for (const part of cookies?.split(';') ?? []) {
    const index = part.indexOf('=');
    if (index < 0 || part.slice(0, index).trim() !== SESSION_COOKIE_NAME) { continue; }
    if (token !== undefined) { throw new UnauthorizedException(); }
    token = part.slice(index + 1).trim();
  }
  if (!token || !TOKEN.test(token)) { throw new UnauthorizedException(); }
  return token;
}

export function bodyFields(body: unknown, keys: readonly string[]): Record<string, string> {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) { throw new BadRequestException(); }
  const obj = body as Record<string, unknown>;
  const actual = Object.keys(obj);
  if (actual.length !== keys.length || keys.some((key) => !Object.hasOwn(obj, key) || typeof obj[key] !== 'string' || obj[key].length > 1024)) {
    throw new BadRequestException();
  }
  return obj as Record<string, string>;
}

export function etag(version: number): string {
  if (!Number.isSafeInteger(version) || version < 0) { throw new InternalServerErrorException(); }
  return `"staff-v${String(version)}"`;
}

export function envelope<T>(data: T): { data: T; meta: { requestId: string } } {
  return { data, meta: { requestId: randomUUID() } };
}

export function expectExactOrigin(req: StaffRequest, origin: string): void {
  const supplied = header(req, 'origin');
  if (supplied !== undefined && supplied !== origin) { throw new ForbiddenException(); }
}

/** Session-bound CSRF check for mutations, identical to the P02-03 token contract:
 * HMAC-SHA256 over the 'web-auth-csrf\0' domain and the session token, so the csrfToken
 * returned by /auth/login and /auth/me works for staff routes unchanged.
 */
export function staffSessionCsrf(token: string, csrfSecret: string): string {
  return createHmac('sha256', csrfSecret).update('web-auth-csrf\0').update(token).digest('base64url');
}

export function requireSessionCsrf(req: StaffRequest, token: string, csrfSecret: string): void {
  const expected = staffSessionCsrf(token, csrfSecret);
  const supplied = header(req, 'x-csrf-token');
  if (!supplied || !/^[A-Za-z0-9_-]+$/.test(supplied) || supplied.length !== expected.length
    || !timingSafeEqual(Buffer.from(supplied, 'utf8'), Buffer.from(expected, 'utf8'))) {
    throw new ForbiddenException();
  }
}

/** Full mutation barrier for staff writes: exact browser Origin, JSON UTF-8 body and
 * the session-bound CSRF token. Reads use expectExactOrigin only.
 */
export function requireMutation(req: StaffRequest, token: string, config: WebAuthHttpConfig): void {
  if (header(req, 'origin') !== config.origin) { throw new ForbiddenException(); }
  if (!/^application\/json(?:\s*;\s*charset\s*=\s*utf-8)?$/i.test(header(req, 'content-type') ?? '')) { throw new BadRequestException(); }
  requireSessionCsrf(req, token, config.csrfSecret);
}
