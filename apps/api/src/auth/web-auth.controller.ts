import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  BadRequestException, Controller, ForbiddenException, Get, Header, HttpCode,
  HttpException, Inject, InternalServerErrorException, Post, Req, Res,
  UnauthorizedException,
} from '@nestjs/common';
import { WebAuthError } from './web-auth.service.js';

/** Bind these explicit tokens in the consuming module; this controller does not register providers.
 * origin is the exact browser Origin (scheme, host and optional non-default port), with no path.
 * csrfSecret must be a separately generated, stable secret of at least 32 UTF-8 bytes.
 * Deploy over HTTPS on the cookie's host; the __Host- cookie is Secure, host-only and Path=/.
 * The host must enforce a size-limited, strict JSON parser and must not enable untrusted CORS.
 */
export const WEB_AUTH_SERVICE = Symbol('WEB_AUTH_SERVICE');
export const WEB_AUTH_HTTP_CONFIG = Symbol('WEB_AUTH_HTTP_CONFIG');
export interface WebAuthHttpConfig { origin: string; csrfSecret: string }
export interface WebAuthIdentity {
  staffId: string;
  role: 'ADMIN' | 'MANAGER';
  authVersion: number;
  idleExpiresAt: Date;
  absoluteExpiresAt: Date;
}
export interface WebAuthCredential extends WebAuthIdentity { token: string }
export interface WebAuthServiceApi {
  login(login: string, password: string, source: string): Promise<WebAuthCredential>;
  authenticate(token: string): Promise<WebAuthIdentity>;
  renew(token: string): Promise<WebAuthCredential>;
  logout(token: string): Promise<void>;
  changePassword(token: string, currentPassword: string, newPassword: string, source: string, expectedVersion: number): Promise<number>;
}

type Request = IncomingMessage & { body?: unknown };
const cookieName = '__Host-fixlevelup_session';
const csrfHeader = 'x-csrf-token';

/** Reject duplicate security-sensitive headers instead of relying on Node's header merging. */
function header(req: Request, name: string): string | undefined {
  let value: string | undefined;
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i]?.toLowerCase() === name) {
      if (value !== undefined) { throw new BadRequestException(); }
      value = req.rawHeaders[i + 1];
    }
  }
  return value;
}
function bodyFields(body: unknown, keys: readonly string[]): Record<string, string> {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) { throw new BadRequestException(); }
  const obj = body as Record<string, unknown>;
  const actual = Object.keys(obj);
  if (actual.length !== keys.length || keys.some((key) => !Object.hasOwn(obj, key) || typeof obj[key] !== 'string' || obj[key].length > 1024)) {
    throw new BadRequestException();
  }
  return obj as Record<string, string>;
}
function field(fields: Record<string, string>, name: string): string {
  const value = fields[name];
  if (value === undefined) { throw new BadRequestException(); }
  return value;
}
function sessionToken(req: Request): string {
  const cookies = header(req, 'cookie');
  let token: string | undefined;
  for (const part of cookies?.split(';') ?? []) {
    const index = part.indexOf('=');
    if (index < 0 || part.slice(0, index).trim() !== cookieName) { continue; }
    if (token !== undefined) { throw new UnauthorizedException(); }
    token = part.slice(index + 1).trim();
  }
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) { throw new UnauthorizedException(); }
  return token;
}
function etag(version: number): string {
  if (!Number.isSafeInteger(version) || version < 0) { throw new InternalServerErrorException(); }
  return `"auth-v${String(version)}"`;
}
function expectedVersion(req: Request): number {
  const supplied = header(req, 'if-match');
  if (supplied === undefined) { throw new HttpException('Precondition Required', 428); }
  const matched = /^"auth-v(0|[1-9][0-9]*)"$/.exec(supplied);
  if (!matched || !Number.isSafeInteger(Number(matched[1]))) { throw new BadRequestException(); }
  return Number(matched[1]);
}
function envelope<T>(data: T): { data: T; meta: { requestId: string } } {
  return { data, meta: { requestId: randomUUID() } };
}
function identityResult(identity: WebAuthIdentity, csrfToken: string) {
  return envelope({ staffId: identity.staffId, role: identity.role, authVersion: identity.authVersion, idleExpiresAt: identity.idleExpiresAt, absoluteExpiresAt: identity.absoluteExpiresAt, csrfToken });
}
function mapError(error: unknown): never {
  if (!(error instanceof WebAuthError)) { throw error; }
  switch (error.code) {
    case 'INVALID_CREDENTIALS': case 'UNAUTHORIZED': throw new UnauthorizedException();
    case 'RATE_LIMITED': throw new HttpException('Too Many Requests', 429);
    case 'STALE': throw new HttpException('Precondition Failed', 412);
    case 'INVALID_INPUT': throw new BadRequestException();
    default: throw new InternalServerErrorException();
  }
}

@Controller('api/v1/auth')
export class WebAuthController {
  private readonly origin: string;
  private readonly csrfSecret: string;
  constructor(
    @Inject(WEB_AUTH_SERVICE) private readonly service: WebAuthServiceApi,
    @Inject(WEB_AUTH_HTTP_CONFIG) config: WebAuthHttpConfig,
  ) {
    let parsed: URL;
    try { parsed = new URL(config.origin); } catch { throw new Error('Invalid web auth HTTP configuration'); }
    if (parsed.protocol !== 'https:' || parsed.origin !== config.origin || Buffer.byteLength(config.csrfSecret, 'utf8') < 32) {
      throw new Error('Invalid web auth HTTP configuration');
    }
    this.origin = config.origin;
    this.csrfSecret = config.csrfSecret;
  }
  private csrf(token: string): string {
    return createHmac('sha256', this.csrfSecret).update('web-auth-csrf\0').update(token).digest('base64url');
  }
  private mutation(req: Request, token?: string): void {
    if (header(req, 'origin') !== this.origin) { throw new ForbiddenException(); }
    if (!/^application\/json(?:\s*;\s*charset\s*=\s*utf-8)?$/i.test(header(req, 'content-type') ?? '')) { throw new BadRequestException(); }
    const supplied = header(req, csrfHeader);
    const expected = token === undefined ? 'login' : this.csrf(token);
    if (!supplied || !/^[A-Za-z0-9_-]+$/.test(supplied) || supplied.length !== expected.length || !timingSafeEqual(Buffer.from(supplied, 'utf8'), Buffer.from(expected, 'utf8'))) {
      throw new ForbiddenException();
    }
  }
  private setCookie(res: ServerResponse, token: string): void {
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) { throw new InternalServerErrorException(); }
    res.setHeader('Set-Cookie', `${cookieName}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict`);
  }

  @Post('login') @HttpCode(200) @Header('Cache-Control', 'no-store')
  async login(@Req() req: Request, @Res({ passthrough: true }) res: ServerResponse) {
    this.mutation(req);
    const fields = bodyFields(req.body, ['login', 'password']);
    const source = req.socket.remoteAddress;
    if (!source) { throw new BadRequestException(); }
    try {
      const credential = await this.service.login(field(fields, 'login'), field(fields, 'password'), source);
      res.setHeader('ETag', etag(credential.authVersion));
      this.setCookie(res, credential.token);
      return identityResult(credential, this.csrf(credential.token));
    } catch (error) { return mapError(error); }
  }

  @Get('me') @Header('Cache-Control', 'no-store')
  async me(@Req() req: Request, @Res({ passthrough: true }) res: ServerResponse) {
    const origin = header(req, 'origin');
    if ((origin !== undefined && origin !== this.origin) || header(req, 'x-auth-request') !== '1') { throw new ForbiddenException(); }
    const token = sessionToken(req);
    try {
      const identity = await this.service.authenticate(token);
      res.setHeader('ETag', etag(identity.authVersion));
      return identityResult(identity, this.csrf(token));
    } catch (error) { return mapError(error); }
  }

  @Post('session/renew') @HttpCode(200) @Header('Cache-Control', 'no-store')
  async renew(@Req() req: Request, @Res({ passthrough: true }) res: ServerResponse) {
    const token = sessionToken(req);
    this.mutation(req, token);
    bodyFields(req.body, []);
    try {
      const credential = await this.service.renew(token);
      res.setHeader('ETag', etag(credential.authVersion));
      this.setCookie(res, credential.token);
      return identityResult(credential, this.csrf(credential.token));
    } catch (error) { return mapError(error); }
  }

  @Post('logout') @HttpCode(204) @Header('Cache-Control', 'no-store')
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: ServerResponse) {
    const token = sessionToken(req);
    this.mutation(req, token);
    bodyFields(req.body, []);
    try {
      await this.service.logout(token);
      res.setHeader('Set-Cookie', `${cookieName}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
      return;
    } catch (error) { return mapError(error); }
  }

  @Post('password/change') @HttpCode(200) @Header('Cache-Control', 'no-store')
  async changePassword(@Req() req: Request, @Res({ passthrough: true }) res: ServerResponse) {
    const token = sessionToken(req);
    this.mutation(req, token);
    const fields = bodyFields(req.body, ['currentPassword', 'newPassword']);
    const source = req.socket.remoteAddress;
    if (!source) { throw new BadRequestException(); }
    const version = expectedVersion(req);
    try {
      const authVersion = await this.service.changePassword(token, field(fields, 'currentPassword'), field(fields, 'newPassword'), source, version);
      res.setHeader('ETag', etag(authVersion));
      return envelope({ ok: true, authVersion });
    } catch (error) { return mapError(error); }
  }
}
