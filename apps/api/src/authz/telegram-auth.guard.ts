import {
  BadRequestException, ForbiddenException, HttpException, Inject, Injectable,
  InternalServerErrorException, UnauthorizedException,
} from '@nestjs/common';
import type { CanActivate, ExecutionContext } from '@nestjs/common';
import type { IncomingMessage } from 'node:http';
import { Reflector } from '@nestjs/core';
import { TELEGRAM_AUTH_SERVICE } from '../auth/telegram-auth.controller.js';
import type { TelegramAuthServiceApi } from '../auth/telegram-auth.controller.js';
import { TelegramAuthError } from '../auth/telegram-auth.service.js';
import { AUTHORIZATION_SERVICE } from './authorization.resources.js';
import { AuthorizationError } from './authorization.service.js';
import type { AuthorizationServiceApi } from './authorization.service.js';
import { CAPABILITY_METADATA, GLOBAL_SCOPE } from './capability.js';
import type { Capability } from './capability.js';
import type { StaffTelegramPrincipal } from './principal.js';

/** The Principal union in principal.ts covers both staff channels; the authorization
 * service accepts it unchanged, so the guard needs only the narrow principal type.
 */

/** Bearer-style session extraction for staff Telegram routes: the Mini App keeps the
 * opaque token in memory and sends exactly one Authorization: Bearer header.
 * Duplicate or malformed Authorization headers fail with 400/401 before any DB access.
 */
export function bearerToken(req: IncomingMessage & { rawHeaders: string[] }): string {
  let value: string | undefined;
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i]?.toLowerCase() === 'authorization') {
      if (value !== undefined) { throw new BadRequestException(); }
      value = req.rawHeaders[i + 1];
    }
  }
  const token = value?.startsWith('Bearer ') ? value.slice('Bearer '.length) : undefined;
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) { throw new UnauthorizedException(); }
  return token;
}

/** Request shape the guard fills in; future staff-telegram routes read the principal here. */
export type TelegramAuthorizedRequest = IncomingMessage & {
  principal?: StaffTelegramPrincipal;
  sessionToken?: string;
};

/** Same safe mapping as the other auth boundaries: no raw service errors in logs. */
function mapAuthError(error: unknown): never {
  if (error instanceof TelegramAuthError) {
    switch (error.code) {
      case 'UNAUTHORIZED': case 'REPLAY': throw new UnauthorizedException();
      case 'RATE_LIMITED': throw new HttpException('Too Many Requests', 429);
      case 'INVALID_INPUT': throw new BadRequestException();
      default: throw new InternalServerErrorException();
    }
  }
  if (error instanceof AuthorizationError) {
    switch (error.code) {
      case 'UNAUTHORIZED': throw new UnauthorizedException();
      case 'FORBIDDEN': throw new ForbiddenException();
      default: throw new InternalServerErrorException();
    }
  }
  throw error;
}

/** Session recheck + default-deny capability gate for future staff Telegram (Mini App)
 * routes. P02-05 registers the guard as a provider to prove its wiring, but mounts no
 * route: master routes arrive in later phases. The channel of login adds no rights;
 * authorization is the same capability check as staff-web (DECISIONS §21).
 */
@Injectable()
export class StaffTelegramAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(TELEGRAM_AUTH_SERVICE) private readonly auth: TelegramAuthServiceApi,
    @Inject(AUTHORIZATION_SERVICE) private readonly authorization: AuthorizationServiceApi,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const capability = this.reflector.getAllAndOverride<Capability | undefined>(CAPABILITY_METADATA, [context.getHandler(), context.getClass()]);
    if (!capability) { throw new InternalServerErrorException(); }
    const request = context.switchToHttp().getRequest<TelegramAuthorizedRequest>();
    const token = bearerToken(request);
    try {
      const identity = await this.auth.authenticate(token);
      const principal: StaffTelegramPrincipal = {
        kind: 'staff-telegram', staffId: identity.staffId, role: identity.role,
        authVersion: identity.authVersion, telegramUserId: identity.telegramUserId,
      };
      await this.authorization.authorize(principal, capability, GLOBAL_SCOPE);
      request.principal = principal;
      request.sessionToken = token;
      return true;
    } catch (error) { return mapAuthError(error); }
  }
}
