import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import {
  BadRequestException, Controller, Header, HttpCode, HttpException,
  Inject, InternalServerErrorException, Post, Req,
} from '@nestjs/common';
import { bodyFields } from './http.js';
import { TelegramAuthError } from './telegram-auth.service.js';
import type { TelegramSessionCredential, TelegramSessionIdentity } from './telegram-auth.service.js';

/** Bind these explicit tokens in the consuming module; this controller registers no providers.
 * The exchange deliberately has no Origin/CSRF requirement (owner decision): the session
 * token is returned only in the JSON body — never a cookie — so no ambient authority
 * is created and cross-site requests cannot authenticate anything. The token lives
 * in Mini App memory only (DECISIONS §21). TLS, the strict JSON parser, size limits
 * and rate limiting remain mandatory at the host.
 */
export const TELEGRAM_AUTH_SERVICE = Symbol('TELEGRAM_AUTH_SERVICE');

export interface TelegramAuthServiceApi {
  exchange(rawInitData: string, source: string): Promise<TelegramSessionCredential>;
  authenticate(token: string): Promise<TelegramSessionIdentity>;
}

type Request = IncomingMessage & { body?: unknown };

function field(fields: Record<string, string>, name: string): string {
  const value = fields[name];
  if (value === undefined) { throw new BadRequestException(); }
  return value;
}

function mapError(error: unknown): never {
  if (!(error instanceof TelegramAuthError)) { throw error; }
  switch (error.code) {
    case 'UNAUTHORIZED': case 'REPLAY': throw new BadRequestException();
    case 'RATE_LIMITED': throw new HttpException('Too Many Requests', 429);
    case 'INVALID_INPUT': throw new BadRequestException();
    default: throw new InternalServerErrorException();
  }
}

@Controller('api/v1/auth')
export class TelegramAuthController {
  constructor(@Inject(TELEGRAM_AUTH_SERVICE) private readonly service: TelegramAuthServiceApi) {}

  /** Raw initData → opaque staff session token in the JSON body (no cookie, no CSRF). */
  @Post('telegram-miniapp') @HttpCode(200) @Header('Cache-Control', 'no-store')
  async exchange(@Req() req: Request) {
    const fields = bodyFields(req.body, ['initData']);
    const source = req.socket.remoteAddress;
    if (!source) { throw new BadRequestException(); }
    try {
      const credential = await this.service.exchange(field(fields, 'initData'), source);
      // telegramUserId stays a decimal string end to end (BIGINT, never a JS number).
      return {
        data: {
          sessionToken: credential.token,
          staffId: credential.staffId,
          role: credential.role,
          authVersion: credential.authVersion,
          telegramUserId: credential.telegramUserId,
          idleExpiresAt: credential.idleExpiresAt,
          absoluteExpiresAt: credential.absoluteExpiresAt,
        },
        meta: { requestId: randomUUID() },
      };
    } catch (error) { return mapError(error); }
  }
}
