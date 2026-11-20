import {
  BadRequestException,
  ForbiddenException,
  HttpException,
  Inject,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import type { CanActivate, ExecutionContext } from '@nestjs/common';
import type { IncomingMessage } from 'node:http';
import { Reflector } from '@nestjs/core';
import { WEB_AUTH_SERVICE } from '../auth/web-auth.controller.js';
import type { WebAuthServiceApi } from '../auth/web-auth.controller.js';
import { WebAuthError } from '../auth/web-auth.service.js';
import { sessionToken } from '../auth/http.js';
import { AUTHORIZATION_SERVICE } from './authorization.resources.js';
import { AuthorizationError } from './authorization.service.js';
import type { AuthorizationServiceApi } from './authorization.service.js';
import { CAPABILITY_METADATA, GLOBAL_SCOPE } from './capability.js';
import type { Capability } from './capability.js';
import type { StaffWebPrincipal } from './principal.js';

/** Request shape the guard fills in; controllers read the principal from here. */
export type AuthorizedRequest = IncomingMessage & {
  principal?: StaffWebPrincipal;
  sessionToken?: string;
};

/** Same safe mapping as the P02-03 controller boundary: no raw service errors in logs. */
function mapAuthError(error: unknown): never {
  if (error instanceof WebAuthError) {
    switch (error.code) {
      case 'UNAUTHORIZED': throw new UnauthorizedException();
      case 'RATE_LIMITED': throw new HttpException('Too Many Requests', 429);
      case 'INVALID_INPUT': throw new BadRequestException();
      case 'STALE': throw new HttpException('Precondition Failed', 412);
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

/** Session recheck + default-deny capability gate for staff routes.
 * Mounted per-controller on the new /staff routes only; health and auth stay untouched.
 * 401 without a session, 403 without the capability; no metadata means a programming
 * error (the guard must not silently allow), so it fails loud with 500.
 */
@Injectable()
export class StaffWebAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    @Inject(WEB_AUTH_SERVICE) private readonly auth: WebAuthServiceApi,
    @Inject(AUTHORIZATION_SERVICE) private readonly authorization: AuthorizationServiceApi,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const capability = this.reflector.getAllAndOverride<Capability | undefined>(CAPABILITY_METADATA, [context.getHandler(), context.getClass()]);
    if (!capability) { throw new InternalServerErrorException(); }
    const request = context.switchToHttp().getRequest<AuthorizedRequest>();
    const token = sessionToken(request);
    let principal: StaffWebPrincipal;
    try {
      const identity = await this.auth.authenticate(token);
      principal = { kind: 'staff-web', staffId: identity.staffId, role: identity.role, authVersion: identity.authVersion };
    } catch (error) { return mapAuthError(error); }
    try {
      await this.authorization.authorize(principal, capability, GLOBAL_SCOPE);
    } catch (error) { return mapAuthError(error); }
    request.principal = principal;
    request.sessionToken = token;
    return true;
  }
}
