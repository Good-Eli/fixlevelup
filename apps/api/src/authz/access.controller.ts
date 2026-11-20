import { Controller, Get, Header, Inject, Req } from '@nestjs/common';
import { envelope, expectExactOrigin, sessionToken } from '../auth/http.js';
import type { StaffRequest } from '../auth/http.js';
import { WEB_AUTH_HTTP_CONFIG } from '../auth/web-auth.controller.js';
import type { WebAuthHttpConfig } from '../auth/web-auth.controller.js';
import { AUTHORIZATION_SERVICE } from './authorization.resources.js';
import type { AuthorizationServiceApi } from './authorization.service.js';
import { authFailure } from './rbac-http.js';

/** Session-only projection of the caller's *own* UI capabilities. No arbitrary
 * staff id, no protected read callback and no assumption that roles.read is granted. */
@Controller('api/v1/access')
export class AccessController {
  constructor(@Inject(AUTHORIZATION_SERVICE) private readonly service: AuthorizationServiceApi,
    @Inject(WEB_AUTH_HTTP_CONFIG) private readonly config: WebAuthHttpConfig) {}
  @Get() @Header('Cache-Control', 'no-store')
  async current(@Req() req: StaffRequest) {
    expectExactOrigin(req, this.config.origin);
    try { return envelope(await this.service.inspectAccess({ kind: 'staff-web', token: sessionToken(req) })); }
    catch (error) { return authFailure(error); }
  }
}
