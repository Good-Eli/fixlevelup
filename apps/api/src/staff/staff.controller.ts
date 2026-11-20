import { randomUUID } from 'node:crypto';
import {
  BadRequestException, Controller, ForbiddenException, Get, Header, HttpCode, Inject, Injectable,
  InternalServerErrorException, NotFoundException, Param, Post, Req, Res, UnauthorizedException, UseGuards,
} from '@nestjs/common';
import type { PoolClient } from 'pg';
import type { ServerResponse } from 'node:http';
import { WEB_AUTH_HTTP_CONFIG } from '../auth/web-auth.controller.js';
import type { WebAuthHttpConfig } from '../auth/web-auth.controller.js';
import { bodyFields, envelope, etag, expectExactOrigin, requireMutation, sessionToken } from '../auth/http.js';
import type { StaffRequest } from '../auth/http.js';
import { AuthorizationError } from '../authz/authorization.service.js';
import type { AuthorizationServiceApi } from '../authz/authorization.service.js';
import { AUTHORIZATION_SERVICE } from '../authz/authorization.resources.js';
import { StaffWebAuthGuard } from '../authz/authorization.guard.js';
import type { AuthorizedRequest } from '../authz/authorization.guard.js';
import { RequireCapability } from '../authz/require-capability.decorator.js';
import { GLOBAL_SCOPE } from '../authz/capability.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
type StaffRoleValue = 'ADMIN' | 'MANAGER' | 'TECHNICIAN';
interface StaffListRow { id: string; role: StaffRoleValue; employment_state: 'ACTIVE' | 'INACTIVE' }
interface StaffRow { id: string; role: StaffRoleValue; employment_state: 'ACTIVE' | 'INACTIVE'; auth_version: number }
function toDto(row: StaffListRow): { id: string; role: StaffRoleValue; employmentState: 'ACTIVE' | 'INACTIVE' } {
  return { id: row.id, role: row.role, employmentState: row.employment_state };
}
/** Service authorization errors map to safe statuses; anything else propagates to the filter. */
function mapAuthorizationError(error: unknown): never {
  if (!(error instanceof AuthorizationError)) { throw error; }
  switch (error.code) {
    case 'UNAUTHORIZED': throw new UnauthorizedException();
    case 'FORBIDDEN': throw new ForbiddenException();
    default: throw new InternalServerErrorException();
  }
}

/** Staff data access on the authorization pool. Reads run lockless after the guard's
 * checks; the create write runs inside authorizeForWrite under the staff→session lock order.
 */
@Injectable()
export class StaffService {
  constructor(@Inject(AUTHORIZATION_SERVICE) private readonly authorization: AuthorizationServiceApi) {}

  async list(): Promise<StaffListRow[]> {
    return this.authorization.read(async (client: PoolClient) =>
      (await client.query<StaffListRow>('SELECT id, role, employment_state FROM foundation.staff ORDER BY id')).rows);
  }

  async get(id: string): Promise<StaffRow> {
    return this.authorization.read(async (client: PoolClient) => {
      const result = await client.query<StaffRow>('SELECT id, role, employment_state, auth_version FROM foundation.staff WHERE id = $1', [id]);
      const row = result.rows[0];
      if (!row) { throw new NotFoundException(); }
      return row;
    });
  }

  async create(token: string, actorStaffId: string, role: 'MANAGER' | 'TECHNICIAN'): Promise<StaffRow> {
    return this.authorization.authorizeForWrite(token, 'staff.manage', GLOBAL_SCOPE, async ({ client }) => {
      const result = await client.query<StaffRow>(
        `INSERT INTO foundation.staff (id, role, employment_state, auth_version) VALUES ($1, $2, 'ACTIVE', 0)
         RETURNING id, role, employment_state, auth_version`, [randomUUID(), role]);
      const row = result.rows[0];
      if (!row) { throw new AuthorizationError('FAILED'); }
      await client.query('INSERT INTO foundation.audit_logs (id, operation, correlation_id, details) VALUES ($1, $2, $3, $4::jsonb)',
        [randomUUID(), 'STAFF_CREATED', randomUUID(), JSON.stringify({ by: actorStaffId, created: row.id })]);
      return row;
    });
  }
}

/** Staff routes behind the shared capability guard; 401 without a session, 403 without
 * the capability, 404 for a missing staff id. POST /staff is a plain pre-registered
 * profile INSERT without Idempotency-Key (lead decision): no external side effects,
 * a repeat creates a second staff row.
 */
@Controller('api/v1/staff')
@UseGuards(StaffWebAuthGuard)
export class StaffController {
  constructor(
    private readonly staff: StaffService,
    @Inject(WEB_AUTH_HTTP_CONFIG) private readonly config: WebAuthHttpConfig,
  ) {}

  @Get() @RequireCapability('staff.read') @Header('Cache-Control', 'no-store')
  async list(@Req() req: AuthorizedRequest) {
    expectExactOrigin(req, this.config.origin);
    try {
      const items = (await this.staff.list()).map(toDto);
      return envelope({ items, pageInfo: { nextCursor: null, hasMore: false } });
    } catch (error) { return mapAuthorizationError(error); }
  }

  @Get(':id') @RequireCapability('staff.read') @Header('Cache-Control', 'no-store')
  async get(@Req() req: AuthorizedRequest, @Param('id') id: string) {
    expectExactOrigin(req, this.config.origin);
    if (!UUID.test(id)) { throw new BadRequestException(); }
    try {
      return envelope(toDto(await this.staff.get(id)));
    } catch (error) { return mapAuthorizationError(error); }
  }

  @Post() @HttpCode(201) @RequireCapability('staff.manage') @Header('Cache-Control', 'no-store')
  async create(@Req() req: StaffRequest & AuthorizedRequest, @Res({ passthrough: true }) res: ServerResponse) {
    const token = req.sessionToken ?? sessionToken(req);
    requireMutation(req, token, this.config);
    const fields = bodyFields(req.body, ['role']);
    const role = fields['role'];
    if (role !== 'MANAGER' && role !== 'TECHNICIAN') { throw new BadRequestException(); }
    const actor = req.principal;
    if (!actor) { throw new AuthorizationError('FAILED'); }
    try {
      const created = await this.staff.create(token, actor.staffId, role);
      res.setHeader('ETag', etag(created.auth_version));
      return envelope({ id: created.id, role: created.role, employmentState: created.employment_state });
    } catch (error) { return mapAuthorizationError(error); }
  }
}
