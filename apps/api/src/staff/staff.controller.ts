import { BadRequestException, Controller, Get, Header, HttpCode, Inject, Injectable, Param, Patch, Post, Put, Req, Res, UseGuards } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { WEB_AUTH_HTTP_CONFIG } from '../auth/web-auth.controller.js';
import type { WebAuthHttpConfig } from '../auth/web-auth.controller.js';
import { bodyFields, envelope, etag } from '../auth/http.js';
import { StaffWebAuthGuard } from '../authz/authorization.guard.js';
import { StaffTelegramAuthGuard } from '../authz/telegram-auth.guard.js';
import { RequireCapability } from '../authz/require-capability.decorator.js';
import { authFailure, expectedVersion, mutation, proof, readOrigin, uuid } from '../authz/rbac-http.js';
import type { RbacRequest } from '../authz/rbac-http.js';
import { displayName } from './staff-policy.js';
import { StaffService } from './staff.service.js';

export { StaffService } from './staff.service.js';
export function staffResult<T extends { version: number }>(res: ServerResponse, value: T) {
  res.setHeader('ETag', etag(value.version));
  return envelope(value);
}
export function profileBody(body: unknown): string { return displayName(bodyFields(body, ['displayName'])['displayName']); }
function createBody(body: unknown) {
  const withName = body !== null && typeof body === 'object' && Object.hasOwn(body, 'displayName');
  const fields = bodyFields(body, withName ? ['role', 'displayName'] : ['role']);
  const role = fields['role'];
  if (role !== 'MANAGER' && role !== 'TECHNICIAN') { throw new BadRequestException(); }
  return { role, displayName: withName ? displayName(fields['displayName']) : null } as const;
}

/** No client-controlled owner ID. proof() and service transaction both verify
 * the actual channel; an absent guard cannot result in a data read or mutation. */
function selfTarget(req: RbacRequest) {
  return { kind: 'self', id: uuid(req.principal?.staffId) } as const;
}

/** Thin transport adapter. Concrete controllers have disjoint paths and guards;
 * neither the channel nor inherited route metadata implies an RBAC permission. */
@Injectable()
abstract class StaffHttpAdapter {
  constructor(@Inject(StaffService) private readonly staff: StaffService, @Inject(WEB_AUTH_HTTP_CONFIG) private readonly config: WebAuthHttpConfig) {}

  @Get() @RequireCapability('staff.read') @Header('Cache-Control', 'no-store')
  async list(@Req() req: RbacRequest) {
    readOrigin(req, this.config);
    const items = await this.staff.list(proof(req)).catch(authFailure);
    return envelope({ items, pageInfo: { nextCursor: null, hasMore: false } });
  }
  // Nest registers handlers in declaration order: fixed /self paths precede /:id.
  @Get('self') @RequireCapability('staff.self.read') @Header('Cache-Control', 'no-store')
  async getSelf(@Req() req: RbacRequest, @Res({ passthrough: true }) res: ServerResponse) {
    readOrigin(req, this.config);
    return staffResult(res, await this.staff.get(proof(req), selfTarget(req)).catch(authFailure));
  }
  @Patch('self') @RequireCapability('staff.self.update') @Header('Cache-Control', 'no-store')
  async updateSelf(@Req() req: RbacRequest, @Res({ passthrough: true }) res: ServerResponse) {
    mutation(req, this.config);
    return staffResult(res, await this.staff.update(proof(req), selfTarget(req), expectedVersion(req, 'staff'), profileBody(req.body)).catch(authFailure));
  }
  @Post('self/deactivate') @HttpCode(200) @RequireCapability('staff.self.deactivate') @Header('Cache-Control', 'no-store')
  async deactivateSelf(@Req() req: RbacRequest, @Res({ passthrough: true }) res: ServerResponse) {
    mutation(req, this.config);
    bodyFields(req.body, []);
    return staffResult(res, await this.staff.deactivate(proof(req), selfTarget(req), expectedVersion(req, 'staff')).catch(authFailure));
  }
  @Get(':id') @RequireCapability('staff.read') @Header('Cache-Control', 'no-store')
  async get(@Req() req: RbacRequest, @Param('id') id: string, @Res({ passthrough: true }) res: ServerResponse) {
    readOrigin(req, this.config);
    return staffResult(res, await this.staff.get(proof(req), { kind: 'general', id: uuid(id) }).catch(authFailure));
  }
  @Post() @HttpCode(201) @RequireCapability('staff.create') @Header('Cache-Control', 'no-store')
  async create(@Req() req: RbacRequest, @Res({ passthrough: true }) res: ServerResponse) {
    mutation(req, this.config);
    const { role, displayName: name } = createBody(req.body);
    return staffResult(res, await this.staff.create(proof(req), role, name).catch(authFailure));
  }
  @Patch(':id') @RequireCapability('staff.update') @Header('Cache-Control', 'no-store')
  async update(@Req() req: RbacRequest, @Param('id') id: string, @Res({ passthrough: true }) res: ServerResponse) {
    mutation(req, this.config);
    return staffResult(res, await this.staff.update(proof(req), { kind: 'general', id: uuid(id) }, expectedVersion(req, 'staff'), profileBody(req.body)).catch(authFailure));
  }
  @Post(':id/deactivate') @HttpCode(200) @RequireCapability('staff.deactivate') @Header('Cache-Control', 'no-store')
  async deactivate(@Req() req: RbacRequest, @Param('id') id: string, @Res({ passthrough: true }) res: ServerResponse) {
    mutation(req, this.config);
    bodyFields(req.body, []);
    return staffResult(res, await this.staff.deactivate(proof(req), { kind: 'general', id: uuid(id) }, expectedVersion(req, 'staff')).catch(authFailure));
  }
  @Put(':id/role') @HttpCode(200) @RequireCapability('staff.role.assign') @Header('Cache-Control', 'no-store')
  async assign(@Req() req: RbacRequest, @Param('id') id: string, @Res({ passthrough: true }) res: ServerResponse) {
    mutation(req, this.config);
    const roleId = uuid(bodyFields(req.body, ['roleId'])['roleId']);
    return staffResult(res, await this.staff.assign(proof(req), uuid(id), expectedVersion(req, 'staff'), roleId).catch(authFailure));
  }
}

@Controller('api/v1/staff')
@UseGuards(StaffWebAuthGuard)
export class StaffController extends StaffHttpAdapter {}

@Controller('api/v1/telegram/staff')
@UseGuards(StaffTelegramAuthGuard)
export class TelegramStaffController extends StaffHttpAdapter {}
