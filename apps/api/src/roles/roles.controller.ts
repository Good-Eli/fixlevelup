import { Controller, Get, Header, HttpCode, Inject, Param, Patch, Post, Put, Req, Res, UseGuards } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { envelope } from '../auth/http.js';
import { WEB_AUTH_HTTP_CONFIG } from '../auth/web-auth.controller.js';
import type { WebAuthHttpConfig } from '../auth/web-auth.controller.js';
import { StaffWebAuthGuard } from '../authz/authorization.guard.js';
import { StaffTelegramAuthGuard } from '../authz/telegram-auth.guard.js';
import { authFailure, expectedVersion, mutation, proof, readOrigin, uuid } from '../authz/rbac-http.js';
import type { RbacRequest } from '../authz/rbac-http.js';
import { RequireCapability } from '../authz/require-capability.decorator.js';
import { createMetadata, emptyBody, metadataPatch, replacement } from './role-policy.js';
import { RolesService } from './roles.service.js';
import type { RoleResult } from './roles.service.js';

const page = <T>(items: T[]) => ({ items, pageInfo: { nextCursor: null, hasMore: false } });
async function sendRole<T extends RoleResult>(operation: Promise<T>, res: ServerResponse) {
  const role = await operation.catch(authFailure);
  res.setHeader('ETag', `"role-v${String(role.version)}"`);
  return envelope(role);
}

abstract class RoleReads {
  constructor(@Inject(RolesService) protected readonly service: RolesService,
    @Inject(WEB_AUTH_HTTP_CONFIG) protected readonly config: WebAuthHttpConfig) {}

  @Get() @RequireCapability('roles.read') @Header('Cache-Control', 'no-store')
  async list(@Req() req: RbacRequest) {
    readOrigin(req, this.config);
    return envelope(page(await this.service.list(proof(req)).catch(authFailure)));
  }
  @Get(':id') @RequireCapability('roles.read') @Header('Cache-Control', 'no-store')
  get(@Req() req: RbacRequest, @Param('id') id: string, @Res({ passthrough: true }) res: ServerResponse) {
    readOrigin(req, this.config);
    return sendRole(this.service.get(proof(req), uuid(id)), res);
  }
  @Get(':id/staff') @RequireCapability('roles.read') @Header('Cache-Control', 'no-store')
  async members(@Req() req: RbacRequest, @Param('id') id: string) {
    readOrigin(req, this.config);
    return envelope(page(await this.service.members(proof(req), uuid(id)).catch(authFailure)));
  }
}

@Controller('api/v1/telegram/roles')
@UseGuards(StaffTelegramAuthGuard)
export class TelegramRolesController extends RoleReads {}

@Controller('api/v1/roles')
@UseGuards(StaffWebAuthGuard)
export class RolesController extends RoleReads {
  @Post() @HttpCode(201) @RequireCapability('roles.create') @Header('Cache-Control', 'no-store')
  create(@Req() req: RbacRequest, @Res({ passthrough: true }) res: ServerResponse) {
    mutation(req, this.config);
    return sendRole(this.service.create(proof(req), createMetadata(req.body)), res);
  }
  @Patch(':id') @RequireCapability('roles.update') @Header('Cache-Control', 'no-store')
  patch(@Req() req: RbacRequest, @Param('id') id: string, @Res({ passthrough: true }) res: ServerResponse) {
    mutation(req, this.config);
    return sendRole(this.service.patch(proof(req), uuid(id), expectedVersion(req, 'role'), metadataPatch(req.body)), res);
  }
  @Post(':id/archive') @HttpCode(200) @RequireCapability('roles.archive') @Header('Cache-Control', 'no-store')
  archive(@Req() req: RbacRequest, @Param('id') id: string, @Res({ passthrough: true }) res: ServerResponse) {
    mutation(req, this.config);
    emptyBody(req.body);
    return sendRole(this.service.archive(proof(req), uuid(id), expectedVersion(req, 'role')), res);
  }
  @Put(':id/permissions') @RequireCapability('roles.permissions.manage') @Header('Cache-Control', 'no-store')
  replace(@Req() req: RbacRequest, @Param('id') id: string, @Res({ passthrough: true }) res: ServerResponse) {
    mutation(req, this.config);
    return sendRole(this.service.replacePermissions(proof(req), uuid(id), expectedVersion(req, 'role'), replacement(req.body)), res);
  }
}

abstract class PermissionReads {
  constructor(@Inject(RolesService) private readonly service: RolesService,
    @Inject(WEB_AUTH_HTTP_CONFIG) private readonly config: WebAuthHttpConfig) {}
  @Get() @RequireCapability('roles.read') @Header('Cache-Control', 'no-store')
  async list(@Req() req: RbacRequest) {
    readOrigin(req, this.config);
    return envelope({ ...page(await this.service.permissions(proof(req)).catch(authFailure)), unsupportedScopes: ['CITY'] });
  }
}

@Controller('api/v1/permissions')
@UseGuards(StaffWebAuthGuard)
export class PermissionsController extends PermissionReads {}

@Controller('api/v1/telegram/permissions')
@UseGuards(StaffTelegramAuthGuard)
export class TelegramPermissionsController extends PermissionReads {}
