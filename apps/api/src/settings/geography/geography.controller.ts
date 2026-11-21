import { BadRequestException, Controller, createParamDecorator, Get, HttpCode, Inject, Patch, Post, Put } from '@nestjs/common';
import type { ExecutionContext } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { envelope, expectExactOrigin, header, requireMutation, sessionToken } from '../../auth/http.js';
import type { StaffRequest } from '../../auth/http.js';
import { WEB_AUTH_HTTP_CONFIG } from '../../auth/web-auth.controller.js';
import type { WebAuthHttpConfig } from '../../auth/web-auth.controller.js';
import { uuid } from '../../authz/rbac-http.js';
import { bearerToken } from '../../authz/telegram-auth.guard.js';
import type { GeoTarget } from './geo-contract.js';
import { GeoRunner, geoPreconditions } from './geo-runner.js';
import type { GeoOperation } from './geo-runner.js';

interface RequestContext { req: StaffRequest & {params: Record<string,string>}; res: ServerResponse }
const Http = createParamDecorator((_data: unknown, ctx: ExecutionContext): RequestContext => {
  const http = ctx.switchToHttp();
  return { req: http.getRequest<RequestContext['req']>(), res: http.getResponse<ServerResponse>() };
});
function routeTarget(params: Record<string,string>): GeoTarget {
  const target: GeoTarget = {};
  for (const k of ['cityId','staffId','areaId','districtId','versionId','grantId'] as const) {
    if (Object.hasOwn(params, k)) { target[k] = uuid(params[k]); }
  }
  if (params['permissionCode'] !== undefined) { target.permissionCode = params['permissionCode']; }
  return target;
}
const listOps: ReadonlySet<GeoOperation> = new Set(['cityList','cityVersions','districtList','areaList','areaVersions']);
function readOptions(op: GeoOperation, query: URLSearchParams): Record<string, number | boolean> | undefined {
  if (!query.size) { return undefined; }
  if (!listOps.has(op)) { throw new BadRequestException(); }
  const options: Record<string, number | boolean> = {};
  for (const [k,v] of query) {
    if (Object.hasOwn(options,k)) { throw new BadRequestException(); }
    if (k === 'limit' && /^[1-9][0-9]{0,2}$/.test(v)) { options[k] = Number(v); }
    else if (k === 'includeArchived' && (v === 'true' || v === 'false')) { options[k] = v === 'true'; }
    else { throw new BadRequestException(); }
  }
  return options;
}
const base = 'settings/service-cities';
const city = `${base}/:cityId`;
const districts = `${city}/administrative-districts`;
const areas = `${city}/service-areas`;
const versions = `${areas}/:areaId/versions`;
const admins = `${city}/administrators/:staffId/assignments`;
const tech = `${city}/technicians/:staffId`;
const techAlias = 'technicians/:staffId';
const areaAlias = 'catalog/service-areas';

@Controller('api/v1')
export class GeographyController {
  constructor(@Inject(GeoRunner) private readonly runner: GeoRunner,
    @Inject(WEB_AUTH_HTTP_CONFIG) private readonly config: WebAuthHttpConfig) {}

  private async handle(op: GeoOperation, {req,res}: RequestContext) {
    res.setHeader('Cache-Control','no-store');
    const token = sessionToken(req);
    const target = routeTarget(req.params);
    const write = req.method !== 'GET' && req.method !== 'HEAD';
    if (write) { requireMutation(req,token,this.config); } else { expectExactOrigin(req,this.config.origin); }
    if (op === 'techGrantZone') {
      const body = req.body;
      if (!body || typeof body !== 'object' || !('areaId' in body)) { throw new BadRequestException(); }
      target.areaId = uuid(body.areaId);
    }
    const guards = write ? geoPreconditions(op,header(req,'idempotency-key'),header(req,'if-match')) : undefined;
    const search = new URL(req.url ?? '/', 'http://localhost').searchParams;
    // The compatibility routes use an explicit query city; it is still independently checked by the policy service.
    if (!target.cityId && (op === 'areaList' || op === 'areaCreate' || op === 'areaArchive' || op === 'areaGet' || op === 'techCities' || op === 'techGrantCity' || op === 'techZones' || op === 'techGrantZone' || op === 'techRevokeCity' || op === 'techRevokeZone')) {
      const ids = search.getAll('cityId');
      if (ids.length !== 1) { throw new BadRequestException(); }
      target.cityId = uuid(ids[0]); search.delete('cityId');
    }
    if (write && search.size) { throw new BadRequestException(); }
    const input = write ? req.body : readOptions(op,search);
    const { data: result, replayed } = await this.runner.execute({kind:'staff-web',token},op,target,input,guards);
    if (replayed) { res.statusCode = 200; }
    if (result !== null && typeof result === 'object' && 'version' in result && typeof result.version === 'number') {
      res.setHeader('ETag',`"geo-v${String(result.version)}"`);
    }
    return envelope(result);
  }

  @Get(base) cities(@Http() h: RequestContext) { return this.handle('cityList',h); }
  @Post(base) createCity(@Http() h: RequestContext) { return this.handle('cityCreate',h); }
  @Get(city) city(@Http() h: RequestContext) { return this.handle('cityGet',h); }
  @Get(`${city}/versions`) cityVersions(@Http() h: RequestContext) { return this.handle('cityVersions',h); }
  @Post(`${city}/versions`) addCityVersion(@Http() h: RequestContext) { return this.handle('cityAddVersion',h); }
  @Post(`${city}/versions/:versionId/publish`) @HttpCode(200) publishCity(@Http() h: RequestContext) { return this.handle('cityPublish',h); }
  @Post(`${city}/activate`) @HttpCode(200) activate(@Http() h: RequestContext) { return this.handle('cityActivate',h); }
  @Post(`${city}/deactivate`) @HttpCode(200) deactivate(@Http() h: RequestContext) { return this.handle('cityDeactivate',h); }
  @Post(`${city}/primary`) @HttpCode(200) primary(@Http() h: RequestContext) { return this.handle('citySetPrimary',h); }

  @Get(`${districts}/:districtId`) districtDetail(@Http() h: RequestContext) { return this.handle('districtGet',h); }
  @Get(`${areas}/:areaId`) areaDetail(@Http() h: RequestContext) { return this.handle('areaGet',h); }
  @Get(`${versions}/:versionId`) draftDetail(@Http() h: RequestContext) { return this.handle('areaVersionGet',h); }
  @Get(districts) districts(@Http() h: RequestContext) { return this.handle('districtList',h); }
  @Post(districts) createDistrict(@Http() h: RequestContext) { return this.handle('districtCreate',h); }
  @Patch(`${districts}/:districtId`) editDistrict(@Http() h: RequestContext) { return this.handle('districtUpdate',h); }
  @Post(`${districts}/:districtId/archive`) @HttpCode(200) archiveDistrict(@Http() h: RequestContext) { return this.handle('districtArchive',h); }
  @Get(areas) areas(@Http() h: RequestContext) { return this.handle('areaList',h); }
  @Post(areas) createArea(@Http() h: RequestContext) { return this.handle('areaCreate',h); }
  @Post(`${areas}/:areaId/archive`) @HttpCode(200) archiveArea(@Http() h: RequestContext) { return this.handle('areaArchive',h); }
  @Get(versions) versions(@Http() h: RequestContext) { return this.handle('areaVersions',h); }
  @Post(versions) addDraft(@Http() h: RequestContext) { return this.handle('areaAddVersion',h); }
  @Patch(`${versions}/:versionId`) editDraft(@Http() h: RequestContext) { return this.handle('areaEditDraft',h); }
  @Post(`${versions}/:versionId/publish`) @HttpCode(200) publishArea(@Http() h: RequestContext) { return this.handle('areaPublish',h); }
  @Get(`${versions}/:versionId/district-coverage`) coverage(@Http() h: RequestContext) { return this.handle('areaCoverageGet',h); }
  @Put(`${versions}/:versionId/district-coverage`) replaceCoverage(@Http() h: RequestContext) { return this.handle('areaCoverage',h); }

  @Post('settings/geography/bootstrap/:staffId/:permissionCode/revoke') @HttpCode(200)
  revokeBootstrap(@Http() h: RequestContext) { return this.handle('revokeBootstrap',h); }

  @Get(admins) admins(@Http() h: RequestContext) { return this.handle('adminList',h); }
  @Post(admins) assignAdmin(@Http() h: RequestContext) { return this.handle('adminAssign',h); }
  @Post(`${admins}/:grantId/revoke`) @HttpCode(200) revokeAdmin(@Http() h: RequestContext) { return this.handle('adminRevoke',h); }
  @Get(`${tech}/city-memberships`) techCities(@Http() h: RequestContext) { return this.handle('techCities',h); }
  @Post(`${tech}/city-memberships`) admitCity(@Http() h: RequestContext) { return this.handle('techGrantCity',h); }
  @Post(`${tech}/city-memberships/:grantId/revoke`) @HttpCode(200) revokeCity(@Http() h: RequestContext) { return this.handle('techRevokeCity',h); }
  @Get(`${tech}/service-area-grants`) techZones(@Http() h: RequestContext) { return this.handle('techZones',h); }
  @Post(`${tech}/service-area-grants`) admitZone(@Http() h: RequestContext) { return this.handle('techGrantZone',h); }
  @Post(`${tech}/service-area-grants/:grantId/revoke`) @HttpCode(200) revokeZone(@Http() h: RequestContext) { return this.handle('techRevokeZone',h); }

  // The catalog and technician aliases require ?cityId= and use the same command/receipt as the nested route.
  @Get(areaAlias) catalogAreas(@Http() h: RequestContext) { return this.handle('areaList',h); }
  @Post(areaAlias) catalogCreate(@Http() h: RequestContext) { return this.handle('areaCreate',h); }
  @Get(`${areaAlias}/:areaId`) catalogDetail(@Http() h: RequestContext) { return this.handle('areaGet',h); }
  @Post(`${areaAlias}/:areaId/archive`) @HttpCode(200) catalogArchive(@Http() h: RequestContext) { return this.handle('areaArchive',h); }
  @Get(`${techAlias}/city-memberships`) techAliasCities(@Http() h: RequestContext) { return this.handle('techCities',h); }
  @Post(`${techAlias}/city-memberships`) techAliasAdmit(@Http() h: RequestContext) { return this.handle('techGrantCity',h); }
  @Get(`${techAlias}/service-area-grants`) techAliasZones(@Http() h: RequestContext) { return this.handle('techZones',h); }
  @Post(`${techAlias}/service-area-grants`) techAliasZone(@Http() h: RequestContext) { return this.handle('techGrantZone',h); }
}

@Controller('api/v1/telegram/technicians/self')
export class TechnicianTerritoryController {
  constructor(@Inject(GeoRunner) private readonly runner: GeoRunner) {}
  @Get('territory') async territory(@Http() {req,res}: RequestContext) {
    res.setHeader('Cache-Control','no-store');
    const { data } = await this.runner.execute({kind:'staff-telegram',token:bearerToken(req)},'techSelf',{});
    return envelope(data);
  }
}
