import { Controller, createParamDecorator, Get, HttpCode, Inject, InternalServerErrorException, Post, ServiceUnavailableException } from '@nestjs/common';
import type { ExecutionContext } from '@nestjs/common';
import { P03_API_PREFIX, P03_CITY_PICKER_DOMAINS, P03_COMMANDS, P03_CONTENT_KINDS, P03_LEGAL_KINDS, P03_LEGAL_PURPOSES,
  P03_REFERENCE_TYPES, P03_RESPONSE_BYTES, P03_ROUTES, formatP03Etag, isP03Version } from '@fixlevelup/p03-contracts';
import type { P03Operation, P03Target } from '@fixlevelup/p03-contracts';
import type { ServerResponse } from 'node:http';
import { envelope, expectExactOrigin, requireMutation, sessionToken } from '../../auth/http.js';
import type { StaffRequest } from '../../auth/http.js';
import { WEB_AUTH_HTTP_CONFIG } from '../../auth/web-auth.controller.js';
import type { WebAuthHttpConfig } from '../../auth/web-auth.controller.js';
import type { SessionProof } from '../../authz/authorization.service.js';
import { uuid } from '../../authz/rbac-http.js';
import { RuntimeDatabase } from '../../infrastructure/database/runtime-database.js';
import * as catalog from './catalog-reads.js';
import { COMPANY, Query, explicitTarget, invalid, oneOf, parseCommand, preconditions, referenceScope, referenceType } from './input.js';
import { ManagementRunner, managementFailure, resolveContentTarget } from './management-runner.js';
import { Keyset, paging } from './page.js';
import * as projections from './projections.js';

interface HttpContext { req: StaffRequest & { params: Record<string, string> }; res: ServerResponse }
const Http = createParamDecorator((_data: unknown, context: ExecutionContext): HttpContext => {
  const http = context.switchToHttp();
  return { req: http.getRequest<HttpContext['req']>(), res: http.getResponse<ServerResponse>() };
});
type ReadOperation = Exclude<
  keyof typeof P03_ROUTES,
  // Commands and geography use their dedicated handlers.
  P03Operation | 'technicianPicker' | 'geographyCoverage'
>;
const pickerCaps = { content: 'content.read', callback_interval: P03_REFERENCE_TYPES.callback_interval.read } as const;

function render(res: ServerResponse, data: unknown, cap: number, status = 200): void {
  // All DB clients have been released. Serialize once and send exactly the checked bytes, with no partial response.
  const serialized = JSON.stringify(envelope(data));
  const length = Buffer.byteLength(serialized, 'utf8');
  if (length > cap) { throw new InternalServerErrorException(); }
  if (data && typeof data === 'object') {
    const version = 'version' in data ? data.version : 'sequence' in data ? data.sequence : undefined;
    if (isP03Version(version, true)) { res.setHeader('ETag', formatP03Etag(version)); }
  }
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Length', length);
  res.end(serialized);
}

@Controller(P03_API_PREFIX)
export class ManagementController {
  constructor(@Inject(ManagementRunner) private readonly runner: ManagementRunner,
    @Inject(WEB_AUTH_HTTP_CONFIG) private readonly config: WebAuthHttpConfig,
    @Inject(RuntimeDatabase) private readonly database: RuntimeDatabase) {}

  private async ready(): Promise<void> {
    if (!await this.database.settingsManagementReady()) { throw new ServiceUnavailableException(); }
  }

  private async write(op: P03Operation, { req, res }: HttpContext): Promise<void> {
    res.setHeader('Cache-Control', 'no-store');
    const token = sessionToken(req);
    requireMutation(req, token, this.config);
    const guards = preconditions(op, req);
    const query = new Query(req.url);
    let command;
    try {
      command = parseCommand(op, req.params, query, op === 'bootstrapRevoke' && req.body === undefined ? {} : req.body);
      query.finish();
    } catch (error) { managementFailure(error); }
    await this.ready();
    const result = await this.runner.execute({ kind: 'staff-web', token }, command, guards);
    render(res, result.data, P03_RESPONSE_BYTES.detail, result.replayed ? 200 : P03_COMMANDS[op].status);
  }

  private async read(op: ReadOperation, { req, res }: HttpContext): Promise<void> {
    res.setHeader('Cache-Control', 'no-store');
    const token = sessionToken(req);
    expectExactOrigin(req, this.config.origin);
    const query = new Query(req.url);
    const proof = { kind: 'staff-web', token } as const;
    const { cap, run } = this.readPlan(op, proof, query, req.params);
    query.finish();
    await this.ready();
    render(res, await run(), cap);
  }

  private readPlan(op: ReadOperation, proof: SessionProof, query: Query, params: Record<string, string>): { cap: number; run: () => Promise<unknown> } {
    const { detail, list, legalExact, contentExact, companyExact, referenceExact } = P03_RESPONSE_BYTES;
    switch (op) {
      case 'companyList': {
        const page = new Keyset<number>(paging(query), [op], 'version');
        return { cap: list, run: () => this.runner.read(proof, ['settings.fullread'], COMPANY, ctx => catalog.companyHistory(ctx.client, page)) };
      }
      case 'companyExact': {
        const text = params['version'];
        const version = Number(text);
        if (!text || !/^[1-9][0-9]{0,9}$/.test(text) || !isP03Version(version)) { invalid(); }
        return { cap: companyExact, run: () => this.runner.read(proof, ['settings.fullread'], COMPANY, ctx => catalog.companyExact(ctx.client, version)) };
      }
      case 'readiness': {
        const page = new Keyset<string>(paging(query), [op], 'code');
        return { cap: list, run: () => this.runner.read(proof, ['settings.readiness.read'], COMPANY, ctx => projections.readiness(ctx, page)) };
      }
      case 'referenceList': case 'referenceGet': case 'referenceVersions': case 'referenceExact': {
        const ref = referenceType(params['type']);
        const target = referenceScope(ref, query);
        const caps = [ref.read];
        if (op === 'referenceList') {
          const archived = query.flag('includeArchived');
          const page = new Keyset<string>(paging(query), [op, ref.dbType, target, archived], 'code');
          return { cap: list, run: () => this.runner.read(proof, caps, target, async ctx => {
            await catalog.requireCity(ctx.client, ctx.target);
            return catalog.referenceList(ctx.client, ref, ctx.target, archived, page);
          }) };
        }
        const id = uuid(params['id']);
        const page = op === 'referenceVersions' ? new Keyset<number>(paging(query), [op, ref.dbType, target, id], 'version') : null;
        const revision = op === 'referenceExact' ? uuid(params['versionId']) : null;
        return { cap: page ? list : revision ? referenceExact : detail, run: () => this.runner.read(proof, caps, target, async ctx => {
          const parent = await catalog.referenceIdentity(ctx.client, ref, ctx.target, id);
          if (revision) { return catalog.referenceExact(ctx.client, parent, revision); }
          if (page) { return catalog.referenceHistory(ctx.client, parent, page); }
          return parent;
        }) };
      }
      case 'contentList': {
        const target = explicitTarget(query.take('scope'), query.take('cityId'));
        const kind = query.optional('kind', P03_CONTENT_KINDS);
        const archived = query.flag('includeArchived');
        const page = new Keyset<string>(paging(query), [op, target, kind, archived], 'code');
        return { cap: list, run: () => this.runner.read(proof, ['content.read'], target, async ctx => {
          await catalog.requireCity(ctx.client, ctx.target);
          return catalog.contentList(ctx.client, ctx.target, kind, archived, page);
        }) };
      }
      case 'contentGet': case 'contentRevisions': case 'contentExact': {
        const id = uuid(params['id']);
        const pagination = op === 'contentRevisions' ? paging(query) : null;
        const revision = op === 'contentExact' ? uuid(params['revisionId']) : null;
        return { cap: pagination ? list : revision ? contentExact : detail,
          run: () => this.runner.read(proof, ['content.read'], resolveContentTarget(id), async ctx => {
            const page = pagination ? new Keyset<number>(pagination, [op, ctx.target, id], 'version') : null;
            const parent = await catalog.contentIdentity(ctx.client, ctx.target, id);
            if (revision) { return catalog.contentExact(ctx.client, parent, revision); }
            if (page) { return catalog.contentHistory(ctx.client, parent, page); }
            return parent;
          }) };
      }
      case 'legalList': {
        const purpose = query.optional('purpose', P03_LEGAL_PURPOSES);
        const kind = query.optional('kind', P03_LEGAL_KINDS);
        const page = new Keyset<string>(paging(query), [op, purpose, kind], 'code');
        return { cap: list, run: () => this.runner.read(proof, ['legal.read'], COMPANY, ctx => catalog.legalList(ctx.client, purpose, kind, page)) };
      }
      case 'legalGet': case 'legalVersions': case 'legalExact': {
        const id = uuid(params['id']);
        const page = op === 'legalVersions' ? new Keyset<number>(paging(query), [op, id], 'version') : null;
        const revision = op === 'legalExact' ? uuid(params['versionId']) : null;
        return { cap: page ? list : revision ? legalExact : detail, run: () => this.runner.read(proof, ['legal.read'], COMPANY, async ctx => {
          const parent = await catalog.legalIdentity(ctx.client, id);
          if (revision) { return catalog.legalExact(ctx.client, parent, revision); }
          if (page) { return catalog.legalHistory(ctx.client, parent, page); }
          return parent;
        }) };
      }
      case 'bootstrapList': {
        const page = new Keyset<string>(paging(query), [op], 'code');
        return { cap: list, run: () => this.runner.read(proof, [], COMPANY, ctx => projections.bootstrapList(ctx, page)) };
      }
      case 'cityPicker': case 'cityVersionPicker': {
        const domain = oneOf(query.take('domain'), P03_CITY_PICKER_DOMAINS);
        if (op === 'cityPicker') {
          const page = new Keyset<string>(paging(query), [op, domain], 'code');
          return { cap: list, run: () => this.runner.discover(proof, domain, (ctx, ids) => projections.cityPicker(ctx.client, ids, page)) };
        }
        const cityId = uuid(params['cityId']);
        const target: P03Target = { scope: 'CITY', cityId };
        const page = new Keyset<number>(paging(query), [op, domain, cityId], 'version');
        return { cap: list, run: () => this.runner.read(proof, [pickerCaps[domain]], target, ctx => projections.cityVersionPicker(ctx.client, cityId, page)) };
      }
    }
  }

  @Get(P03_ROUTES.companyList) companyList(@Http() h: HttpContext) { return this.read('companyList', h); }
  @Get(P03_ROUTES.companyExact) companyExact(@Http() h: HttpContext) { return this.read('companyExact', h); }
  @Post(P03_ROUTES.companyPublish) companyPublish(@Http() h: HttpContext) { return this.write('companyPublish', h); }
  @Get(P03_ROUTES.readiness) readiness(@Http() h: HttpContext) { return this.read('readiness', h); }
  @Get(P03_ROUTES.referenceList) referenceList(@Http() h: HttpContext) { return this.read('referenceList', h); }
  @Post(P03_ROUTES.referenceCreate) referenceCreate(@Http() h: HttpContext) { return this.write('referenceCreate', h); }
  @Get(P03_ROUTES.referenceGet) referenceGet(@Http() h: HttpContext) { return this.read('referenceGet', h); }
  @Get(P03_ROUTES.referenceVersions) referenceVersions(@Http() h: HttpContext) { return this.read('referenceVersions', h); }
  @Post(P03_ROUTES.referencePublish) referencePublish(@Http() h: HttpContext) { return this.write('referencePublish', h); }
  @Get(P03_ROUTES.referenceExact) referenceExact(@Http() h: HttpContext) { return this.read('referenceExact', h); }
  @Post(P03_ROUTES.referenceArchive) @HttpCode(200) referenceArchive(@Http() h: HttpContext) { return this.write('referenceArchive', h); }
  @Get(P03_ROUTES.contentList) contentList(@Http() h: HttpContext) { return this.read('contentList', h); }
  @Post(P03_ROUTES.contentCreate) contentCreate(@Http() h: HttpContext) { return this.write('contentCreate', h); }
  @Get(P03_ROUTES.contentGet) contentGet(@Http() h: HttpContext) { return this.read('contentGet', h); }
  @Get(P03_ROUTES.contentRevisions) contentRevisions(@Http() h: HttpContext) { return this.read('contentRevisions', h); }
  @Get(P03_ROUTES.contentExact) contentExact(@Http() h: HttpContext) { return this.read('contentExact', h); }
  @Post(P03_ROUTES.contentPublish) contentPublish(@Http() h: HttpContext) { return this.write('contentPublish', h); }
  @Post(P03_ROUTES.contentArchive) @HttpCode(200) contentArchive(@Http() h: HttpContext) { return this.write('contentArchive', h); }
  @Get(P03_ROUTES.legalList) legalList(@Http() h: HttpContext) { return this.read('legalList', h); }
  @Post(P03_ROUTES.legalCreate) legalCreate(@Http() h: HttpContext) { return this.write('legalCreate', h); }
  @Get(P03_ROUTES.legalGet) legalGet(@Http() h: HttpContext) { return this.read('legalGet', h); }
  @Get(P03_ROUTES.legalVersions) legalVersions(@Http() h: HttpContext) { return this.read('legalVersions', h); }
  @Get(P03_ROUTES.legalExact) legalExact(@Http() h: HttpContext) { return this.read('legalExact', h); }
  @Post(P03_ROUTES.legalPublish) legalPublish(@Http() h: HttpContext) { return this.write('legalPublish', h); }
  @Get(P03_ROUTES.bootstrapList) bootstrapList(@Http() h: HttpContext) { return this.read('bootstrapList', h); }
  @Post(P03_ROUTES.bootstrapRevoke) @HttpCode(200) bootstrapRevoke(@Http() h: HttpContext) { return this.write('bootstrapRevoke', h); }
  @Get(P03_ROUTES.cityPicker) cityPicker(@Http() h: HttpContext) { return this.read('cityPicker', h); }
  @Get(P03_ROUTES.cityVersionPicker) cityVersionPicker(@Http() h: HttpContext) { return this.read('cityVersionPicker', h); }
}
