import { BadRequestException, Controller, Get, Inject, InternalServerErrorException, NotFoundException, Post,
  Req, Res, ServiceUnavailableException } from '@nestjs/common';
import { decodeP04Data, matchP04Route, P04_PREFIX, P04_ROUTES } from '@fixlevelup/p03-contracts/p04';
import type { P04MutationOperation, P04Operation } from '@fixlevelup/p03-contracts/p04';
import type { ServerResponse } from 'node:http';
import { envelope, expectExactOrigin, requireMutation, sessionToken } from '../auth/http.js';
import type { StaffRequest } from '../auth/http.js';
import { WEB_AUTH_HTTP_CONFIG } from '../auth/web-auth.controller.js';
import type { WebAuthHttpConfig } from '../auth/web-auth.controller.js';
import { RuntimeDatabase } from '../infrastructure/database/runtime-database.js';
import { commandFor } from './commands.js';
import type { Receipt } from './commands.js';
import { CatalogManagementRunner } from './runner.js';

// Register only explicitly documented paths. The dispatch below checks the raw canonical
// path too, since Express may also invoke handlers for a case/trailing slash variant.
function paths(method: 'GET' | 'POST'): string[] {
  const operations = Object.keys(P04_ROUTES) as P04Operation[];
  return operations.map(op => P04_ROUTES[op]).filter(route => route.method === method)
    .map(route => route.path.slice(P04_PREFIX.length + 1).replace(/\{([a-zA-Z]+)\}/gu, ':$1'));
}
function parseRoute(req: StaffRequest, method: 'GET' | 'POST') {
  const raw = req.url ?? '';
  const separator = raw.indexOf('?');
  const route = matchP04Route(method, separator < 0 ? raw : raw.slice(0, separator));
  if (req.method !== method || !route) { throw new NotFoundException(); }
  return { route, query: separator < 0 ? '' : raw.slice(separator) };
}
function isMutation(op: P04Operation): op is P04MutationOperation {
  return P04_ROUTES[op].method === 'POST';
}
function render(res: ServerResponse, op: P04Operation, data: unknown, status: number, receipt?: Receipt): void {
  let payload: string;
  try { payload = JSON.stringify(envelope(decodeP04Data(op, data))); }
  catch { throw new InternalServerErrorException(); }
  const size = Buffer.byteLength(payload, 'utf8');
  if (size > P04_ROUTES[op].responseLimit) { throw new InternalServerErrorException(); }
  if (receipt) { res.setHeader('ETag', `"p04-v${String(receipt.version)}"`); }
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Length', size);
  res.end(payload);
}

@Controller(P04_PREFIX.slice(1))
export class CatalogManagementController {
  constructor(@Inject(CatalogManagementRunner) private readonly runner: CatalogManagementRunner,
    @Inject(WEB_AUTH_HTTP_CONFIG) private readonly config: WebAuthHttpConfig,
    @Inject(RuntimeDatabase) private readonly database: RuntimeDatabase) {}

  private async ready(): Promise<void> {
    if (!await this.database.catalogManagementReady()) { throw new ServiceUnavailableException(); }
  }

  @Get(paths('GET'))
  async read(@Req() req: StaffRequest, @Res() res: ServerResponse): Promise<void> {
    res.setHeader('Cache-Control', 'no-store');
    const { route, query } = parseRoute(req, 'GET');
    if (req.body !== undefined) { throw new BadRequestException(); }
    const token = sessionToken(req);
    expectExactOrigin(req, this.config.origin);
    await this.ready();
    render(res, route.operation, await this.runner.read({ kind: 'staff-web', token }, route.operation, route.params, query), 200);
  }

  @Post(paths('POST'))
  async write(@Req() req: StaffRequest, @Res() res: ServerResponse): Promise<void> {
    res.setHeader('Cache-Control', 'no-store');
    const { route, query } = parseRoute(req, 'POST');
    if (query !== '' || !isMutation(route.operation)) { throw new BadRequestException(); }
    const token = sessionToken(req);
    requireMutation(req, token, this.config);
    const command = commandFor(req, route.operation, route.params);
    await this.ready();
    const result = await this.runner.execute({ kind: 'staff-web', token }, command);
    render(res, route.operation, result.data, result.replayed ? 200 : P04_ROUTES[route.operation].status, result.data);
  }
}
