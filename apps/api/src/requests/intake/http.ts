import { randomUUID } from 'node:crypto';
import type { ServerResponse } from 'node:http';
import { All, Catch, Controller, HttpException, Inject, Req, Res } from '@nestjs/common';
import type { ArgumentsHost, ExceptionFilter } from '@nestjs/common';
import { matchP05Route, P05_BODY_BYTES, P05_PROBLEM_STATUS, parseP05Etag } from '@fixlevelup/p03-contracts/p05';
import type { P05Operation, P05ProblemCode } from '@fixlevelup/p03-contracts/p05';
import type { StaffRequest } from '../../auth/http.js';
import { expectExactOrigin, header, requireMutation, sessionToken } from '../../auth/http.js';
import type { WebAuthHttpConfig } from '../../auth/web-auth.controller.js';
import { AuthorizationError } from '../../authz/authorization.service.js';
import { F_MAX_COOKIE_BYTES, FormSessionError } from '../../form-session/contract.js';
import { formatHostCookie } from '../../form-session/cookies.js';
import { FormSessionAuthError } from '../../form-session/service.js';
import { boundedJsonForFormSession } from '../../form-session/body-parser.js';
import { closeAfterProblem, readBoundedJson } from '../../settings/management/body-parser.js';
import { parseRegistryQuery } from '../registry/filters.js';
import { deny, RequestFailure } from './errors.js';
import type { FProof, RequestIntake, StaffCommand, WriteInput, WriteResult } from './service.js';

interface Readiness {
  requestEffectsReady(): Promise<boolean>;
  requestIntakeReady(): Promise<boolean>;
  formSessionReady(): Promise<boolean>;
}
interface HttpDependencies {
  readonly service: RequestIntake;
  readonly readiness: Readiness;
  readonly origin: string;
  readonly staff: WebAuthHttpConfig;
}
export const REQUEST_INTAKE_HTTP = Symbol('REQUEST_INTAKE_HTTP');
const RAW_HEADERS = ['cookie','origin','authorization','content-type','content-encoding','content-length',
  'transfer-encoding','x-form-session-id','x-csrf-token','idempotency-key','if-match','if-none-match'];

function registryQueryString(method: string, target: string): string | null {
  if (method !== 'GET') { return null; }
  const separator = target.indexOf('?');
  const path = separator === -1 ? target : target.slice(0, separator);
  if (path !== '/api/v1/requests') { return null; }
  return separator === -1 ? '' : target.slice(separator + 1);
}

/** Install only in T. Unknown aliases don't get interpreted or forwarded as a
 * successful route; real P03/P04 and S2 paths keep their own parser. */
export function intakeBody(readiness: Readiness) {
  const form = boundedJsonForFormSession(readiness);
  return (req: StaffRequest,res: ServerResponse,next: (error?: HttpException) => void): void => {
    const method = req.method ?? '';
    const target = req.url ?? '';
    if (registryQueryString(method,target) === null && !isRegistryOptions(method,target) && !matchP05Route(method,target)) {
      form(req,res,next); return;
    }
    void readiness.requestEffectsReady().then((ready) => {
      if (!ready) { return deny('NOT_READY'); }
      if (!res.destroyed) { readBoundedJson(req,res,next,{ limit:P05_BODY_BYTES, decode:null, forbidBody:method === 'GET' }); }
    }).catch(() => {
      if (!res.destroyed) { closeAfterProblem(req,res); next(new RequestFailure('NOT_READY')); }
    });
  };
}

function isRegistryOptions(method: string, target: string): boolean {
  return method === 'GET' && target === '/api/v1/requests/filters';
}

function isStaffCommand(operation: P05Operation): operation is StaffCommand {
  return operation === 'startReview' || operation === 'convertCallback' || operation === 'changeDetails'
    || operation === 'recordCoverage' || operation === 'changeContact' || operation === 'readyForDispatch'
    || operation === 'withdrawPhoneStaff' || operation === 'cancelRequestStaff';
}

function sendRead(res: ServerResponse, result: { bytes: Buffer; etag: string }, match: string | undefined) {
  res.setHeader('Cache-Control','no-store, no-transform');
  res.setHeader('ETag',result.etag);
  res.setHeader('X-Request-Id',randomUUID());
  if (match === result.etag) { res.statusCode=304; res.end(); return; }
  res.statusCode=200;
  res.setHeader('Content-Type','application/json; charset=utf-8');
  res.end(result.bytes);
}

function sendWrite(res: ServerResponse, result: WriteResult, operation: P05Operation, staff: boolean, created = false) {
  const { receipt } = result;
  const closing = operation === 'cancelRequestF' || operation === 'cancelRequestStaff' || operation === 'withdrawPhoneStaff'
    || operation === 'withdrawPhonePermission';
  const data = closing ? { applied:receipt.applied,version:receipt.version } : staff
    ? { id:receipt.requestId,publicNumber:receipt.publicNumber,status:receipt.status,version:receipt.version }
    : { publicNumber:receipt.publicNumber,status:receipt.status,version:receipt.version };
  res.statusCode=created && !result.replayed ? 201 : 200;
  res.setHeader('Content-Type','application/json; charset=utf-8');
  res.setHeader('X-Request-Id',randomUUID());
  res.end(JSON.stringify({ data }));
}

function writeInput(req: StaffRequest): WriteInput {
  const conditional = header(req,'if-match');
  if (header(req,'if-none-match') !== undefined) { return deny('INVALID_REQUEST'); }
  return { key:header(req,'idempotency-key') ?? '', bytes:Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0),
    ...(conditional === undefined ? {} : { ifMatch:conditional }) };
}
function conditional(req: StaffRequest): string | undefined {
  if (header(req,'if-match') !== undefined || header(req,'idempotency-key') !== undefined || header(req,'x-csrf-token') !== undefined) {
    return deny('INVALID_REQUEST');
  }
  const none = header(req,'if-none-match');
  if (none !== undefined && parseP05Etag(none) === null) { return deny('INVALID_REQUEST'); }
  return none;
}

/** Explicit route family, exact raw method/path validated before business dispatch.
 * Nest's permissive matching does not decide authorization or semantics. */
@Controller('api/v1')
export class RequestIntakeController {
  constructor(@Inject(REQUEST_INTAKE_HTTP) private readonly deps: HttpDependencies) {}

  @All(['public/callback-requests','public/repair-requests','public/request-session','public/request-session/contact-mode',
    'public/request-session/phone-permissions','public/request-session/cancel','requests','requests/:id','requests/:id/commands/:command'])
  async handle(@Req() req: StaffRequest, @Res() res: ServerResponse): Promise<void> {
    res.setHeader('Cache-Control','no-store');
    const method = req.method ?? '';
    const target = req.url ?? '';
    const matched = matchP05Route(method,target);
    const registry = registryQueryString(method,target);
    const options = isRegistryOptions(method,target);
    if (matched === null && registry === null && !options) { return deny('NOT_FOUND'); }
    if (!await this.deps.readiness.requestEffectsReady()) { return deny('NOT_READY'); }
    for (const key of RAW_HEADERS) { header(req,key); }
    const cookies = header(req,'cookie');
    if (cookies && Buffer.byteLength(cookies,'utf8') > F_MAX_COOKIE_BYTES) { return deny('BODY_TOO_LARGE'); }
    if (header(req,'authorization') !== undefined) { throw new AuthorizationError('UNAUTHORIZED'); }
    const service = this.deps.service;
    if (registry !== null || options) {
      expectExactOrigin(req,this.deps.staff.origin);
      const token = sessionToken(req);
      if ((registry !== null && (registry.length > 2048 || registry.includes('#')))
        || ['x-form-session-id','x-csrf-token','idempotency-key','if-match','if-none-match'].some(key => header(req,key) !== undefined)) {
        return deny('INVALID_REQUEST');
      }
      const proof = { kind:'staff-web' as const,token };
      const data = registry === null ? await service.readStaffRegistryOptions(proof)
        : await service.readStaffRegistry(proof,parseRegistryQuery(new URLSearchParams(registry)));
      res.setHeader('Cache-Control','no-store, no-transform');
      res.setHeader('Content-Type','application/json; charset=utf-8');
      res.setHeader('X-Request-Id',randomUUID());
      res.statusCode=200;
      res.end(JSON.stringify({ data }));
      return;
    }
    if (matched === null) { return deny('NOT_FOUND'); }
    const op = matched.operation;
    if (op === 'readRequestSession' || op === 'createCallback' || op === 'createRepair' || op === 'chooseCallback'
      || op === 'withdrawPhonePermission' || op === 'cancelRequestF') {
      const origin = header(req,'origin');
      if (origin !== this.deps.origin && (op !== 'readRequestSession' || origin !== undefined)) { return deny('FORBIDDEN'); }
      const proof: FProof = { selector:header(req,'x-form-session-id'),csrf:header(req,'x-csrf-token'),cookieHeader:cookies,
        source:req.socket.remoteAddress ?? '' };
      if (op === 'readRequestSession') { sendRead(res,await service.readForm(proof),conditional(req)); }
      else if (op === 'createCallback' || op === 'createRepair') { sendWrite(res,await service.submitForm(op,proof,writeInput(req)),op,false,true); }
      else { sendWrite(res,await service.commandForm(op,proof,writeInput(req)),op,false); }
      return;
    }
    if (header(req,'x-form-session-id') !== undefined) { return deny('INVALID_REQUEST'); }
    const token = sessionToken(req);
    const staff = { kind:'staff-web' as const,token };
    if (op === 'readStaffRequest') {
      expectExactOrigin(req,this.deps.staff.origin);
      const result = await service.readStaff(staff,matched.params.id);
      sendRead(res,result,conditional(req));
      return;
    }
    requireMutation(req,token,this.deps.staff);
    if (op === 'createManualRequest') { sendWrite(res,await service.submitStaff(staff,writeInput(req)),op,true,true); return; }
    if (isStaffCommand(op) && 'id' in matched.params && typeof matched.params.id === 'string') {
      sendWrite(res,await service.commandStaff(op,staff,matched.params.id,writeInput(req)),op,true);
      return;
    }
    deny('NOT_FOUND');
  }
}

const CLOSED_CODES: Readonly<Record<number,P05ProblemCode>> = { 400:'MALFORMED',401:'UNAUTHORIZED',403:'FORBIDDEN',404:'NOT_FOUND',
  408:'REQUEST_TIMEOUT',409:'CONFLICT',412:'VERSION_MISMATCH',413:'BODY_TOO_LARGE',415:'UNSUPPORTED_MEDIA_TYPE',422:'SEMANTIC',
  428:'PRECONDITION_REQUIRED',429:'QUOTA',500:'INTERNAL_ERROR',503:'NOT_READY' };

/** In the new T routes never serialize a throwable, body, token or driver message. */
@Catch()
export class IntakeProblemFilter implements ExceptionFilter {
  catch(error: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<ServerResponse>();
    if (res.destroyed || res.headersSent) { return; }
    let status = error instanceof HttpException ? error.getStatus() : 500;
    if (error instanceof FormSessionError) {
      status = { MALFORMED:400,ORIGIN:403,CSRF:403,UNAUTHENTICATED:401,FORBIDDEN:403,NOT_FOUND:404,
        CONFLICT:409,PAYLOAD_TOO_LARGE:413,UNSUPPORTED_MEDIA:415,UNPROCESSABLE:422,QUOTA:429,UNAVAILABLE:503,PII_REJECTED:400 }[error.code];
    }
    if (error instanceof AuthorizationError) { status = error.code === 'UNAUTHORIZED' ? 401 : error.code === 'FORBIDDEN' ? 403 : 503; }
    if (error instanceof FormSessionAuthError && error.clearCookieName !== null) {
      res.setHeader('Set-Cookie',formatHostCookie(error.clearCookieName,'',0));
    }
    const mapped = CLOSED_CODES[status];
    if (mapped === undefined) { status = 500; }
    const code = error instanceof RequestFailure && Object.hasOwn(P05_PROBLEM_STATUS,error.code)
      ? error.code : mapped ?? 'INTERNAL_ERROR';
    res.statusCode=status;
    res.setHeader('Cache-Control','no-store');
    res.setHeader('Content-Type','application/problem+json');
    res.end(JSON.stringify({ type:'about:blank',title:code,status,code,requestId:randomUUID() }));
  }
}
