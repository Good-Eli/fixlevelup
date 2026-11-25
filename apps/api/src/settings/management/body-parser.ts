import { BadRequestException, HttpException, ServiceUnavailableException } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { TextDecoder } from 'node:util';
import { P03_BODY_DEADLINE_MS, p03BodyLimit } from '@fixlevelup/p03-contracts';
import { matchP04Route, P04_ROUTES } from '@fixlevelup/p03-contracts/p04';
import {
  matchP05FormSessionRoute,
  P05_F_BODY_LIMIT_BYTES,
  parseStrictP05Json,
} from '../../form-session/routes.js';
import { parseStrictPricingJson } from '../../pricing/codec/index.js';
import { header } from '../../auth/http.js';
import type { StaffRequest } from '../../auth/http.js';

function closeAfterProblem(req: StaffRequest, res: ServerResponse): void {
  req.pause();
  res.setHeader('Connection', 'close');
  // The problem must win the race against socket shutdown. end() after response finish
  // flushes queued bytes and prevents an unfinished/slow body from keeping HTTP alive.
  const socket = req.socket;
  res.once('finish', () => { socket.end(); });
}

export interface FormSessionBodyReadiness {
  requestIntakeReady(): Promise<boolean>;
  formSessionReady(): Promise<boolean>;
}

/** Optional pre-body readiness wrapper for the isolated P05 composition. */
export function boundedJsonForFormSession(
  readiness: FormSessionBodyReadiness,
): (req: StaffRequest, res: ServerResponse, next: (error?: HttpException) => void) => void {
  return (req, res, next) => {
    const route = matchP05FormSessionRoute(req.method ?? '', req.url ?? '');
    if (route === null) { boundedJson(req, res, next); return; }
    void Promise.resolve().then(async () => {
      const ok = await readiness.requestIntakeReady() && await readiness.formSessionReady();
      if (!ok) { throw new ServiceUnavailableException(); }
    }).then(() => {
      if (!res.destroyed) { boundedJson(req, res, next); }
    }, () => {
      if (res.destroyed) { return; }
      closeAfterProblem(req, res);
      next(new ServiceUnavailableException());
    });
  };
}

/** Runs before any route/controller/authorization; Express's automatic parser is off.
 * Never coerce a pathname, decompress input or trust Content-Length as a byte count. */
export function boundedJson(req: StaffRequest, res: ServerResponse, next: (error?: HttpException) => void): void {
  let type: string | undefined;
  try {
    const encoding = header(req, 'content-encoding');
    if (encoding !== undefined && encoding.toLowerCase() !== 'identity') {
      closeAfterProblem(req, res);
      next(new HttpException('Unsupported Media Type', 415));
      return;
    }
    type = header(req, 'content-type');
  } catch {
    closeAfterProblem(req, res);
    next(new BadRequestException());
    return;
  }
  const hasBody = req.headers['transfer-encoding'] !== undefined ||
    (req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0');
  if (!hasBody) { next(); return; }
  if (!/^application\/json(?:\s*;\s*charset\s*=\s*utf-8)?$/i.test(type ?? '')) {
    // End invalid uploads without letting a client stall the connection or reach DB work.
    closeAfterProblem(req, res);
    next(type && /^application\/json\s*;/i.test(type) ? new HttpException('Unsupported Media Type', 415) : new BadRequestException());
    return;
  }

  const method = req.method ?? '';
  const path = (req.url ?? '').split('?', 1)[0] ?? '';
  // P05 public namespace: a non-canonical spelling (wrong case, trailing
  // slash, HEAD, unknown subpath) must never borrow the P03 fallback parser.
  // It is either bodyless/refused outright (GET/HEAD with a body) or parsed
  // with the strict P05 grammar under the P05 cap, so the later exact-route
  // controller check answers 404/400 without any fallback interpretation.
  const p05namespace = /^\/api\/v1\/public(?:\/|$)/i.test(path);
  if (p05namespace && (method === 'GET' || method === 'HEAD')) {
    closeAfterProblem(req, res);
    next(new BadRequestException());
    return;
  }
  const p04 = method === 'POST' ? matchP04Route(method, path) : null;
  const p05 = method === 'POST' ? matchP05FormSessionRoute(method, path) : null;
  const p05Strict = p05namespace && !p05;
  const limit = p04 ? P04_ROUTES[p04.operation].bodyLimit
    : p05 ? p05.bodyLimit
      : p05Strict ? P05_F_BODY_LIMIT_BYTES
        : p03BodyLimit(method, path);
  const chunks: Buffer[] = [];
  let bytes = 0;
  let done = false;
  const cleanup = () => {
    clearTimeout(deadline);
    req.off('data', onData);
    req.off('end', onEnd);
    req.off('error', onError);
    req.off('close', onClose);
    chunks.length = 0;
  };
  const finish = (error?: HttpException, close = false) => {
    if (done) { return; }
    done = true;
    cleanup();
    if (res.destroyed) { return; }
    if (close) { closeAfterProblem(req, res); }
    next(error);
  };
  function onData(chunk: Buffer): void {
    bytes += chunk.length;
    if (bytes > limit) { finish(new HttpException('Payload Too Large', 413), true); return; }
    chunks.push(chunk);
  }
  function onEnd(): void {
    try {
      const buffer = Buffer.concat(chunks, bytes);
      const value: unknown = p04 ? parseStrictPricingJson(buffer)
        : p05 || p05Strict ? parseStrictP05Json(buffer)
        : JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer));
      if (value === null || typeof value !== 'object') { throw new BadRequestException(); }
      req.body = value;
    } catch (error) {
      // §6.3: an over-cap P05 body is 413 Payload Too Large, not the 400 of an
      // invalid body. The decoder already classified it; do not flatten it here.
      if ((p05 || p05Strict) && error instanceof HttpException && error.getStatus() === 413) {
        finish(new HttpException('Payload Too Large', 413), true);
        return;
      }
      finish(new BadRequestException());
      return;
    }
    finish();
  }
  function onError(): void { finish(new BadRequestException(), true); }
  function onClose(): void { if (!done) { done = true; cleanup(); } }
  const deadline = setTimeout(() => { finish(new HttpException('Request Timeout', 408), true); }, P03_BODY_DEADLINE_MS);
  deadline.unref();
  req.on('error', onError);
  req.on('close', onClose);
  req.on('end', onEnd);
  req.on('data', onData);
}
