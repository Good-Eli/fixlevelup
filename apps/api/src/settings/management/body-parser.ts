import { BadRequestException, HttpException } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { TextDecoder } from 'node:util';
import { P03_BODY_DEADLINE_MS, p03BodyLimit } from '@fixlevelup/p03-contracts';
import { matchP04Route, P04_ROUTES } from '@fixlevelup/p03-contracts/p04';
import { parseStrictPricingJson } from '../../pricing/codec/index.js';
import { header } from '../../auth/http.js';
import type { StaffRequest } from '../../auth/http.js';

export function closeAfterProblem(req: StaffRequest, res: ServerResponse): void {
  req.pause();
  res.setHeader('Connection', 'close');
  // Flush the problem before shutting down an incomplete request.
  const socket = req.socket;
  res.once('finish', () => { socket.end(); });
}

type Next = (error?: HttpException) => void;
interface BodyOptions {
  readonly limit: number;
  readonly decode: ((value: Buffer) => unknown) | null;
  readonly forbidBody?: boolean;
}

/** Cap and bound the byte stream before interpreting it. `decode:null` hands
 * opaque bytes to an isolated caller that must authorize before decoding. */
export function readBoundedJson(req: StaffRequest, res: ServerResponse, next: Next, options: BodyOptions): void {
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
  if (options.forbidBody || !/^application\/json(?:\s*;\s*charset\s*=\s*utf-8)?$/i.test(type ?? '')) {
    closeAfterProblem(req, res);
    next(!options.forbidBody && type && /^application\/json\s*;/i.test(type)
      ? new HttpException('Unsupported Media Type', 415) : new BadRequestException());
    return;
  }
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
    if (bytes > options.limit) { finish(new HttpException('Payload Too Large', 413), true); return; }
    chunks.push(chunk);
  }
  function onEnd(): void {
    try {
      const buffer = Buffer.concat(chunks, bytes);
      const value = options.decode === null ? buffer : options.decode(buffer);
      if (value === null || typeof value !== 'object') { throw new BadRequestException(); }
      req.body = value;
    } catch (error) {
      finish(error instanceof HttpException && error.getStatus() === 413 ? error : new BadRequestException());
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

export function boundedJson(req: StaffRequest, res: ServerResponse, next: Next): void {
  const method = req.method ?? '';
  const path = (req.url ?? '').split('?', 1)[0] ?? '';
  const p04 = method === 'POST' ? matchP04Route(method, path) : null;
  readBoundedJson(req, res, next, { limit: p04 ? P04_ROUTES[p04.operation].bodyLimit : p03BodyLimit(method, path),
    decode: p04 ? parseStrictPricingJson : (value): unknown => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(value)) });
}
