import { BadRequestException, ForbiddenException, HttpException, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import type { StaffRequest } from '../auth/http.js';
import { expectExactOrigin, header, requireMutation } from '../auth/http.js';
import type { WebAuthHttpConfig } from '../auth/web-auth.controller.js';
import { AuthorizationError } from './authorization.service.js';
import type { SessionProof } from './authorization.service.js';
import type { Principal } from './principal.js';

export type RbacRequest = StaffRequest & { principal?: Principal; sessionToken?: string };
export function proof(req: RbacRequest): SessionProof {
  if (!req.principal || !req.sessionToken) { throw new UnauthorizedException(); }
  return { token: req.sessionToken, kind: req.principal.kind };
}
export function readOrigin(req: RbacRequest, config: WebAuthHttpConfig): void {
  if (proof(req).kind === 'staff-web') { expectExactOrigin(req, config.origin); }
}
export function mutation(req: RbacRequest, config: WebAuthHttpConfig): void {
  const verified = proof(req);
  if (verified.kind === 'staff-web') { requireMutation(req, verified.token, config); return; }
  // The TG guard only accepts an explicit bearer, never a cookie or a client-supplied role.
  if (!/^application\/json(?:\s*;\s*charset\s*=\s*utf-8)?$/i.test(header(req, 'content-type') ?? '')) { throw new BadRequestException(); }
}
export function uuid(value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) { throw new BadRequestException(); }
  return value.toLowerCase();
}
export function expectedVersion(req: StaffRequest, kind: 'staff' | 'role'): number {
  const supplied = header(req, 'if-match');
  if (supplied === undefined) { throw new HttpException('Precondition Required', 428); }
  const match = /^"(staff|role)-v(0|[1-9][0-9]*)"$/.exec(supplied);
  if (!match || match[1] !== kind || !Number.isSafeInteger(Number(match[2]))) { throw new BadRequestException(); }
  return Number(match[2]);
}
export function authFailure(error: unknown): never {
  if (!(error instanceof AuthorizationError)) { throw error; }
  if (error.code === 'UNAUTHORIZED') { throw new UnauthorizedException(); }
  if (error.code === 'FORBIDDEN') { throw new ForbiddenException(); }
  throw new InternalServerErrorException();
}
