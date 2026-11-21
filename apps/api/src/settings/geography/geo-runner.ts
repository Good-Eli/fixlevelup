import { createHash, randomUUID } from 'node:crypto';
import { BadRequestException, ConflictException, ForbiddenException, HttpException, Inject, Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { AUTHORIZATION_SERVICE } from '../../authz/authorization.resources.js';
import type { SessionProof } from '../../authz/authorization.service.js';
import { authFailure, uuid } from '../../authz/rbac-http.js';
import { catalogCommands } from './catalog-commands.js';
import { membershipCommands } from './membership-commands.js';
import type { GeoCommand, GeographyAuthorizationApi, GeoReceipt, GeoTarget } from './geo-contract.js';

import { revokeBootstrap } from './bootstrap-revoke.js';

const commands = { ...catalogCommands, ...membershipCommands, revokeBootstrap } as const;
export type GeoOperation = keyof typeof commands;

/** JSON from the bounded HTTP parser; reject ambiguous types, never persist the raw body. */
function canonical(value: unknown, depth = 0): string {
  if (depth > 24) { throw new BadRequestException(); }
  if (value === null || typeof value === 'string' || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) { return `[${value.map((v: unknown) => canonical(v, depth + 1)).join(',')}]`; }
  if (!value || typeof value !== 'object' || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    throw new BadRequestException();
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map(k => `${JSON.stringify(k)}:${canonical(record[k], depth + 1)}`).join(',')}}`;
}

function receipt(value: unknown): GeoReceipt {
  if (typeof value === 'object' && value !== null && 'id' in value && typeof value.id === 'string' && 'version' in value
      && typeof value.version === 'number' && Number.isSafeInteger(value.version) && value.version >= 0) {
    return { id: uuid(value.id), version: value.version };
  }
  throw new InternalServerErrorException();
}

interface WriteProof { key: string; expected: number | null }
interface ExecutionResult { readonly data: unknown; readonly replayed: boolean }
export function geoPreconditions(operation: GeoOperation, key: string | undefined, tag: string | undefined): WriteProof {
  if (!key) { throw new BadRequestException(); }
  const normalized = uuid(key);
  if (operation === 'cityCreate' && tag === undefined) { return { key: normalized, expected: null }; }
  if (!tag) { throw new HttpException('Precondition Required', 428); }
  const match = /^"geo-v(0|[1-9][0-9]*)"$/.exec(tag);
  if (!match || !Number.isSafeInteger(Number(match[1])) || operation === 'cityCreate') { throw new BadRequestException(); }
  return { key: normalized, expected: Number(match[1]) };
}

function mapConstraint(error: unknown): never {
  if (error instanceof HttpException) { throw error; }
  if (error && typeof error === 'object' && 'code' in error) {
    if (error.code === '23503' || error.code === '23505' || error.code === '23P01' || error.code === '40001' || error.code === '55P03' || error.code === '40P01') { throw new ConflictException(); }
    if (error.code === '23514' || error.code === '22001' || error.code === '22007' || error.code === '22008' || error.code === '22P02') { throw new BadRequestException(); }
  }
  throw error;
}

@Injectable()
export class GeoRunner {
  constructor(@Inject(AUTHORIZATION_SERVICE) private readonly auth: GeographyAuthorizationApi) {}

  execute(session: SessionProof, op: GeoOperation, target: GeoTarget, body?: unknown, write?: WriteProof): Promise<ExecutionResult> {
    const command: GeoCommand = commands[op];
    if (command.write !== Boolean(write) || (command.scoped === 'city' && !target.cityId)) { throw new InternalServerErrorException(); }
    return this.auth.withGeography(session, write ? 'write' : 'read', command.action, target.cityId ?? null, async ctx => {
      if (command.scoped === 'global' && (ctx.cityIds !== null || ctx.role.type !== 'SYSTEM' || ctx.role.code !== 'ADMIN')) { throw new ForbiddenException(); }
      if (target.cityId && ctx.cityIds !== null && !ctx.cityIds.includes(target.cityId)) { throw new NotFoundException(); }
      if (command.scoped === 'self' && (ctx.principal.kind !== 'staff-telegram' || target.staffId !== undefined)) { throw new ForbiddenException(); }
      await command.check(ctx, target); // Includes visibility of the actual object, on this transaction, even for replay.
      if (!write) { return { data: await command.run(ctx, target, body, null), replayed: false }; }
      const digest = createHash('sha256').update(canonical({ target, body, expected: write.expected, key: write.key })).digest('hex');
      const prior = await ctx.client.query<{ body_hash: string; entity_id: string; entity_version: number }>(
        'SELECT body_hash,entity_id,entity_version FROM foundation.geography_command_receipts WHERE actor_id=$1 AND operation=$2 AND key=$3', [ctx.staffId,op,write.key]);
      const stored = prior.rows[0];
      if (stored) {
        if (stored.body_hash !== digest) { throw new ConflictException(); }
        return { data: { id: stored.entity_id, version: stored.entity_version }, replayed: true };
      }
      // Only domain constraints are client errors. Failure to persist audit/outbox/receipt is a server failure and rolls back the command.
      const result = receipt(await command.run(ctx, target, body, write.expected).catch(mapConstraint));
      const eventId = randomUUID();
      const details = { actorId: ctx.staffId, operation: op, ...target, entityId: result.id, version: result.version };
      await ctx.client.query(`INSERT INTO foundation.geography_command_receipts(actor_id,operation,key,body_hash,entity_id,entity_version)
        VALUES ($1,$2,$3,$4,$5,$6)`, [ctx.staffId,op,write.key,digest,result.id,result.version]);
      await ctx.client.query(`INSERT INTO foundation.audit_logs(id,operation,correlation_id,details)
        VALUES ($1,'GEOGRAPHY_CHANGED',$2,$3::jsonb)`, [randomUUID(),eventId,JSON.stringify(details)]);
      await ctx.client.query(`INSERT INTO foundation.outbox_events(id,event_id,event_type,payload)
        VALUES ($1,$2,'GEOGRAPHY_CHANGED',$3::jsonb)`, [randomUUID(),eventId,JSON.stringify({operation:op,entityId:result.id,version:result.version})]);
      return { data: result, replayed: false };
    }).catch(authFailure);
  }
}
