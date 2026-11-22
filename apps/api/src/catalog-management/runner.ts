import { createHash } from 'node:crypto';
import { BadRequestException, ConflictException, HttpException, Inject, Injectable, InternalServerErrorException,
  NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { decodeP04Data, P04_ROUTES } from '@fixlevelup/p03-contracts/p04';
import type { P04Operation } from '@fixlevelup/p03-contracts/p04';
import { AUTHORIZATION_SERVICE } from '../authz/authorization.resources.js';
import { P03CommitUnknown } from '../authz/authorization.service.js';
import type { P04AuthorizationApi, P04Context, P04Target, SessionProof } from '../authz/authorization.service.js';
import { isP04Capability } from '../authz/capability.js';
import { authFailure } from '../authz/rbac-http.js';
import { CatalogError } from '../catalog/index.js';
import { canonicalPricingJson } from '../pricing/codec/index.js';
import { applyCommand, commandScope, subjectName } from './commands.js';
import type { Command, Params, Receipt } from './commands.js';
import { assertManagementTarget, readManagement } from './reads.js';

interface Row {
  readonly request_sha256: string;
  readonly city_id: string | null;
  readonly subject_id: string;
  readonly target_version_id: string | null;
  readonly entity_id: string;
  readonly entity_version: number;
  readonly revision_id: string | null;
  readonly revision_version: number | null;
}
const COMPANY = { scope: 'COMPANY' } as const;
function authorizationTarget(operation: P04Operation, params: Params): P04Target {
  if (P04_ROUTES[operation].scope === 'COMPANY') { return COMPANY; }
  if (operation === 'cityList' || operation === 'pricingReadiness') { return { scope: 'DISCOVERY' }; }
  if (!params['cityId']) { throw new InternalServerErrorException(); }
  return { scope: 'CITY', cityId: params['cityId'] };
}
function required(operation: P04Operation) {
  return P04_ROUTES[operation].permissions.map((code) => {
    if (!isP04Capability(code)) { throw new InternalServerErrorException(); }
    return code;
  });
}
function requestDigest(command: Command, actor: string): string {
  return createHash('sha256').update(canonicalPricingJson({ version: 1, actor, operation: command.operation,
    key: command.key, target: command.params, expectedVersion: command.expectedVersion, body: command.body }), 'utf8').digest('hex');
}
function checkedReceipt(command: Command, value: Receipt): Receipt {
  try { decodeP04Data(command.operation, value); }
  catch { throw new InternalServerErrorException(); }
  return value;
}
function receiptFromRow(command: Command, row: Row): Receipt {
  const minimal = { id: row.entity_id, version: row.entity_version };
  if (row.revision_id === null && row.revision_version === null) { return checkedReceipt(command, minimal); }
  if (row.revision_id === null || row.revision_version === null) { throw new InternalServerErrorException(); }
  return checkedReceipt(command, { ...minimal, revisionId: row.revision_id, revisionVersion: row.revision_version });
}

async function verifyStored(ctx: P04Context, command: Command, row: Row): Promise<void> {
  const op = command.operation;
  const storedTarget: P04Target = row.city_id === null ? COMPANY : { scope: 'CITY', cityId: row.city_id };
  await ctx.recheck(storedTarget);
  const params: Record<string, string> = row.city_id === null ? {} : { cityId: row.city_id };
  if (row.target_version_id !== null) { params['versionId'] = row.target_version_id; }
  const receipt = { entityId: row.entity_id, entityVersion: row.entity_version,
    revisionId: row.revision_id, revisionVersion: row.revision_version };
  if (op.endsWith('Create')) {
    await assertManagementTarget(ctx.client, op, params, { storedSubjectId: row.subject_id, receipt });
  } else {
    params[subjectName(op)] = row.subject_id;
    await assertManagementTarget(ctx.client, op, params, { receipt });
  }
  await ctx.recheck(storedTarget);
}

async function matchingReceipt(ctx: P04Context, command: Command, sha: string): Promise<Receipt | null> {
  const { rows } = await ctx.client.query<Row>(`SELECT request_sha256,city_id,subject_id,target_version_id,
    entity_id,entity_version,revision_id,revision_version FROM foundation.p04_command_receipts
    WHERE actor_id=$1 AND operation=$2 AND key=$3`, [ctx.staffId, command.operation, command.key]);
  // The receipt SELECT can block. Discovery of a stored key is never itself authority.
  await ctx.recheck();
  const found = rows[0];
  if (!found) { return null; }
  await verifyStored(ctx, command, found);
  if (found.request_sha256 !== sha) { throw new ConflictException(); }
  const subject = command.params[subjectName(command.operation)];
  if (found.city_id !== (command.params['cityId'] ?? null) || found.target_version_id !== (command.params['versionId'] ?? null)
      || (subject !== undefined && subject !== found.subject_id)) { throw new InternalServerErrorException(); }
  return receiptFromRow(command, found);
}

async function writeReceipt(ctx: P04Context, command: Command, sha: string, data: Receipt): Promise<void> {
  const op = command.operation;
  const subject = op.endsWith('Create') ? data.id : command.params[subjectName(op)];
  if (!subject) { throw new InternalServerErrorException(); }
  try {
    const { rowCount } = await ctx.client.query(`INSERT INTO foundation.p04_command_receipts
      (actor_id,operation,key,request_sha256,city_id,subject_id,target_version_id,entity_id,entity_version,revision_id,revision_version)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, [ctx.staffId, op, command.key, sha, command.params['cityId'] ?? null,
      subject, command.params['versionId'] ?? null, data.id, data.version,
      'revisionId' in data ? data.revisionId : null, 'revisionVersion' in data ? data.revisionVersion : null]);
    if (rowCount !== 1) { throw new InternalServerErrorException(); }
  } catch {
    // This statement stores evidence, not a business resource. Do not let a
    // driver constraint error masquerade as a request conflict. The enclosing
    // transaction rolls back the effect and rechecks authority before responding.
    throw new InternalServerErrorException();
  }
}

function domainFailure(error: unknown): never {
  if (error instanceof CatalogError) {
    switch (error.code) {
      case 'INVALID_INPUT': throw new BadRequestException();
      case 'NOT_FOUND': throw new NotFoundException();
      case 'STALE_VERSION': throw new HttpException('Precondition Failed', 412);
      case 'CONFLICT': case 'ARCHIVED': case 'PRICE_NOT_CONFIGURED': throw new ConflictException();
      default: throw new InternalServerErrorException();
    }
  }
  throw error;
}

@Injectable()
export class CatalogManagementRunner {
  constructor(@Inject(AUTHORIZATION_SERVICE) private readonly auth: P04AuthorizationApi) {}

  read(proof: SessionProof, op: P04Operation, params: Params, query: string): Promise<unknown> {
    return this.auth.withP04(proof, 'read', required(op), authorizationTarget(op, params), async ctx => {
      await ctx.client.query('SELECT pg_catalog.pg_advisory_xact_lock_shared(77304,1)');
      await ctx.recheck();
      return readManagement(ctx.client, op, params, query, ctx.cityIds).catch(domainFailure);
    }).catch(authFailure);
  }

  execute(proof: SessionProof, command: Command): Promise<{ data: Receipt; replayed: boolean }> {
    const { operation, params, body } = command;
    return this.auth.withP04(proof, 'write', required(operation), authorizationTarget(operation, params), async ctx => {
      await ctx.client.query('SELECT pg_catalog.pg_advisory_xact_lock(77304,1)');
      await ctx.recheck();
      await assertManagementTarget(ctx.client, operation, params, commandScope(body, operation)).catch(domainFailure);
      await ctx.recheck();
      const sha = requestDigest(command, ctx.staffId);
      const prior = await matchingReceipt(ctx, command, sha).catch(domainFailure);
      if (prior) { return { data: prior, replayed: true }; }
      if (ctx.target.scope === 'CITY') {
        const { rowCount } = await ctx.client.query('SELECT id FROM foundation.service_cities WHERE id=$1 FOR SHARE', [ctx.target.cityId]);
        if (rowCount !== 1) { throw new NotFoundException(); }
      }
      // The inner ports take the same already-held fence and city lock. No body or authority
      // is read again from the HTTP request after hashing.
      await ctx.recheck();
      const data = checkedReceipt(command, await applyCommand(ctx.client, ctx.staffId, command).catch(domainFailure));
      await writeReceipt(ctx, command, sha, data);
      return { data, replayed: false };
    }).catch((error: unknown) => {
      if (error instanceof P03CommitUnknown) { throw new ServiceUnavailableException(); }
      return authFailure(error);
    });
  }
}
