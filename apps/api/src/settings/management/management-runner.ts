import { createHash, randomUUID } from 'node:crypto';
import { BadRequestException, ConflictException, HttpException, Inject, Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { P03_COMMANDS, P03_RECEIPT_ENVELOPE_VERSION, isP03Uuid, isP03Version } from '@fixlevelup/p03-contracts';
import type { P03Capability, P03CommandReceipt, P03Operation, P03Target } from '@fixlevelup/p03-contracts';
import type { PoolClient } from 'pg';
import { AUTHORIZATION_SERVICE } from '../../authz/authorization.resources.js';
import { P03CommitUnknown } from '../../authz/authorization.service.js';
import type { P03AuthorizationApi, P03Context, P03PolicyContext, SessionProof } from '../../authz/authorization.service.js';
import { activeAdminCityIds } from '../../authz/p03-grants.js';
import { authFailure } from '../../authz/rbac-http.js';
import {
  ConfigurationError, acquireCompanySettingsLock, archiveContentBlock, archiveReferenceEntry, createContentBlock,
  createReferenceEntry, publishCompanySettings, publishContentRevision, publishReferenceVersion,
} from '../configuration/index.js';
import { createLegalDocument, LegalPortError, publishLegalDocumentVersion } from '../legal/index.js';
import { contentIdentity, contentTarget, legalIdentity, referenceIdentity, referenceTarget } from './catalog-reads.js';
import { COMPANY } from './input.js';
import type { P03Command, Preconditions } from './input.js';
import { bootstrapIdentity, bootstrapRevoke } from './projections.js';
import type { P03BootstrapGrant, P03CityPickerDomain } from '@fixlevelup/p03-contracts';

type AuthTarget = P03Target | ((ctx: P03PolicyContext) => Promise<P03Target>);

export function managementFailure(error: unknown): never {
  if (error instanceof ConfigurationError || error instanceof LegalPortError) {
    switch (error.code) {
      case 'INVALID_INPUT': case 'RESERVED_CODE': case 'INVALID_REFERENCE': throw new BadRequestException();
      case 'NOT_FOUND': throw new NotFoundException();
      case 'STALE_VERSION': throw new HttpException('Precondition Failed', 412);
      case 'ARCHIVED': case 'CONFLICT': case 'ALREADY_EXISTS': case 'INCOMPLETE': throw new ConflictException();
      default: throw new InternalServerErrorException();
    }
  }
  authFailure(error);
}

function requirements(command: P03Command): readonly P03Capability[] {
  switch (command.op) {
    case 'companyPublish': return ['settings.fullread', 'settings.manage'];
    case 'referenceCreate': case 'referencePublish': case 'referenceArchive': return [command.ref.read, command.ref.manage];
    case 'contentCreate': case 'contentArchive': return ['content.read', 'content.manage'];
    case 'contentPublish': return ['content.read', 'content.manage', 'content.publish'];
    case 'legalCreate': case 'legalPublish': return ['legal.read', 'legal.manage'];
    case 'bootstrapRevoke': return [command.code];
  }
}

export function resolveContentTarget(id: string): AuthTarget { return ({ client }) => contentTarget(client, id); }
function targetOf(command: P03Command): AuthTarget {
  if ('target' in command) { return command.target; }
  if (command.op === 'contentPublish' || command.op === 'contentArchive') { return resolveContentTarget(command.id); }
  return COMPANY;
}

function canonical(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) { return JSON.stringify(value); }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const row = value as Record<string, unknown>;
    return `{${Object.keys(row).sort().map(k => `${JSON.stringify(k)}:${canonical(row[k])}`).join(',')}}`;
  }
  throw new InternalServerErrorException();
}
interface ReceiptRow { request_sha256: string; entity_id: string; entity_version: number; revision_id: string | null; revision_version: number | null }
function safeReceipt(op: P03Operation, row: Omit<ReceiptRow, 'request_sha256'>): P03CommandReceipt {
  if (!isP03Uuid(row.entity_id) || !isP03Version(row.entity_version)) { throw new InternalServerErrorException(); }
  const base = { id: row.entity_id, version: row.entity_version };
  if (P03_COMMANDS[op].revisionReceipt) {
    if (!isP03Uuid(row.revision_id) || !isP03Version(row.revision_version)) { throw new InternalServerErrorException(); }
    return { ...base, revisionId: row.revision_id, revisionVersion: row.revision_version };
  }
  if (row.revision_id !== null || row.revision_version !== null) { throw new InternalServerErrorException(); }
  return base;
}

/** Evidence errors must remain 500, even when a driver code resembles a domain validation failure. */
async function evidence<T>(write: () => Promise<T>): Promise<T> {
  try { return await write(); } catch { throw new InternalServerErrorException(); }
}
/** Existing ports use this same client's query method; isolate their evidence I/O from legal SQLSTATE mapping. */
function domainClient(client: PoolClient): Pick<PoolClient, 'query'> {
  // Shape of the public internal ports is Pick<PoolClient, 'query'>; invocation stays on the identical backend.
  const query = ((text: string, values?: unknown[]) => /\bINSERT INTO foundation\.(?:audit_logs|outbox_events)\b/i.test(text)
    ? evidence(() => client.query(text, values)) : client.query(text, values)) as PoolClient['query'];
  return { query };
}

async function publishCompany(ctx: P03Context, body: Extract<P03Command, { op: 'companyPublish' }>['body'], expected: number): Promise<P03CommandReceipt> {
  await acquireCompanySettingsLock(ctx.client);
  const { rows: [latest] } = await ctx.client.query<{ version: number; active: boolean }>(`
    SELECT b.version,(b.launch_mode='SINGLE_CITY' AND c.lifecycle='ACTIVE' AND c.current_version_id IS NOT NULL) AS active
    FROM foundation.business_settings_versions b JOIN foundation.service_cities c ON c.id=b.primary_city_id
    ORDER BY b.version DESC LIMIT 1`);
  // Geography owns activation and the initial settings revision; policy/consent readiness is not a prerequisite.
  if (!latest) { throw new ConflictException(); }
  if (latest.version !== expected) { throw new HttpException('Precondition Failed', 412); }
  if (!latest.active) { throw new ConflictException(); }
  const { id, version } = await publishCompanySettings(domainClient(ctx.client), ctx.staffId, { settings: body, expectedLastVersion: expected });
  return { id, version };
}

async function runNew(ctx: P03Context, command: P03Command, version: number | null, bootstrap: P03BootstrapGrant | null): Promise<P03CommandReceipt> {
  const client = domainClient(ctx.client);
  if (P03_COMMANDS[command.op].versioned && version === null) { throw new InternalServerErrorException(); }
  const expectedVersion = version ?? 0;
  switch (command.op) {
    case 'companyPublish': return publishCompany(ctx, command.body, expectedVersion);
    case 'referenceCreate': return createReferenceEntry(client, ctx.staffId, { ...command.body, type: command.ref.dbType, cityId: ctx.target.cityId });
    case 'referencePublish': {
      const r = await publishReferenceVersion(client, ctx.staffId, { ...command.body, type: command.ref.dbType, entryId: command.id, expectedVersion });
      return { id: r.entryId, version: r.entryVersion, revisionId: r.id, revisionVersion: r.version };
    }
    case 'referenceArchive': return archiveReferenceEntry(client, ctx.staffId, { entryId: command.id, expectedVersion });
    case 'contentCreate': return createContentBlock(client, ctx.staffId, command.body);
    case 'contentPublish': {
      const r = await publishContentRevision(client, ctx.staffId, { ...command.body, blockId: command.id, expectedVersion });
      return { id: r.blockId, version: r.blockVersion, revisionId: r.id, revisionVersion: r.version };
    }
    case 'contentArchive': return archiveContentBlock(client, ctx.staffId, { blockId: command.id, expectedVersion });
    case 'legalCreate': {
      const r = await createLegalDocument(client, command.body);
      return { id: r.documentId, version: r.version };
    }
    case 'legalPublish': {
      const r = await publishLegalDocumentVersion(client, { ...command.body, documentId: command.id, expectedVersion, reviewedBy: ctx.staffId });
      return { id: r.documentId, version: r.version, revisionId: r.versionId, revisionVersion: r.sequence };
    }
    case 'bootstrapRevoke': {
      if (!bootstrap) { throw new InternalServerErrorException(); }
      return bootstrapRevoke(ctx, bootstrap, expectedVersion);
    }
  }
}

/** The receipt's stored identity can belong to a different territory or catalogue type
 * than the newly authorized request. Check its own capability intersection before
 * disclosing a collision. These are already-effective grants under the same policy lock. */
async function requireStoredTarget(ctx: P03Context, codes: readonly P03Capability[], target: P03Target): Promise<void> {
  const required = codes.map(code => ctx.p03Permissions.find(grant => grant.code === code));
  if (required.some(grant => !grant)) { throw new NotFoundException(); }
  if (!required.some(grant => grant?.scope === 'CITY')) { return; }
  if (target.scope !== 'CITY') { throw new NotFoundException(); }
  const cityIds = await activeAdminCityIds(ctx.client, ctx.staffId);
  if (!cityIds.includes(target.cityId)) { throw new NotFoundException(); }
}

async function verifyReplay(ctx: P03Context, command: P03Command, stored: ReceiptRow, bootstrap: P03BootstrapGrant | null): Promise<void> {
  switch (command.op) {
    case 'referenceCreate': case 'referencePublish': case 'referenceArchive': {
      const { ref, target } = await referenceTarget(ctx.client, stored.entity_id);
      await requireStoredTarget(ctx, [ref.read, ref.manage], target);
      if ('id' in command && command.id !== stored.entity_id) { throw new ConflictException(); }
      break;
    }
    case 'contentCreate': case 'contentPublish': case 'contentArchive': {
      const target = await contentTarget(ctx.client, stored.entity_id);
      await requireStoredTarget(ctx, requirements(command), target);
      if ('id' in command && command.id !== stored.entity_id) { throw new ConflictException(); }
      break;
    }
    case 'legalCreate': case 'legalPublish': {
      await legalIdentity(ctx.client, stored.entity_id);
      if ('id' in command && command.id !== stored.entity_id) { throw new ConflictException(); }
      break;
    }
    case 'companyPublish': {
      const { rowCount } = await ctx.client.query('SELECT 1 FROM foundation.business_settings_versions WHERE id=$1', [stored.entity_id]);
      if (rowCount !== 1) { throw new NotFoundException(); }
      break;
    }
    case 'bootstrapRevoke': if (stored.entity_id !== bootstrap?.assignmentId) { throw new NotFoundException(); } break;
  }
}

async function commandVisibility(ctx: P03Context, command: P03Command): Promise<{ bootstrap: P03BootstrapGrant | null; version: number | null }> {
  switch (command.op) {
    case 'referencePublish': case 'referenceArchive':
      return { bootstrap: null, version: (await referenceIdentity(ctx.client, command.ref, ctx.target, command.id)).version };
    case 'contentPublish': case 'contentArchive':
      return { bootstrap: null, version: (await contentIdentity(ctx.client, ctx.target, command.id)).version };
    case 'legalPublish': return { bootstrap: null, version: (await legalIdentity(ctx.client, command.id)).version };
    case 'bootstrapRevoke': {
      const bootstrap = await bootstrapIdentity(ctx, command.staffId, command.code);
      return { bootstrap, version: bootstrap.version };
    }
    default: return { bootstrap: null, version: null };
  }
}

function commandTarget(ctx: P03Context, command: P03Command, bootstrap: P03BootstrapGrant | null) {
  return { ...ctx.target, ...('id' in command ? { id: command.id } : {}), ...('ref' in command ? { type: command.ref.dbType } : {}),
    ...(bootstrap ? { assignmentId: bootstrap.assignmentId, staffId: bootstrap.staffId, code: bootstrap.code } : {}) };
}

async function matchingReceipt(ctx: P03Context, command: P03Command, guards: Preconditions, requestSha: string, bootstrap: P03BootstrapGrant | null): Promise<P03CommandReceipt | null> {
  const { rows: [stored] } = await evidence(() => ctx.client.query<ReceiptRow>(`SELECT request_sha256,entity_id,entity_version,revision_id,revision_version
    FROM foundation.p03_command_receipts WHERE actor_id=$1 AND operation=$2 AND key=$3`, [ctx.staffId, command.op, guards.key]));
  if (!stored) { return null; }
  // The bootstrap receipt identifies an assignment, not its original code. A changed
  // envelope cannot prove that exact source is still visible; deny without disclosing a collision.
  if (command.op === 'bootstrapRevoke' && stored.request_sha256 !== requestSha) { throw new NotFoundException(); }
  await verifyReplay(ctx, command, stored, bootstrap);
  if (stored.request_sha256 !== requestSha) { throw new ConflictException(); }
  return safeReceipt(command.op, stored);
}

function digest(ctx: P03Context, command: P03Command, guards: Preconditions, target: ReturnType<typeof commandTarget>): string {
  return createHash('sha256').update(canonical({ v: P03_RECEIPT_ENVELOPE_VERSION, actor: ctx.staffId,
    operation: command.op, target, key: guards.key, expectedVersion: guards.expectedVersion, normalizedBody: command.body })).digest('hex');
}

@Injectable()
export class ManagementRunner {
  constructor(@Inject(AUTHORIZATION_SERVICE) private readonly auth: P03AuthorizationApi) {}

  read<T>(proof: SessionProof, caps: readonly P03Capability[], target: AuthTarget, run: (ctx: P03Context) => Promise<T>): Promise<T> {
    return this.auth.withP03(proof, 'read', caps, target, ctx => run(ctx).catch(managementFailure)).catch(authFailure);
  }

  discover<T>(proof: SessionProof, domain: P03CityPickerDomain, run: (ctx: P03PolicyContext, cityIds: readonly string[] | null) => Promise<T>): Promise<T> {
    return this.auth.withP03Discovery(proof, domain, run).catch(authFailure);
  }

  execute(proof: SessionProof, command: P03Command, guards: Preconditions): Promise<{ data: P03CommandReceipt; replayed: boolean }> {
    const required = requirements(command);
    const authorizationTarget = targetOf(command);
    return this.auth.withP03(proof, 'write', required, authorizationTarget, async ctx => {
      const { bootstrap, version } = await commandVisibility(ctx, command);
      const target = commandTarget(ctx, command, bootstrap);
      const requestSha = digest(ctx, command, guards, target);
      const stored = await matchingReceipt(ctx, command, guards, requestSha, bootstrap);
      if (stored) { return { data: stored, replayed: true }; }
      if (version !== null && version !== guards.expectedVersion) { throw new HttpException('Precondition Failed', 412); }
      const result = await runNew(ctx, command, guards.expectedVersion, bootstrap).catch(managementFailure);
      const row = { entity_id: result.id, entity_version: result.version, revision_id: 'revisionId' in result ? result.revisionId : null,
        revision_version: 'revisionVersion' in result ? result.revisionVersion : null };
      const data = safeReceipt(command.op, row);
      const correlation = randomUUID();
      const payload = JSON.stringify({ actorId: ctx.staffId, operation: command.op, ...target, entityId: data.id, version: data.version,
        ...('revisionId' in data ? { revisionId: data.revisionId, revisionVersion: data.revisionVersion } : {}) });
      await evidence(async () => {
        await ctx.client.query(`INSERT INTO foundation.p03_command_receipts(actor_id,operation,key,request_sha256,entity_id,entity_version,revision_id,revision_version)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, [ctx.staffId, command.op, guards.key, requestSha, row.entity_id, row.entity_version, row.revision_id, row.revision_version]);
        await ctx.client.query(`INSERT INTO foundation.audit_logs(id,operation,correlation_id,details)
          VALUES ($1,'P03_MANAGEMENT_CHANGED',$2,$3::jsonb)`, [randomUUID(), correlation, payload]);
        await ctx.client.query(`INSERT INTO foundation.outbox_events(id,event_id,event_type,payload)
          VALUES ($1,$2,'P03_MANAGEMENT_CHANGED',$3::jsonb)`, [randomUUID(), correlation, payload]);
      });
      return { data, replayed: false };
    }).catch(async (error: unknown) => {
      if (!(error instanceof P03CommitUnknown)) { authFailure(error); }
      // The first transaction may have committed. Start exactly one newly authorized read, never another mutation.
      return this.read(proof, required, authorizationTarget, async ctx => {
        const { bootstrap } = await commandVisibility(ctx, command);
        const target = commandTarget(ctx, command, bootstrap);
        const data = await matchingReceipt(ctx, command, guards, digest(ctx, command, guards, target), bootstrap);
        if (!data) { throw new InternalServerErrorException(); }
        return { data, replayed: true };
      });
    });
  }
}
