import { InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { P03_LEGAL_PURPOSES, P03_REFERENCE_TYPES } from '@fixlevelup/p03-contracts';
import type {
  P03CompanySummary, P03CompanyVersion, P03ContentBlock, P03ContentKind, P03ContentRevision, P03ContentSummary,
  P03LegalDocument, P03LegalKind, P03LegalPurpose, P03LegalSummary, P03LegalVersion, P03Page,
  P03ReferenceDbType, P03ReferenceEntry, P03ReferenceSummary, P03ReferenceVersion, P03Target, P03VersionedPage,
} from '@fixlevelup/p03-contracts';
import type { PoolClient } from 'pg';
import { readCompanySettingsVersion } from '../configuration/index.js';
import { COMPANY } from './input.js';
import type { ReferenceDescriptor } from './input.js';
import type { Keyset } from './page.js';

export function found<T>(row: T | undefined): T {
  if (row === undefined) { throw new NotFoundException(); }
  return row;
}
export async function requireCity(client: PoolClient, target: P03Target): Promise<void> {
  if (target.scope === 'CITY') {
    const result = await client.query('SELECT 1 FROM foundation.service_cities WHERE id=$1', [target.cityId]);
    if (result.rowCount !== 1) { throw new NotFoundException(); }
  }
}

interface SummaryRow { id: string; version: number; published_at: Date }
const summary = (r: SummaryRow) => ({ id: r.id, version: r.version, publishedAt: r.published_at.toISOString() });
const versionKey = (r: SummaryRow) => [r.version, r.id] as const;
const codeKey = (r: { code: string; id: string }) => [r.code, r.id] as const;
const isoNull = (date: Date | null) => date?.toISOString() ?? null;

export async function companyHistory(client: PoolClient, page: Keyset<number>): Promise<P03VersionedPage<P03CompanySummary>> {
  // Both metadata and page are drawn under one statement snapshot, including empty final pages.
  const { rows: [result] } = await client.query<{ version: number; items: { id: string; version: number; published_at: string }[] }>(`
    SELECT COALESCE((SELECT max(version) FROM foundation.business_settings_versions), 0) AS version,
      COALESCE((SELECT json_agg(p ORDER BY p.version DESC,p.id DESC) FROM (
        SELECT id,version,published_at FROM foundation.business_settings_versions
        WHERE ($1::int IS NULL OR (version,id)<($1,$2::uuid)) ORDER BY version DESC,id DESC LIMIT $3
      ) p), '[]'::json) AS items`, [page.key, page.id, page.count]);
  if (!result) { throw new InternalServerErrorException(); }
  return { ...page.page(result.items, row => ({ id: row.id, version: row.version, publishedAt: new Date(row.published_at).toISOString() }), row => [row.version, row.id]), version: result.version };
}
export async function companyExact(client: PoolClient, version: number): Promise<P03CompanyVersion> {
  const value = await readCompanySettingsVersion(client, version);
  if (value.launchMode !== 'SINGLE_CITY' && value.launchMode !== 'MULTI_CITY') { throw new InternalServerErrorException(); }
  return { ...value, launchMode: value.launchMode };
}

interface ReferenceRow {
  id: string; code: string; type: P03ReferenceDbType; scope: P03Target['scope']; city_id: string | null;
  row_version: number; current_version_id: string | null; archived_at: Date | null;
}
const referenceColumns = 'id,type,scope,city_id,code,row_version,current_version_id,archived_at';
function reference(r: ReferenceRow): P03ReferenceEntry {
  return { id: r.id, type: r.type, scope: r.scope, cityId: r.city_id, code: r.code, version: r.row_version,
    currentVersionId: r.current_version_id, archivedAt: isoNull(r.archived_at) };
}
/** Resolve only immutable authorization facts for the entity named by a create receipt. */
export async function referenceTarget(client: PoolClient, id: string): Promise<{ ref: ReferenceDescriptor; target: P03Target }> {
  const { rows } = await client.query<Pick<ReferenceRow, 'type' | 'scope' | 'city_id'>>(
    'SELECT type,scope,city_id FROM foundation.reference_entries WHERE id=$1', [id]);
  const r = found(rows[0]);
  const ref = Object.values(P03_REFERENCE_TYPES).find(item => item.dbType === r.type && item.scope === r.scope);
  if (!ref) { throw new InternalServerErrorException(); }
  return { ref, target: persistedTarget(r.scope, r.city_id) };
}
export async function referenceIdentity(client: PoolClient, type: ReferenceDescriptor, target: P03Target, id: string): Promise<P03ReferenceEntry> {
  const { rows } = await client.query<ReferenceRow>(`SELECT ${referenceColumns} FROM foundation.reference_entries
    WHERE id=$1 AND type=$2 AND scope=$3 AND city_id IS NOT DISTINCT FROM $4::uuid`, [id, type.dbType, target.scope, target.cityId ?? null]);
  return reference(found(rows[0]));
}
export async function referenceList(client: PoolClient, type: ReferenceDescriptor, target: P03Target, archived: boolean, page: Keyset<string>): Promise<P03Page<P03ReferenceEntry>> {
  const { rows } = await client.query<ReferenceRow>(`SELECT ${referenceColumns} FROM foundation.reference_entries
    WHERE type=$1 AND scope=$2 AND city_id IS NOT DISTINCT FROM $3::uuid AND ($4::bool OR archived_at IS NULL)
      AND ($5::text IS NULL OR (code COLLATE "C",id)>($5::text,$6::uuid))
    ORDER BY code COLLATE "C",id LIMIT $7`, [type.dbType, target.scope, target.cityId ?? null, archived, page.key, page.id, page.count]);
  return page.page(rows, reference, codeKey);
}
interface ReferenceSummaryRow extends SummaryRow { entry_id: string; label: string }
const referenceSummary = (r: ReferenceSummaryRow): P03ReferenceSummary => ({ ...summary(r), entryId: r.entry_id, label: r.label });
export async function referenceHistory(client: PoolClient, parent: P03ReferenceEntry, page: Keyset<number>): Promise<P03VersionedPage<P03ReferenceSummary>> {
  const { rows } = await client.query<ReferenceSummaryRow>(`SELECT id,version,entry_id,label,published_at
    FROM foundation.reference_entry_versions WHERE entry_id=$1 AND type=$2 AND city_id IS NOT DISTINCT FROM $3::uuid
      AND ($4::int IS NULL OR (version,id)<($4,$5::uuid)) ORDER BY version DESC,id DESC LIMIT $6`,
  [parent.id, parent.type, parent.cityId, page.key, page.id, page.count]);
  return { version: parent.version, ...page.page(rows, referenceSummary, versionKey) };
}
interface ReferenceVersionRow extends ReferenceSummaryRow {
  type: P03ReferenceDbType; city_id: string | null; source_ref: string; valid_from: Date; valid_until: Date | null;
  city_version_id: string | null; start_minute: number | null; end_minute: number | null;
}
export async function referenceExact(client: PoolClient, parent: P03ReferenceEntry, id: string): Promise<P03ReferenceVersion> {
  const { rows } = await client.query<ReferenceVersionRow>(`SELECT id,version,entry_id,label,published_at,type,city_id,source_ref,
    valid_from,valid_until,city_version_id,start_minute,end_minute FROM foundation.reference_entry_versions
    WHERE id=$1 AND entry_id=$2 AND type=$3 AND city_id IS NOT DISTINCT FROM $4::uuid`, [id, parent.id, parent.type, parent.cityId]);
  const r = found(rows[0]);
  return { ...referenceSummary(r), type: r.type, cityId: r.city_id, sourceRef: r.source_ref, validFrom: r.valid_from.toISOString(),
    validUntil: isoNull(r.valid_until), provenanceCityVersionId: r.city_version_id,
    interval: r.start_minute === null || r.end_minute === null ? null : { startMinute: r.start_minute, endMinute: r.end_minute } };
}

interface ContentRow {
  id: string; code: string; kind: P03ContentKind; scope: P03Target['scope']; city_id: string | null;
  allow_company_fallback: boolean; row_version: number; current_revision_id: string | null; archived_at: Date | null;
}
const contentColumns = 'id,code,kind,scope,city_id,allow_company_fallback,row_version,current_revision_id,archived_at';
function content(r: ContentRow): P03ContentBlock {
  return { id: r.id, code: r.code, kind: r.kind, scope: r.scope, cityId: r.city_id, allowCompanyFallback: r.allow_company_fallback,
    version: r.row_version, currentRevisionId: r.current_revision_id, archivedAt: isoNull(r.archived_at) };
}
/** Trusted target resolver for ID routes. Never looks up bodies, metadata or receipts. */
export async function contentTarget(client: PoolClient, id: string): Promise<P03Target> {
  const { rows } = await client.query<Pick<ContentRow, 'scope' | 'city_id'>>('SELECT scope,city_id FROM foundation.content_blocks WHERE id=$1', [id]);
  const r = found(rows[0]);
  return persistedTarget(r.scope, r.city_id);
}
function persistedTarget(scope: P03Target['scope'], cityId: string | null): P03Target {
  if (scope === 'CITY' && cityId !== null) { return { scope, cityId }; }
  if (scope === 'COMPANY' && cityId === null) { return COMPANY; }
  throw new InternalServerErrorException();
}
export async function contentIdentity(client: PoolClient, target: P03Target, id: string): Promise<P03ContentBlock> {
  const { rows } = await client.query<ContentRow>(`SELECT ${contentColumns} FROM foundation.content_blocks
    WHERE id=$1 AND scope=$2 AND city_id IS NOT DISTINCT FROM $3::uuid`, [id, target.scope, target.cityId ?? null]);
  return content(found(rows[0]));
}
export async function contentList(client: PoolClient, target: P03Target, kind: P03ContentKind | null, archived: boolean, page: Keyset<string>): Promise<P03Page<P03ContentBlock>> {
  const { rows } = await client.query<ContentRow>(`SELECT ${contentColumns} FROM foundation.content_blocks
    WHERE scope=$1 AND city_id IS NOT DISTINCT FROM $2::uuid AND ($3::text IS NULL OR kind=$3) AND ($4::bool OR archived_at IS NULL)
      AND ($5::text IS NULL OR (code COLLATE "C",id)>($5::text,$6::uuid))
    ORDER BY code COLLATE "C",id LIMIT $7`, [target.scope, target.cityId ?? null, kind, archived, page.key, page.id, page.count]);
  return page.page(rows, content, codeKey);
}
interface ContentSummaryRow extends SummaryRow { block_id: string; title: string }
const contentSummary = (r: ContentSummaryRow): P03ContentSummary => ({ ...summary(r), blockId: r.block_id, title: r.title });
export async function contentHistory(client: PoolClient, parent: P03ContentBlock, page: Keyset<number>): Promise<P03VersionedPage<P03ContentSummary>> {
  const { rows } = await client.query<ContentSummaryRow>(`SELECT id,version,block_id,title,published_at
    FROM foundation.content_block_revisions WHERE block_id=$1
      AND ($2::int IS NULL OR (version,id)<($2,$3::uuid)) ORDER BY version DESC,id DESC LIMIT $4`, [parent.id, page.key, page.id, page.count]);
  return { version: parent.version, ...page.page(rows, contentSummary, versionKey) };
}
export async function contentExact(client: PoolClient, parent: P03ContentBlock, id: string): Promise<P03ContentRevision> {
  const { rows } = await client.query<ContentSummaryRow & { body: string; source_ref: string }>(`SELECT id,version,block_id,title,published_at,body,source_ref
    FROM foundation.content_block_revisions WHERE block_id=$1 AND id=$2`, [parent.id, id]);
  const r = found(rows[0]);
  return { ...contentSummary(r), body: r.body, sourceRef: r.source_ref };
}

interface LegalRow { id: string; purpose: P03LegalPurpose; kind: P03LegalKind; row_version: number; current_version_id: string | null }
const legalColumns = 'id,purpose,kind,row_version,current_version_id';
const legal = (r: LegalRow): P03LegalDocument => ({ id: r.id, purpose: r.purpose, kind: r.kind, version: r.row_version, currentVersionId: r.current_version_id });
export async function legalIdentity(client: PoolClient, id: string): Promise<P03LegalDocument> {
  const { rows } = await client.query<LegalRow>(`SELECT ${legalColumns} FROM foundation.legal_documents
    WHERE id=$1 AND purpose=ANY($2::text[])`, [id, P03_LEGAL_PURPOSES]);
  return legal(found(rows[0]));
}
export async function legalList(client: PoolClient, purpose: P03LegalPurpose | null, kind: P03LegalKind | null, page: Keyset<string>): Promise<P03Page<P03LegalDocument>> {
  const { rows } = await client.query<LegalRow & { sort_key: string }>(`SELECT ${legalColumns}, purpose||':'||kind AS sort_key
    FROM foundation.legal_documents WHERE purpose=ANY($1::text[]) AND ($2::text IS NULL OR purpose=$2)
      AND ($3::text IS NULL OR kind=$3) AND ($4::text IS NULL OR ((purpose||':'||kind) COLLATE "C",id)>($4::text,$5::uuid))
    ORDER BY (purpose||':'||kind) COLLATE "C",id LIMIT $6`, [P03_LEGAL_PURPOSES, purpose, kind, page.key, page.id, page.count]);
  return page.page(rows, legal, r => [r.sort_key, r.id]);
}
interface LegalSummaryRow extends SummaryRow { document_id: string; title: string; checksum: string }
function legalSummary(r: LegalSummaryRow): P03LegalSummary {
  return { id: r.id, documentId: r.document_id, sequence: r.version, title: r.title, checksum: r.checksum, publishedAt: r.published_at.toISOString() };
}
export async function legalHistory(client: PoolClient, parent: P03LegalDocument, page: Keyset<number>): Promise<P03VersionedPage<P03LegalSummary>> {
  const { rows } = await client.query<LegalSummaryRow>(`SELECT id,version,document_id,title,checksum,published_at
    FROM foundation.legal_document_versions WHERE document_id=$1 AND purpose=$2 AND kind=$3
      AND ($4::int IS NULL OR (version,id)<($4,$5::uuid)) ORDER BY version DESC,id DESC LIMIT $6`,
  [parent.id, parent.purpose, parent.kind, page.key, page.id, page.count]);
  return { version: parent.version, ...page.page(rows, legalSummary, versionKey) };
}
export async function legalExact(client: PoolClient, parent: P03LegalDocument, id: string): Promise<P03LegalVersion> {
  const { rows } = await client.query<LegalSummaryRow & { body: string; legal_basis: string; source_ref: string; reviewed_by: string }>(`
    SELECT id,version,document_id,title,checksum,published_at,body,legal_basis,source_ref,reviewed_by
    FROM foundation.legal_document_versions WHERE document_id=$1 AND purpose=$2 AND kind=$3 AND id=$4`, [parent.id, parent.purpose, parent.kind, id]);
  const r = found(rows[0]);
  return { ...legalSummary(r), purpose: parent.purpose, kind: parent.kind, body: r.body, legalBasis: r.legal_basis,
    sourceRef: r.source_ref, reviewedBy: r.reviewed_by };
}
