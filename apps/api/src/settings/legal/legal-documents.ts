/**
 * Legal document identity, immutable revisions and the CAS publish pointer.
 *
 * `legal_documents` is the stable company-wide identity of one purpose-specific
 * document; `legal_document_versions` is append-only reviewed text. Publishing is
 * exactly two writes on the caller's transaction: insert the next immutable
 * revision, then move the current pointer with a compare-and-swap on
 * `legal_documents.row_version`. A stale expected version is refused, never
 * silently rebased, so two publishers cannot both claim "the" current text.
 *
 * The SHA-256 checksum is computed over the exact UTF-8 body and is re-computed by
 * the database on insert, which is what makes "the stored revision is the reviewed
 * text" checkable later. Nothing in this file returns a version that the caller
 * did not just publish, and the audit/outbox rows are written last in the same
 * transaction: if they fail, the revision and pointer move roll back too.
 */
import { randomUUID } from 'node:crypto';
import { LegalPortError } from './legal-contract.js';
import type {
  CreateLegalDocumentInput, LegalDocumentKind, LegalDocumentReceipt, LegalDocumentVersionReceipt,
  LegalDocumentVersionView, LegalDocumentView, LegalPurpose, LegalSqlClient, PublishLegalDocumentVersionInput,
} from './legal-contract.js';
import { writeLegalAudit } from './legal-audit.js';
import { guard } from './legal-errors.js';
import { sha256Hex } from './legal-hash.js';
import { documentCreateInput, documentVersionInput, kindValue, limitValue, purposeValue, uuidValue } from './legal-input.js';
import { assertCallerTransaction } from './legal-tx.js';

type LegalDocumentRow = {
  id: string; purpose: string; kind: string; row_version: number; current_version_id: string | null;
};

type LegalDocumentVersionRow = {
  id: string; document_id: string; purpose: string; kind: string; version: number; title: string; body: string;
  checksum: string; legal_basis: string; source_ref: string; reviewed_by: string; published_at: Date;
};

const DOCUMENT_COLUMNS = 'id,purpose,kind,row_version,current_version_id';
const VERSION_COLUMNS = 'id,document_id,purpose,kind,version,title,body,checksum,legal_basis,source_ref,reviewed_by,published_at';
const JOINED_VERSION_COLUMNS = VERSION_COLUMNS.split(',').map((column) => `v.${column}`).join(',');

function documentView(row: LegalDocumentRow): LegalDocumentView {
  return {
    id: row.id,
    // The migration CHECK constrains the closed vocabulary; no caller value is echoed.
    purpose: row.purpose as LegalPurpose,
    kind: row.kind as LegalDocumentKind,
    version: row.row_version,
    currentVersionId: row.current_version_id,
  };
}

function versionView(row: LegalDocumentVersionRow): LegalDocumentVersionView {
  return {
    id: row.id,
    documentId: row.document_id,
    purpose: row.purpose as LegalPurpose,
    kind: row.kind as LegalDocumentKind,
    sequence: row.version,
    title: row.title,
    body: row.body,
    checksum: row.checksum,
    legalBasis: row.legal_basis,
    sourceRef: row.source_ref,
    reviewedBy: row.reviewed_by,
    publishedAt: row.published_at.toISOString(),
  };
}

/**
 * Creates the stable document identity for one purpose/kind pair. The unique
 * `(purpose,kind)` index is the authority: a second POLICY or CONSENT_FORM for the
 * same purpose is `ALREADY_EXISTS`, never a silent duplicate. No revision exists
 * yet, so the pointer stays NULL until the first publish.
 *
 * Known limitation (deliberate, P03-05): the document identity has no `created_by`
 * column and this port takes no actor, so the audit row names the document, purpose
 * and kind but not "who created it". Adding an actor parameter here would invent an
 * authorization/attribution contract that belongs to the P03-05 staff command; the
 * first actor-attributed event is the reviewed revision publish, which records
 * `reviewedBy`. The caller of this port is the trusted internal command.
 */
export async function createLegalDocument(
  client: LegalSqlClient, input: CreateLegalDocumentInput,
): Promise<LegalDocumentReceipt> {
  const parsed = documentCreateInput(input);
  await assertCallerTransaction(client);
  const result = await guard(() => client.query<LegalDocumentRow>(
    `INSERT INTO foundation.legal_documents (id,purpose,kind) VALUES ($1,$2,$3)
     RETURNING ${DOCUMENT_COLUMNS}`,
    [randomUUID(), parsed.purpose, parsed.kind],
  ));
  const row = result.rows[0];
  if (!row) {
    throw new LegalPortError('CONFLICT');
  }
  await writeLegalAudit(client, 'LEGAL_DOCUMENT_CREATED', {
    documentId: row.id, purpose: parsed.purpose, kind: parsed.kind,
  });
  return { documentId: row.id, purpose: parsed.purpose, kind: parsed.kind, version: row.row_version };
}

/**
 * Publishes one immutable revision and moves the current pointer with CAS.
 *
 * The document row is locked first, so concurrent publishes serialize and the
 * `version` sequence cannot collide. `kind` and `purpose` are taken from the
 * locked parent, never from the input: a revision can never disagree with its
 * document, which is also enforced by the database composite FK.
 */
export async function publishLegalDocumentVersion(
  client: LegalSqlClient, input: PublishLegalDocumentVersionInput,
): Promise<LegalDocumentVersionReceipt> {
  const parsed = documentVersionInput(input);
  const checksum = sha256Hex(parsed.body);
  await assertCallerTransaction(client);
  const locked = await guard(() => client.query<LegalDocumentRow>(
    `SELECT ${DOCUMENT_COLUMNS} FROM foundation.legal_documents WHERE id=$1 FOR UPDATE`,
    [parsed.documentId],
  ));
  const document = locked.rows[0];
  if (!document) {
    throw new LegalPortError('NOT_FOUND');
  }
  if (document.row_version !== parsed.expectedVersion) {
    throw new LegalPortError('STALE_VERSION');
  }
  const inserted = await guard(() => client.query<{ id: string; version: number; checksum: string }>(
    `INSERT INTO foundation.legal_document_versions
       (id,document_id,purpose,kind,version,title,body,checksum,legal_basis,source_ref,reviewed_by)
     SELECT $1,d.id,d.purpose,d.kind,
            COALESCE((SELECT max(v.version) FROM foundation.legal_document_versions v WHERE v.document_id=d.id),0)+1,
            $3,$4,$5,$6,$7,$8
     FROM foundation.legal_documents d WHERE d.id=$2
     RETURNING id,version,checksum`,
    [randomUUID(), parsed.documentId, parsed.title, parsed.body, checksum, parsed.legalBasis, parsed.sourceRef,
      parsed.reviewedBy],
  ));
  const revision = inserted.rows[0];
  if (!revision) {
    throw new LegalPortError('CONFLICT');
  }
  const moved = await guard(() => client.query<{ row_version: number }>(
    `UPDATE foundation.legal_documents SET current_version_id=$2
     WHERE id=$1 AND row_version=$3 RETURNING row_version`,
    [parsed.documentId, revision.id, parsed.expectedVersion],
  ));
  const pointer = moved.rows[0];
  if (!pointer) {
    throw new LegalPortError('STALE_VERSION');
  }
  await writeLegalAudit(client, 'LEGAL_DOCUMENT_VERSION_PUBLISHED', {
    documentId: parsed.documentId,
    purpose: document.purpose,
    kind: document.kind,
    versionId: revision.id,
    sequence: revision.version,
    reviewedBy: parsed.reviewedBy,
  });
  return {
    documentId: parsed.documentId,
    versionId: revision.id,
    purpose: document.purpose as LegalPurpose,
    kind: document.kind as LegalDocumentKind,
    sequence: revision.version,
    checksum: revision.checksum,
    version: pointer.row_version,
  };
}

/** One stable document identity, or null. Read-only, no lock. */
export async function readLegalDocument(client: LegalSqlClient, documentId: string): Promise<LegalDocumentView | null> {
  const id = uuidValue(documentId);
  const result = await guard(() => client.query<LegalDocumentRow>(
    `SELECT ${DOCUMENT_COLUMNS} FROM foundation.legal_documents WHERE id=$1`, [id],
  ));
  const row = result.rows[0];
  return row ? documentView(row) : null;
}

/** The stable identity of one purpose/kind pair, or null. */
export async function findLegalDocument(
  client: LegalSqlClient, purpose: LegalPurpose, kind: LegalDocumentKind,
): Promise<LegalDocumentView | null> {
  const result = await guard(() => client.query<LegalDocumentRow>(
    `SELECT ${DOCUMENT_COLUMNS} FROM foundation.legal_documents WHERE purpose=$1 AND kind=$2`,
    [purposeValue(purpose), kindValue(kind)],
  ));
  const row = result.rows[0];
  return row ? documentView(row) : null;
}

/** The immutable revision the current pointer names, or null when unpublished. */
export async function readCurrentLegalDocument(
  client: LegalSqlClient, purpose: LegalPurpose, kind: LegalDocumentKind,
): Promise<LegalDocumentVersionView | null> {
  const result = await guard(() => client.query<LegalDocumentVersionRow>(
    `SELECT ${JOINED_VERSION_COLUMNS}
     FROM foundation.legal_documents d
     JOIN foundation.legal_document_versions v ON v.id=d.current_version_id AND v.document_id=d.id
     WHERE d.purpose=$1 AND d.kind=$2`,
    [purposeValue(purpose), kindValue(kind)],
  ));
  const row = result.rows[0];
  return row ? versionView(row) : null;
}

/**
 * Bounded read of the stable identities. The internal caller decides the page
 * size (1..200) so an accidental unbounded list cannot be introduced later.
 */
export async function listLegalDocuments(
  client: LegalSqlClient, limit?: number,
): Promise<readonly LegalDocumentView[]> {
  const result = await guard(() => client.query<LegalDocumentRow>(
    `SELECT ${DOCUMENT_COLUMNS} FROM foundation.legal_documents ORDER BY purpose,kind LIMIT $1`,
    [limitValue(limit)],
  ));
  return result.rows.map(documentView);
}
