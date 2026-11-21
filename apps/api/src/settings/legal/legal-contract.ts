/**
 * P03-03 legal documents and consent evidence: shared internal contract.
 *
 * This module is a set of typed, transaction-scoped ports over a caller-owned
 * PostgreSQL transaction. It deliberately contains no NestJS provider, no HTTP
 * route, no DI token, no authentication/authorization dependency and no file
 * upload: P03-05/P05 own the staff and public surfaces, capability policy and
 * request submission. Every function receives the caller's `PoolClient`, so the
 * caller decides when to BEGIN/COMMIT/ROLLBACK and every audit/outbox row is
 * written in that same transaction.
 *
 * Three purpose-separated facts live here:
 *
 * - `legal_documents` / `legal_document_versions`: company-wide immutable legal
 *   text. A purpose may have several documents (a POLICY, the CONSENT_FORM that
 *   the person actually accepts, an OPT_IN_NOTICE); only a CONSENT_FORM can back
 *   a GIVEN event. Publishing is insert-revision + CAS pointer move.
 * - `request_sessions`: the minimal pre-submit anchor. It stores only a SHA-256
 *   secret hash, the intake city/version and an explicit caller-supplied expiry;
 *   there is no default TTL, no name/phone/address/request/customer column and no
 *   raw secret. Issuing the raw token once is the caller's job; this module only
 *   ever accepts the hash for creation and verifies a presented raw token against
 *   it (or a capability-like trusted server proof) for evidence operations.
 * - `consent_records`: append-only GIVEN/REVOKED evidence. GIVEN requires an
 *   exactly `true` acceptance, a live anchor and the *current* CONSENT_FORM
 *   version; REVOKED supersedes one exact GIVEN event and never erases history.
 *
 * Nothing here decides whether a purpose is legally required or what a document
 * must say: Q02/Q13 and the approved legal review own the text and the intake
 * policy. This is a technical contract, not a legal opinion.
 */
import type { PoolClient } from 'pg';

/** Purpose vocabulary is closed: a consent for one purpose never authorizes another. */
export const LEGAL_PURPOSES = ['REQUEST_PROCESSING', 'ADDRESS_COVERAGE', 'MARKETING'] as const;
export type LegalPurpose = (typeof LEGAL_PURPOSES)[number];

/** A purpose can carry a policy and the actual consent form as separate documents. */
export const LEGAL_DOCUMENT_KINDS = ['POLICY', 'CONSENT_FORM', 'OPT_IN_NOTICE'] as const;
export type LegalDocumentKind = (typeof LEGAL_DOCUMENT_KINDS)[number];

/** The only document kind that can back a GIVEN event. */
export const CONSENT_FORM_KIND: LegalDocumentKind = 'CONSENT_FORM';

/** The only evidence source modelled in this sub-step. */
export const CONSENT_SOURCE = 'FORM' as const;

export type ConsentAction = 'GIVEN' | 'REVOKED';

/**
 * Minimal `PoolClient` surface: exactly `query`, so the caller's transaction is
 * the only connection this module can use. `pg.PoolClient` satisfies it directly.
 */
export type LegalSqlClient = Pick<PoolClient, 'query'>;

/**
 * Typed refusal codes. The message is the code itself, so a failure can never
 * echo submitted text, a body, a legal basis or a secret into a log or response.
 */
export type LegalErrorCode =
  | 'INVALID_INPUT'
  | 'NOT_FOUND'
  | 'ALREADY_EXISTS'
  | 'STALE_VERSION'
  | 'INVALID_REFERENCE'
  | 'DOCUMENT_NOT_PUBLISHED'
  | 'DOCUMENT_NOT_CURRENT'
  | 'KIND_NOT_CONSENT_FORM'
  | 'SESSION_EXPIRED'
  | 'SESSION_REVOKED'
  | 'REPLAY_MISMATCH'
  | 'CONSENT_REVOKED'
  | 'CONSENT_ALREADY_ACTIVE'
  | 'CONFLICT';

export class LegalPortError extends Error {
  readonly code: LegalErrorCode;

  constructor(code: LegalErrorCode) {
    super(code);
    this.name = 'LegalPortError';
    this.code = code;
  }
}

/** Projection of the stable document identity. Contains no legal text. */
export interface LegalDocumentView {
  readonly id: string;
  readonly purpose: LegalPurpose;
  readonly kind: LegalDocumentKind;
  readonly version: number;
  readonly currentVersionId: string | null;
}

/** Immutable reviewed revision. Only the internal read port returns `body`. */
export interface LegalDocumentVersionView {
  readonly id: string;
  readonly documentId: string;
  readonly purpose: LegalPurpose;
  readonly kind: LegalDocumentKind;
  readonly sequence: number;
  readonly title: string;
  readonly body: string;
  readonly checksum: string;
  readonly legalBasis: string;
  readonly sourceRef: string;
  readonly reviewedBy: string;
  readonly publishedAt: string;
}

export interface LegalDocumentReceipt {
  readonly documentId: string;
  readonly purpose: LegalPurpose;
  readonly kind: LegalDocumentKind;
  /** `legal_documents.row_version` after creation. */
  readonly version: number;
}

export interface LegalDocumentVersionReceipt {
  readonly documentId: string;
  readonly versionId: string;
  readonly purpose: LegalPurpose;
  readonly kind: LegalDocumentKind;
  /** Monotonic revision number of the document (`legal_document_versions.version`). */
  readonly sequence: number;
  /** SHA-256 of the exact UTF-8 body, also enforced by the database. */
  readonly checksum: string;
  /** `legal_documents.row_version` after the CAS pointer move. */
  readonly version: number;
}

/**
 * Anchor receipt. It carries identifiers and database timestamps only: the raw
 * secret is issued once by the caller, never returned or stored here.
 */
export interface RequestSessionReceipt {
  readonly sessionId: string;
  readonly createdAt: string;
  readonly expiresAt: string;
}

export interface RequestSessionRevocation {
  readonly sessionId: string;
  readonly revokedAt: string;
  /** True when the session was already revoked; the first revoke is not repeated. */
  readonly replayed: boolean;
}

export interface ConsentReceipt {
  readonly evidenceId: string;
  readonly sessionId: string;
  readonly documentId: string;
  readonly documentVersionId: string;
  readonly purpose: LegalPurpose;
  readonly action: ConsentAction;
  /** Database clock value, never a caller-supplied timestamp. */
  readonly occurredAt: string;
  readonly replayed: boolean;
}

export type CurrentConsentReason =
  | 'GRANTED'
  | 'SESSION_EXPIRED'
  | 'SESSION_REVOKED'
  | 'DOCUMENT_NOT_PUBLISHED'
  | 'DOCUMENT_NOT_CURRENT'
  | 'NOT_GIVEN'
  | 'REVOKED';

/**
 * Current-consent answer. A refusal is a typed value, not an exception, so an
 * intake caller can render the exact missing consent without guessing.
 */
export interface CurrentConsent {
  readonly granted: boolean;
  readonly reason: CurrentConsentReason;
  readonly documentId: string | null;
  readonly documentVersionId: string | null;
  readonly evidenceId: string | null;
  readonly occurredAt: string | null;
}

/**
 * A raw pre-submit session token presented by the server-side caller together
 * with the anchor id. The module hashes the token and compares it with the stored
 * hash; a browser-supplied UUID alone is never sufficient.
 */
export interface RawTokenSessionProof {
  readonly sessionId: string;
  readonly token: string;
}

const TRUSTED_SESSION_PROOF = Symbol('fixlevelup.legal.trusted-session');

/**
 * Capability-like proof for an internal caller that already authenticated the
 * anchor through another mandatory port (P03-05/P05). The brand is a module-local
 * symbol, so it cannot be produced by JSON or by a plain `{sessionId}` object; it
 * exists only for trusted server code that deliberately constructs it.
 *
 * NOT part of the public `index.ts` surface: a caller that can mint this proof
 * would bypass the token check, so no capability issuer exists yet. Until P03-05
 * defines one, external callers use `RawTokenSessionProof` only.
 */
export interface TrustedSessionProof {
  readonly sessionId: string;
  readonly [TRUSTED_SESSION_PROOF]: true;
}

export function trustedSessionProof(sessionId: string): TrustedSessionProof {
  return Object.freeze({ sessionId, [TRUSTED_SESSION_PROOF]: true as const });
}

export function isTrustedSessionProof(value: unknown): value is TrustedSessionProof {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<PropertyKey, unknown>;
  return record[TRUSTED_SESSION_PROOF] === true;
}

export type SessionProof = RawTokenSessionProof | TrustedSessionProof;

/* ----------------------------- write inputs ----------------------------- */

export interface CreateLegalDocumentInput {
  readonly purpose: LegalPurpose;
  readonly kind: LegalDocumentKind;
}

export interface PublishLegalDocumentVersionInput {
  readonly documentId: string;
  /** CAS token: `legal_documents.row_version` the caller last read. */
  readonly expectedVersion: number;
  readonly title: string;
  readonly body: string;
  readonly legalBasis: string;
  readonly sourceRef: string;
  /** Reviewed staff member; the caller's authorization is an external port. */
  readonly reviewedBy: string;
}

export interface CreateRequestSessionInput {
  /** Lowercase SHA-256 hex of the raw token; the raw token never reaches this port. */
  readonly secretHash: string;
  readonly intakeCityId: string;
  readonly intakeCityVersionId: string;
  /** Explicit trusted-policy expiry. There is no default TTL. */
  readonly expiresAt: Date | string;
}

export interface ConsentGivenInput {
  readonly session: SessionProof;
  readonly purpose: LegalPurpose;
  /** Optional explicit document; omitted means "the current CONSENT_FORM of the purpose". */
  readonly documentId?: string;
  /**
   * The exact CONSENT_FORM revision the person was shown and accepted. Required:
   * the port compares it with the document's current revision and refuses
   * `DOCUMENT_NOT_CURRENT` instead of silently recording the newer text.
   */
  readonly documentVersionId: string;
  readonly evidenceRef: string;
  readonly accepted: boolean;
}

export interface ConsentRevokeInput {
  readonly session: SessionProof;
  readonly purpose: LegalPurpose;
  readonly evidenceRef: string;
  /** Exactly one GIVEN event of the same session/purpose/document/version. */
  readonly supersedesEvidenceId: string;
}

export interface CurrentConsentQuery {
  readonly session: SessionProof;
  readonly purpose: LegalPurpose;
}
