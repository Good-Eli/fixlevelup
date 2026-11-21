/**
 * P03-03 legal documents and consent: the internal port surface.
 *
 * Every export here is a plain function over the caller's `PoolClient`. There is
 * no NestJS provider, no controller, no DI token, no authentication dependency and
 * no file upload in this module: wiring, capability policy and the public intake
 * flow belong to P03-05/P05. The caller opens the transaction and supplies the
 * trusted inputs (reviewed staff id, raw session token, explicit expiry); this
 * module never derives authority from a browser-supplied value.
 *
 * ## Transaction requirement
 *
 * The client must be inside an explicit READ COMMITTED transaction, opened on a
 * primary connection — never a read replica and never autocommit. Open it with
 * `beginLegalTransaction` (`BEGIN ISOLATION LEVEL READ COMMITTED`) as the first
 * statement of the transaction, before any data read or change: a stronger session
 * default (`default_transaction_isolation`) must not be inherited.
 *
 * `assertCallerTransaction` then runs first in every write and every locking read:
 * it sets READ COMMITTED explicitly, verifies the level the server actually reports,
 * and proves this backend is in a multi-statement transaction; see `legal-tx.ts`. A
 * transaction that already pinned a stronger snapshot is refused with the typed
 * `CONFLICT` error (PostgreSQL 25001) instead of being answered from stale state —
 * the guard never rolls back, restarts or upgrades the caller's transaction. The
 * caller owns the commit point so a domain write, its audit row and its outbox row
 * are one atomic unit; after a typed refusal the caller must ROLLBACK the whole
 * transaction and retry in a fresh one, never reuse the aborted transaction.
 *
 * ## Session proof
 *
 * Externally the only accepted proof is a raw pre-submit token plus the anchor id:
 * the port hashes the token and compares it with the stored digest. The
 * capability-like `TrustedSessionProof` brand exists for a future mandatory
 * trusted port that has already authenticated the anchor; it is deliberately not
 * exported here, so no caller can mint it by accident. Browser-supplied ids are
 * never authority.
 *
 * Lock order for consent: anchor (`request_sessions`) first, document
 * (`legal_documents`) second, always through these ports.
 */
export {
  CONSENT_FORM_KIND, CONSENT_SOURCE, LEGAL_DOCUMENT_KINDS, LEGAL_PURPOSES, LegalPortError,
} from './legal-contract.js';
export type {
  ConsentReceipt, ConsentAction, CreateLegalDocumentInput, CreateRequestSessionInput, CurrentConsent,
  CurrentConsentQuery, CurrentConsentReason, LegalDocumentKind, LegalDocumentReceipt, LegalDocumentVersionReceipt,
  LegalDocumentVersionView, LegalDocumentView, LegalErrorCode, LegalPurpose, LegalSqlClient,
  PublishLegalDocumentVersionInput, RawTokenSessionProof, RequestSessionReceipt, RequestSessionRevocation,
  SessionProof,
} from './legal-contract.js';

export {
  createLegalDocument, findLegalDocument, listLegalDocuments, publishLegalDocumentVersion, readCurrentLegalDocument,
  readLegalDocument,
} from './legal-documents.js';

export {
  anchorState, assertAnchorLiveAfterLock, createRequestSession, lockRequestSession, readRequestSession,
  requireAnchorProof, requireLiveAnchor, revokeRequestSession,
} from './legal-sessions.js';
export type { AnchorState, RequestSessionRow } from './legal-sessions.js';

export {
  currentPurposeConsent, listSessionConsent, recordConsentGiven, recordConsentRevoked,
} from './legal-consent.js';

export { hashSessionSecret, sessionSecretMatches, sha256Hex } from './legal-hash.js';
export {
  LEGAL_BEGIN_SQL, LEGAL_ISOLATION_PROBE_SQL, LEGAL_ISOLATION_SQL, LEGAL_REQUIRED_ISOLATION,
  LEGAL_TX_SETTING, assertCallerTransaction, beginLegalTransaction,
} from './legal-tx.js';
export type { LegalAuditDetails, LegalAuditOperation } from './legal-audit.js';
