/**
 * Bounded runtime validation for the P03-03 legal ports.
 *
 * The ports are internal, but "internal" is not a licence to trust a shape: every
 * value that can originate from an HTTP body or a caller's JSON is re-narrowed
 * here, unknown keys are rejected, and every string/quantity has a hard bound.
 * Database CHECK/trigger rules remain authoritative for cross-row rules (same
 * purpose, kind equality, checksum, live anchor); this file only keeps malformed
 * input out of SQL and out of logs.
 *
 * Failures are bare `LegalPortError('INVALID_INPUT')` with no submitted value in
 * the message, so a validation error can never leak a body, a legal basis or a
 * raw session token.
 */
import { LegalPortError } from './legal-contract.js';
import type {
  CreateLegalDocumentInput,
  LegalDocumentKind, LegalPurpose, PublishLegalDocumentVersionInput, SessionProof,
} from './legal-contract.js';
import { isTrustedSessionProof, trustedSessionProof } from './legal-contract.js';

/** Quantity and size bounds that the schema itself cannot express. */
export const MAX_TITLE = 300;
export const MAX_BODY = 200_000;
export const MAX_LEGAL_BASIS = 4_000;
export const MAX_SOURCE_REF = 500;
export const MAX_TOKEN = 512;
export const MIN_TOKEN = 16;
export const MAX_LIST_DOCUMENTS = 200;
export const DEFAULT_LIST_DOCUMENTS = 50;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const TOKEN = /^[A-Za-z0-9_-]{16,512}$/;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/;

const PURPOSES: readonly LegalPurpose[] = ['REQUEST_PROCESSING', 'ADDRESS_COVERAGE', 'MARKETING'];
const KINDS: readonly LegalDocumentKind[] = ['POLICY', 'CONSENT_FORM', 'OPT_IN_NOTICE'];

function invalid(): never {
  throw new LegalPortError('INVALID_INPUT');
}

function object(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    invalid();
  }
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!allowed.includes(key)) {
      invalid();
    }
  }
  return record;
}

/** Non-blank and within the bound; the stored value is preserved verbatim. */
function requiredText(record: Record<string, unknown>, key: string, max: number): string {
  const value = record[key];
  if (typeof value !== 'string' || value.length === 0 || value.length > max || !/\S/.test(value)) {
    invalid();
  }
  return value;
}

export function uuidValue(value: unknown): string {
  if (typeof value !== 'string' || !UUID.test(value)) {
    invalid();
  }
  return value.toLowerCase();
}

export function purposeValue(value: unknown): LegalPurpose {
  if (typeof value !== 'string' || !PURPOSES.includes(value as LegalPurpose)) {
    invalid();
  }
  return value as LegalPurpose;
}

export function kindValue(value: unknown): LegalDocumentKind {
  if (typeof value !== 'string' || !KINDS.includes(value as LegalDocumentKind)) {
    invalid();
  }
  return value as LegalDocumentKind;
}

export function limitValue(value: unknown): number {
  if (value === undefined) {
    return DEFAULT_LIST_DOCUMENTS;
  }
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > MAX_LIST_DOCUMENTS) {
    invalid();
  }
  return value;
}

function requiredSha256(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== 'string' || !SHA256_HEX.test(value)) {
    invalid();
  }
  return value;
}

function requiredTimestamp(record: Record<string, unknown>, key: string): Date {
  const value = record[key];
  const date = value instanceof Date ? value : typeof value === 'string' && ISO_TIMESTAMP.test(value) ? new Date(value) : null;
  if (date === null || Number.isNaN(date.getTime())) {
    invalid();
  }
  return date;
}

function requiredEvidenceRef(record: Record<string, unknown>, key: string): string {
  return uuidValue(record[key]);
}

function requiredTrue(record: Record<string, unknown>, key: string): true {
  // Strict identity: the string 'true', 1 and other truthy values are refused
  // rather than coerced, so acceptance is always an explicit JSON boolean.
  if (record[key] !== true) {
    invalid();
  }
  return true;
}

/** Session proof: a presented raw token, or a capability-like trusted server proof. */
export function sessionProofInput(value: unknown): SessionProof {
  if (isTrustedSessionProof(value)) {
    const record = value as unknown as Record<string, unknown>;
    return trustedSessionProof(uuidValue(record['sessionId']));
  }
  const record = object(value, ['sessionId', 'token']);
  const token = record['token'];
  if (typeof token !== 'string' || !TOKEN.test(token)) {
    invalid();
  }
  return { sessionId: uuidValue(record['sessionId']), token };
}

export function documentCreateInput(value: unknown): CreateLegalDocumentInput {
  const record = object(value, ['purpose', 'kind']);
  return { purpose: purposeValue(record['purpose']), kind: kindValue(record['kind']) };
}

export function documentVersionInput(value: unknown): PublishLegalDocumentVersionInput {
  const record = object(value, ['documentId', 'expectedVersion', 'title', 'body', 'legalBasis', 'sourceRef', 'reviewedBy']);
  const expectedVersion = record['expectedVersion'];
  if (typeof expectedVersion !== 'number' || !Number.isSafeInteger(expectedVersion) || expectedVersion < 1) {
    invalid();
  }
  return {
    documentId: uuidValue(record['documentId']),
    expectedVersion,
    title: requiredText(record, 'title', MAX_TITLE),
    // The body is preserved exactly: the checksum is taken over these bytes and the
    // database re-computes it, so trimming here would silently change reviewed text.
    body: requiredText(record, 'body', MAX_BODY),
    legalBasis: requiredText(record, 'legalBasis', MAX_LEGAL_BASIS),
    sourceRef: requiredText(record, 'sourceRef', MAX_SOURCE_REF),
    reviewedBy: uuidValue(record['reviewedBy']),
  };
}

/** Normalised anchor input: the timestamp is a real `Date`, never a raw string. */
export interface ParsedRequestSessionInput {
  readonly secretHash: string;
  readonly intakeCityId: string;
  readonly intakeCityVersionId: string;
  readonly expiresAt: Date;
}

export function requestSessionInput(value: unknown): ParsedRequestSessionInput {
  const record = object(value, ['secretHash', 'intakeCityId', 'intakeCityVersionId', 'expiresAt']);
  return {
    secretHash: requiredSha256(record, 'secretHash'),
    intakeCityId: uuidValue(record['intakeCityId']),
    intakeCityVersionId: uuidValue(record['intakeCityVersionId']),
    // Required, never defaulted: an absent TTL is a caller bug, not an implicit policy.
    expiresAt: requiredTimestamp(record, 'expiresAt'),
  };
}

export interface ParsedConsentGiven {
  readonly session: SessionProof;
  readonly purpose: LegalPurpose;
  readonly documentId: string | null;
  readonly documentVersionId: string;
  readonly evidenceRef: string;
  readonly accepted: true;
}

export function consentGivenInput(value: unknown): ParsedConsentGiven {
  const record = object(value, ['session', 'purpose', 'documentId', 'documentVersionId', 'evidenceRef', 'accepted']);
  const documentId = record['documentId'];
  return {
    session: sessionProofInput(record['session']),
    purpose: purposeValue(record['purpose']),
    documentId: documentId === undefined ? null : uuidValue(documentId),
    // The accepted revision is mandatory: without it the port could silently
    // upgrade a stale acceptance to the newly published text.
    documentVersionId: uuidValue(record['documentVersionId']),
    evidenceRef: requiredEvidenceRef(record, 'evidenceRef'),
    accepted: requiredTrue(record, 'accepted'),
  };
}

export interface ParsedConsentRevoke {
  readonly session: SessionProof;
  readonly purpose: LegalPurpose;
  readonly evidenceRef: string;
  readonly supersedesEvidenceId: string;
}

export function consentRevokeInput(value: unknown): ParsedConsentRevoke {
  const record = object(value, ['session', 'purpose', 'evidenceRef', 'supersedesEvidenceId']);
  return {
    session: sessionProofInput(record['session']),
    purpose: purposeValue(record['purpose']),
    evidenceRef: requiredEvidenceRef(record, 'evidenceRef'),
    supersedesEvidenceId: requiredEvidenceRef(record, 'supersedesEvidenceId'),
  };
}

export interface ParsedCurrentConsentQuery {
  readonly session: SessionProof;
  readonly purpose: LegalPurpose;
}

export function currentConsentInput(value: unknown): ParsedCurrentConsentQuery {
  const record = object(value, ['session', 'purpose']);
  return { session: sessionProofInput(record['session']), purpose: purposeValue(record['purpose']) };
}

/**
 * The parser return types are checked against the public port inputs at every
 * call site: a field added to a contract input without a matching parser entry
 * stops compiling, and an unknown-key allowlist entry is reviewed explicitly.
 */
