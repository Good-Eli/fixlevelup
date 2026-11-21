/**
 * Canonical hashing for the file-upload reservation ports.
 *
 * Two digests are needed and they mean different things:
 *
 * - `filePolicySha256` is the SHA-256 of the *canonical policy snapshot*: the
 *   closed typed fields of the reviewed policy version, with the MIME allowlist
 *   sorted and a fixed field order. It is stored on every intent so the exact
 *   policy a reservation was made under can be re-proven later. It never contains
 *   a session token, a legal text, a name or any other raw PII.
 * - `fileIntentBodySha256` is the SHA-256 of the *canonical idempotency payload*:
 *   policy version id + policy hash + declared MIME/bytes + expiry + exact consent
 *   basis + idempotency key. Two reserve calls with the same owner and key are the
 *   same request only if this digest matches; the digest is computed by the
 *   server, never supplied by a caller, and is not returned in any DTO.
 *
 * A hash is integrity evidence, never a permission: matching digests do not grant
 * anything, they only prove the payload is unchanged.
 *
 * The JSON form is canonical because it is built from a fixed literal order with
 * sorted arrays — `JSON.stringify` preserves that order, so equal snapshots always
 * produce equal bytes and therefore equal digests.
 */
import { sha256Hex } from '../../settings/legal/legal-hash.js';
import type { FileMimeType, FileReservationPurpose } from './contract.js';

/** The exact policy fields that are hashed, already normalised (Dates as ISO). */
export interface CanonicalFilePolicySnapshot {
  readonly versionId: string;
  readonly sourceRef: string;
  readonly allowedMimeTypes: readonly FileMimeType[];
  readonly maxFileBytes: number;
  readonly maxOwnerBytes: number;
  readonly maxOwnerFiles: number;
  /** `policy.expiresAt` as an ISO-8601 UTC string. */
  readonly policyExpiresAt: string;
}

/** Deterministic canonical JSON of one policy snapshot. */
export function canonicalFilePolicy(snapshot: CanonicalFilePolicySnapshot): string {
  return JSON.stringify({
    allowedMimeTypes: [...snapshot.allowedMimeTypes].sort(),
    maxFileBytes: snapshot.maxFileBytes,
    maxOwnerBytes: snapshot.maxOwnerBytes,
    maxOwnerFiles: snapshot.maxOwnerFiles,
    policyExpiresAt: snapshot.policyExpiresAt,
    sourceRef: snapshot.sourceRef,
    versionId: snapshot.versionId,
  });
}

/** SHA-256 (lowercase hex) of the canonical policy snapshot. */
export function filePolicySha256(snapshot: CanonicalFilePolicySnapshot): string {
  return sha256Hex(canonicalFilePolicy(snapshot));
}

/** The exact idempotency payload of one reserve request. */
export interface CanonicalFileIntentPayload {
  readonly consentDocumentVersionId: string;
  readonly consentEvidenceId: string;
  readonly consentPurpose: FileReservationPurpose;
  readonly declaredBytes: number;
  readonly declaredMime: FileMimeType;
  /** `expiresAt` as an ISO-8601 UTC string. */
  readonly expiresAt: string;
  readonly idempotencyKey: string;
  readonly policySha256: string;
  readonly policyVersionId: string;
}

/** Deterministic canonical JSON of the idempotency payload (fixed field order). */
export function canonicalFileIntentPayload(payload: CanonicalFileIntentPayload): string {
  return JSON.stringify({
    consentDocumentVersionId: payload.consentDocumentVersionId,
    consentEvidenceId: payload.consentEvidenceId,
    consentPurpose: payload.consentPurpose,
    declaredBytes: payload.declaredBytes,
    declaredMime: payload.declaredMime,
    expiresAt: payload.expiresAt,
    idempotencyKey: payload.idempotencyKey,
    policySha256: payload.policySha256,
    policyVersionId: payload.policyVersionId,
  });
}

/** SHA-256 (lowercase hex) of the canonical idempotency payload. */
export function fileIntentBodySha256(payload: CanonicalFileIntentPayload): string {
  return sha256Hex(canonicalFileIntentPayload(payload));
}
