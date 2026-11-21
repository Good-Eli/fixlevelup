import type { FileMimeType, FileOwnerSessionProof, FileReservationErrorCode } from '../reservations/index.js';

export interface UploadOperationalPolicy {
  readonly mode: 'local-synthetic';
  readonly maxAttemptsPerOwner: number;
  readonly maxPhysicalBytesPerOwner: number;
  readonly maxLiveOperationsPerOwner: number;
  readonly leaseMs: number;
  readonly prefixTimeoutMs: number;
  readonly maxSourceChunkBytes: number;
  readonly allowedMimeTypes: readonly FileMimeType[];
}

export interface UploadReservedFileCommand {
  readonly session: FileOwnerSessionProof;
  readonly intentId: string;
  readonly idempotencyKey: string;
  readonly body: (signal: AbortSignal) => AsyncIterable<Uint8Array>;
  readonly signal: AbortSignal;
}

export interface UploadQuarantineReceipt {
  readonly intentId: string;
  readonly quarantineId: string;
  readonly state: 'QUARANTINED';
  readonly replayed: boolean;
}

export type UploadCoordinatorErrorCode = FileReservationErrorCode
  | 'ATTEMPT_ACTIVE' | 'ATTEMPT_FAILED' | 'WRITE_OUTCOME_UNKNOWN' | 'ALREADY_QUARANTINED'
  | 'ATTEMPT_BUDGET_EXCEEDED' | 'PHYSICAL_BUDGET_EXCEEDED' | 'LIVE_OPERATION_LIMIT'
  | 'SIGNATURE_MISMATCH' | 'SOURCE_FAILED' | 'ABORTED' | 'STALE_ATTEMPT';

export class UploadCoordinatorError extends Error {
  readonly code: UploadCoordinatorErrorCode;

  constructor(code: UploadCoordinatorErrorCode) {
    super(code);
    this.name = 'UploadCoordinatorError';
    this.code = code;
  }
}

const internalErrors = new WeakSet<object>();

export function uploadError(code: UploadCoordinatorErrorCode): UploadCoordinatorError {
  const error = new UploadCoordinatorError(code);
  internalErrors.add(error);
  return error;
}

export function isUploadError(error: unknown): error is UploadCoordinatorError {
  return typeof error === 'object' && error !== null && internalErrors.has(error);
}

export function refuse(code: UploadCoordinatorErrorCode): never {
  throw uploadError(code);
}

export type AttemptState = 'REGISTERED' | 'IN_FLIGHT' | 'FAILED_NOBYTES' | 'VERIFIED' | 'UNKNOWN';
export type ObservationKind = 'PRESENT' | 'NOT_OBSERVED' | 'INDETERMINATE';
export type VerifiedContent = { readonly actualBytes: number; readonly sha256: string };
export type Observation = ({ readonly kind: 'PRESENT' } & VerifiedContent)
  | { readonly kind: 'NOT_OBSERVED' | 'INDETERMINATE' };
export interface UploadReconcileCommand {
  readonly limit: number;
  readonly signal: AbortSignal;
}
export interface UploadReconcileSummary {
  readonly retiredWithoutPut: number;
  readonly retiredUnknown: number;
  readonly present: number;
  readonly notObserved: number;
  readonly indeterminate: number;
  readonly skipped: number;
}
