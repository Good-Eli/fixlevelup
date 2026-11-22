import type { FileReservationErrorCode } from '../reservations/index.js';

export type FileLifecycleErrorCode = FileReservationErrorCode
  | 'NOT_READY' | 'UNSUPPORTED_FORMAT' | 'PROCESSING_ACTIVE' | 'PROCESSING_DENIED'
  | 'WRITE_OUTCOME_UNKNOWN' | 'STALE_CLAIM' | 'TICKET_CLOSED' | 'ACCESS_LIMIT' | 'ABORTED'
  | 'ATTEMPT_BUDGET_EXCEEDED' | 'PHYSICAL_BUDGET_EXCEEDED' | 'LIVE_OPERATION_LIMIT';

export class FileLifecycleError extends Error {
  readonly code: FileLifecycleErrorCode;

  constructor(code: FileLifecycleErrorCode) {
    super(code);
    this.name = 'FileLifecycleError';
    this.code = code;
  }
}

const internalErrors = new WeakSet<object>();

export function lifecycleError(code: FileLifecycleErrorCode): FileLifecycleError {
  const error = new FileLifecycleError(code);
  internalErrors.add(error);
  Object.freeze(error);
  return error;
}

export function refuseLifecycle(code: FileLifecycleErrorCode): never {
  throw lifecycleError(code);
}

export function isLifecycleError(error: unknown): error is FileLifecycleError {
  return typeof error === 'object' && error !== null && internalErrors.has(error);
}
