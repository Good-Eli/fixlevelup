import type { Pool } from 'pg';
import type { RuntimeEpoch } from '../file-lifecycle/contract.js';
import type { FileLedger, FileLedgerVerifier, LedgerScope } from '../file-ledger/contract.js';
import type { RestoreGateReceipt } from '../file-restore/contract.js';

export interface RetentionPolicy {
  readonly mode: 'local-synthetic';
  readonly versionId: string;
  readonly expiresAt: Date;
  readonly rawBoundMs: number;
  readonly readyMs: number;
  readonly quarantinedMs: number;
  readonly orphanMs: number;
  readonly maxBatch: number;
  readonly maxItemsPerIntent: number;
  readonly claimMs: number;
}

declare const OPERATOR: unique symbol;
declare const HOLD: unique symbol;
declare const BROKER: unique symbol;
declare const DELETE: unique symbol;
export interface FilePrivacyGrant { readonly [OPERATOR]: true }
export interface HoldGrant { readonly [HOLD]: true }
export interface DeleteBroker { readonly [BROKER]: true }
export interface CommittedDeleteGrant { readonly [DELETE]: true }
export type HoldReason = 'LEGAL_HOLD' | 'OPERATOR_REVIEW';
export type FilePrivacyRole = 'RETENTION' | 'HOLD' | 'DELETE' | 'SOURCE_DRAIN';
export interface PrivacyContext { readonly pool: Pool; readonly epoch: RuntimeEpoch; readonly policy: RetentionPolicy }
export interface DatabaseContext extends PrivacyContext { readonly database?: string }
export interface HoldContext extends PrivacyContext { readonly restore?: RestoreGateReceipt }
export interface RetentionContext extends HoldContext { readonly grant: FilePrivacyGrant; readonly scope: LedgerScope }
export interface FencedDrainContext extends PrivacyContext {
  readonly grant: FilePrivacyGrant; readonly scope: LedgerScope; readonly ledger: FileLedger; readonly verifier: FileLedgerVerifier;
}
export interface DeleteContext extends FencedDrainContext { readonly broker: DeleteBroker }
export interface AggregateOnly { readonly examined: number; readonly advanced: number; readonly deferred: number }

export type PrivacyFailure = 'INVALID_INPUT' | 'NOT_CONFIGURED' | 'NOT_FOUND' | 'TOO_LATE' | 'STALE_VERSION' | 'ABORTED' | 'CONFLICT';
const errors = new WeakSet<object>();
export class FilePrivacyError extends Error {
  constructor(readonly code: PrivacyFailure) {
    super(code);
    this.name = 'FilePrivacyError';
    Object.freeze(this);
  }
}
export function refusePrivacy(code: PrivacyFailure): never {
  const error = new FilePrivacyError(code);
  errors.add(error);
  throw error;
}
export function isPrivacyError(error: unknown): error is FilePrivacyError {
  return typeof error === 'object' && error !== null && errors.has(error);
}
