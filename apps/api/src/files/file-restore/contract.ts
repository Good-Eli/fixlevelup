import type { KeyObject } from 'node:crypto';
import type { Pool } from 'pg';
import type { FileLedgerVerifier, LedgerHead, LedgerScope } from '../file-ledger/contract.js';
import type { ReadyReadStorage, RuntimeEpoch } from '../file-lifecycle/contract.js';
import type { StorageTarget } from '../storage/attempt.js';

export type FileRestoreFailure = 'RESTORE_INPUT' | 'RESTORE_CLOSED' | 'RESTORE_AUTHORITY' | 'RESTORE_LEDGER' | 'RESTORE_OBJECT' | 'RESTORE_ABORTED';
export class FileRestoreError extends Error {
  constructor(readonly code: FileRestoreFailure) {
    super(code);
    this.name = 'FileRestoreError';
  }
}
export function refuseRestore(code: FileRestoreFailure): never { throw new FileRestoreError(code); }

export type RestoreKind = 'RAW' | 'SANITIZED';
export interface RestoreObject {
  readonly kind: RestoreKind;
  readonly intentId: string;
  readonly attemptId: string;
  readonly key: string;
  readonly target: StorageTarget;
  readonly disposition: 'COPY' | 'NEVER_DISPATCHED' | 'UNRESOLVED' | 'TOMBSTONED';
  readonly bytes: number | null;
  readonly sha256: string | null;
}
export interface RestoreAlias {
  readonly source: StorageTarget;
  readonly destination: StorageTarget;
}
export interface RestoreLimits {
  readonly maxObjects: number;
  readonly maxIntents: number;
  readonly maxObjectBytes: number;
  readonly maxTotalObjectBytes: number;
  readonly maxManifestBytes: number;
  readonly maxDumpBytes: number;
}
export interface SignedSnapshotManifest { readonly payload: string; readonly signature: string }
export type SignedRestoreRecord = SignedSnapshotManifest;

export interface SnapshotManifest {
  readonly sourceDatabase: string;
  readonly destinationDatabase: string;
  readonly schemaVersion: string;
  readonly dumpSha256: string;
  readonly base: LedgerHead;
  readonly aliases: readonly RestoreAlias[];
  readonly inventory: readonly RestoreObject[];
}
export interface AuthorityRecord {
  readonly challenge: string;
  readonly manifestSha256: string;
  readonly overlaySha256: string;
  readonly inventorySha256: string;
  readonly head: LedgerHead;
}
export interface RestoreApproval {
  readonly challenge: string;
  readonly authoritySha256: string;
  readonly destinationDatabase: string;
}

/** Operator-only wiring; no HTTP, process bootstrap, runtime role or storage credential in this surface. */
export interface RestoreContext {
  readonly mode: 'local-synthetic';
  readonly schemaVersion: string;
  readonly sourceDatabase: string;
  readonly destinationDatabase: string;
  readonly oldScope: LedgerScope;
  readonly nextEpoch: bigint;
  readonly limits: RestoreLimits;
  readonly targetOperatorPool: Pool;
  readonly snapshotKey: KeyObject;
  readonly authorityKey: KeyObject;
  readonly approvalKey: KeyObject;
  readonly verifier: FileLedgerVerifier;
  /** Re-read immutable source fence + pinned authority, bound to this run/manifest/nonce. */
  readonly currentAuthority: (request: { readonly manifestSha256: string; readonly challenge: string }, signal: AbortSignal) => Promise<SignedRestoreRecord>;
  /** §5.3 source-drain fact. The trusted operator bridge runs this ONLY inside the
   * fenced post-drain window on the SOURCE primary (after the §5.3 FENCED/drain
   * steps revoked writer CONNECT and waited out active transactions): it executes
   * readP05SourceState/assertP05AbsentAfterDrain (./p05-inventory.js) on that same
   * primary and returns only the typed fact — no P05 row ever crosses. The
   * challenge is fresh per handoff and the returned nonce must differ between the
   * two activation checks. */
  readonly readP05SourceState: (input: { readonly manifestSha256: string; readonly challenge: string }, signal: AbortSignal) => Promise<{ readonly fact: 'P05_EMPTY_AFTER_DRAIN' | 'P05_SCHEMA_ABSENT_AFTER_DRAIN'; readonly profile: 'S0' | 'S1'; readonly nonce: string }>;
  /** Must verify actual archives, retain them, CREATE a fresh target with runtime CONNECT withheld, and install the closed epoch. */
  readonly restoreArchives: (manifest: SnapshotManifest, authority: AuthorityRecord, signal: AbortSignal) => Promise<void>;
  /** Byte artifact lookup by manifest item only; returns full bounded object, with no remote target authority. */
  readonly openBackupObject: (item: RestoreObject, signal: AbortSignal) => Promise<Uint8Array>;
  /** Exact physical destination from a verified one-to-one mapping. Must be new-key-only PUT and full readback verification. */
  readonly copyToFreshTarget: (destination: StorageTarget, item: RestoreObject, bytes: Uint8Array, signal: AbortSignal) => Promise<void>;
  readonly approve: (binding: RestoreApproval, signal: AbortSignal) => Promise<SignedRestoreRecord>;
}

export interface RestoreGateReceipt {
  readonly mode: 'ACTIVE';
  readonly epoch: RuntimeEpoch;
  readonly copied: number;
  readonly tombstoned: number;
  readonly unresolved: number;
}

export interface RestoreReaderTarget {
  readonly target: StorageTarget;
  readonly reader: ReadyReadStorage;
}