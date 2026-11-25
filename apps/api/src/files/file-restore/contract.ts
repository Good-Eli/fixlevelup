import type { KeyObject } from 'node:crypto';
import type { Client, Pool } from 'pg';
import type { FileLedgerVerifier, LedgerHead, LedgerScope } from '../file-ledger/contract.js';
import type { ReadyReadStorage, RuntimeEpoch } from '../file-lifecycle/contract.js';
import type { StorageTarget } from '../storage/attempt.js';

export type FileRestoreFailure = 'RESTORE_INPUT' | 'RESTORE_CLOSED' | 'RESTORE_AUTHORITY' | 'RESTORE_LEDGER' | 'RESTORE_OBJECT' | 'RESTORE_ABORTED' | 'RESTORE_COMMIT_UNKNOWN';
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
  /** Present only on a versioned S3 manifest carrying a verified policy in the base archive. */
  readonly policySha256?: string;
}
export interface AuthorityRecord {
  readonly challenge: string;
  readonly manifestSha256: string;
  readonly overlaySha256: string;
  readonly inventorySha256: string;
  readonly head: LedgerHead;
}

/**
 * Immutable cluster identity of the fenced SOURCE, read in the same read-only
 * observation as the drain fact. It is a fact of the physical primary, not of the
 * caller: `system_identifier` is stable for the lifetime of the cluster (a restore
 * of a copy of another cluster can never satisfy it), `server_version_num` pins the
 * reviewed major, and `postmasterStart` distinguishes a restarted cluster from the
 * one the barrier was installed on.
 */
export interface ClusterFact {
  readonly systemIdentifier: string;
  readonly serverVersionNum: string;
  readonly postmasterStart: string;
}

/**
 * §5.3 signed authority v2: the P03 authority record PLUS the exact source
 * database/OID/cluster, the reviewed source schema profile, the old ledger
 * namespace/epoch and the destination database the handoff is allowed to open.
 *
 * A v1 authority record (challenge/manifest/overlay/inventory/head only) is
 * retained for legacy artifacts but is NOT admission: it cannot name the source
 * database, cluster or profile it drained, so it must be refused on its own.
 */
export interface AuthorityRecordV2 extends AuthorityRecord {
  readonly sourceDatabase: string;
  readonly sourceDatabaseOid: number;
  readonly cluster: ClusterFact;
  readonly sourceProfile: 'S0' | 'S1' | 'S2' | 'S3';
  readonly oldNamespace: string;
  /** Decimal text of the pre-restore writer epoch (exact, no JS bigint in the payload). */
  readonly oldWriterEpoch: string;
  readonly destinationDatabase: string;
}
export interface AuthorityRecordV3 extends AuthorityRecordV2 {
  readonly sourceProfile: 'S3';
  readonly drainFact: 'P05_EMPTY_AFTER_DRAIN';
  readonly policySha256: string;
}

/** Independently reviewed metadata, not values discovered from the source or archive. */
export interface RestorePolicyPin {
  readonly workflowVersion: string;
  readonly policyRevision: string;
  readonly metadataSha256: string;
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
  /** Operator provisioned; does not permit a legacy manifest to carry a policy. */
  readonly policyPin?: RestorePolicyPin;
  readonly verifier: FileLedgerVerifier;
  /**
   * Re-read immutable source fence + pinned authority, bound to this run/manifest/
   * nonce. Strict-empty handoffs require authority v2 (§5.3), binding the exact
   * source database/OID/cluster, profile, old epoch and destination. Signed S3
   * carried-policy manifests require authority v3, additionally binding the policy
   * and the observed absence of all P05 operational rows. Version 1 never admits.
   */
  readonly currentAuthority: (request: { readonly manifestSha256: string; readonly challenge: string }, signal: AbortSignal) => Promise<SignedRestoreRecord>;
  /** Dedicated operator-owned connection opened before the hard database fence.
   * The caller pins the numeric OID when opening this source, keeps the same
   * observer until restore returns, and excludes privileged out-of-band DBA
   * actions. Not a pool, runtime credential, or the deferred signed Bridge B. */
  readonly sourceObserver: Client;
  readonly sourceDatabaseOid: number;
  /** Must verify actual archives, retain them, CREATE a fresh target with runtime CONNECT withheld, and install the closed epoch. */
  readonly restoreArchives: (manifest: SnapshotManifest, authority: AuthorityRecordV2, signal: AbortSignal) => Promise<void>;
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