import type { Pool } from 'pg';
import type { FileOwnerSessionProof } from '../reservations/index.js';
import type { FileReadBudget } from '../file-access/budget.js';
import type { LifecycleStorage, ReadyReadStorage } from '../storage/index.js';
import type { UploadOperationalPolicy } from '../upload-coordinator/contract.js';

export type { LifecycleStorage, ReadyReadStorage } from '../storage/index.js';

export type ImageMime = 'image/jpeg' | 'image/png' | 'image/webp';
export type ContentDigest = { readonly bytes: number; readonly sha256: string };
export type FFile = { readonly session: FileOwnerSessionProof; readonly intentId: string };
/** Command acknowledgment only. READY metadata requires separate access authorization. */
export type ProcessQuarantineReceipt = { readonly intentId: string; readonly completed: true };
export type ReadyFileView = { readonly fileId: string; readonly state: 'READY'; readonly mime: ImageMime; readonly bytes: number };
export type RuntimeEpoch = { readonly namespace: string; readonly epoch: bigint };
export type FileProcessingPolicy = {
  readonly mode: 'local-synthetic'; readonly versionId: string; readonly expiresAt: Date;
  readonly allowedMimeTypes: readonly ImageMime[]; readonly maxRawBytes: number; readonly maxOutputBytes: number;
  readonly maxWidth: number; readonly maxHeight: number; readonly maxPixels: number; readonly maxChannels: number;
  readonly leaseMs: number; readonly wallMs: number; readonly maxDefsAgeMs: number;
};
export type FileAccessPolicy = {
  readonly mode: 'local-synthetic'; readonly expiresAt: Date; readonly maxAccessAgeMs: number;
  readonly maxChunkBytes: number; readonly maxBufferedBytes: number; readonly maxActiveStreams: number; readonly ticketMs: number;
};
export type ProcessingContext = {
  readonly pool: Pool; readonly epoch: RuntimeEpoch; readonly storage: LifecycleStorage;
  readonly processor: LocalFileProcessor; readonly uploadPolicy: UploadOperationalPolicy; readonly policy: FileProcessingPolicy;
};
export type AccessContext = {
  readonly pool: Pool; readonly epoch: RuntimeEpoch; readonly storage: ReadyReadStorage;
  readonly policy: FileAccessPolicy; readonly budget: FileReadBudget;
};
export type WorkerReason = 'MALWARE' | 'UNSUPPORTED_FORMAT' | 'LIMIT_EXCEEDED' | 'SCAN_FAILED' | 'DECODE_FAILED'
  | 'STALE_ENGINE' | 'ABORTED' | 'BUSY';
export type WorkerClean = {
  readonly kind: 'CLEAN'; readonly raw: ContentDigest; readonly served: ContentDigest; readonly output: Uint8Array;
  readonly mime: ImageMime; readonly engineVersion: string; readonly engineImageSha256: string;
  readonly defsSha256: string; readonly defsBuiltAt: string;
};
export type WorkerResult = WorkerClean | { readonly kind: 'BLOCKED' | 'INDETERMINATE'; readonly reason: WorkerReason };
/** Trusted orchestration port, never implemented by a subprocess. A resolved result
 * attests actual local settlement (process exit plus pipe closure). If settlement
 * is unknown, the implementation must reject or stay unresolved; lifecycle must
 * leave its durable claim charged. */
export interface LocalFileProcessor {
  process(input: { readonly mime: ImageMime; readonly bytes: Uint8Array; readonly raw: ContentDigest;
    readonly policy: FileProcessingPolicy }, signal: AbortSignal): Promise<WorkerResult>;
  isEvidenceCurrent(evidence: WorkerClean, dbNow: string): boolean;
}
export interface ImageDecoderProcess {
  decode(input: { readonly mime: ImageMime; readonly bytes: Uint8Array; readonly policy: FileProcessingPolicy },
    signal: AbortSignal): Promise<Uint8Array>;
}
