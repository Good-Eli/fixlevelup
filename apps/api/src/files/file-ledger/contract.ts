import type { StorageTarget } from '../storage/attempt.js';

export interface LedgerScope {
  readonly namespace: string;
  readonly incarnation: string;
  readonly writerEpoch: bigint;
}
export interface LedgerItem {
  readonly kind: 'RAW' | 'SANITIZED';
  readonly attemptId: string;
  readonly target: StorageTarget;
  readonly objectKey: string;
  readonly writeProof: 'NEVER_DISPATCHED' | 'VERIFIED_SETTLED' | 'UNKNOWN';
}
export interface LedgerGraph extends LedgerScope {
  readonly eventId: string;
  readonly intentId: string;
  readonly accessEpoch: bigint;
  readonly items: readonly LedgerItem[];
}
export interface LedgerPosition {
  readonly seq: bigint;
  readonly hash: string;
}
export interface LedgerHead extends LedgerScope, LedgerPosition {}
export interface SignedLedgerHead extends LedgerHead {
  readonly v: 1;
  readonly challenge: string;
  readonly signature: string;
}
export interface LedgerEvent extends LedgerPosition {
  readonly graph: LedgerGraph;
  readonly previousHash: string;
}
export interface LedgerReadPort {
  getHead(scope: LedgerScope, challenge: string): Promise<SignedLedgerHead>;
  getEvents(scope: LedgerScope, afterSeq: bigint, throughSeq: bigint): Promise<readonly LedgerEvent[]>;
}
export interface FileLedger extends LedgerReadPort {
  append(graph: LedgerGraph): Promise<LedgerPosition>;
  fenceLedgerWriter(scope: LedgerScope, nextEpoch: bigint, nextWriterRole: string): Promise<LedgerHead>;
}
export interface LedgerLimits {
  readonly maxItems: number;
  readonly maxProofEvents: number;
}
export interface LedgerFloor extends LedgerHead {
  readonly keySha256: string;
}
export interface DurableFloorStore {
  read(namespace: string): Promise<LedgerFloor>;
  compareAndPin(expected: LedgerFloor, next: LedgerFloor): Promise<boolean>;
}
declare const LEDGER_MEMBERSHIP: unique symbol;
export interface LedgerMembership { readonly [LEDGER_MEMBERSHIP]: true }
export interface LedgerMembershipFacts extends LedgerHead {
  readonly eventId: string;
  readonly intentId: string;
  readonly accessEpoch: bigint;
  readonly graphSha256: string;
  readonly head: LedgerHead;
}
export interface FileLedgerVerifier {
  verifyMembership(graph: LedgerGraph, seq: bigint, currentScope?: LedgerScope): Promise<LedgerMembership>;
  verifyLineage(scope: LedgerScope, base: LedgerHead): Promise<{ readonly head: LedgerHead; readonly events: readonly LedgerEvent[] }>;
}
export type LedgerFailure = 'INVALID_LEDGER_INPUT' | 'LEDGER_UNAVAILABLE' | 'LEDGER_CONFLICT' | 'LEDGER_DENIED';
export class FileLedgerError extends Error {
  constructor(readonly code: LedgerFailure) {
    super(code);
    this.name = 'FileLedgerError';
  }
}