import type { RestoreObject } from '../../apps/api/src/files/file-restore/contract.js';
import type { StorageTarget } from '../../apps/api/src/files/storage/attempt.js';
interface Credentials { accessKeyId: string; secretAccessKey: string }
export function restoreDbOptions(database: string, role: 'runtime' | 'migrator' | 'maintenance'): {
  host: string; port: number; database: string; user: string; password: string; connectionTimeoutMillis?: number; statement_timeout?: number;
};
export function freshGarageBucket(namespace?: string): { target: StorageTarget; rw: Credentials; ro: Credentials };
export function newArchives(source: string, destination: string, overlayTables: readonly string[], maxDumpBytes: number): {
  directory: string;
  dump(): string;
  overlay(): string;
  manifest(value: unknown): void;
  evidence(value: unknown): void;
  artifact(item: RestoreObject, bytes: Uint8Array): void;
  object(item: RestoreObject, maximum: number): Uint8Array;
  restore(dump: string, overlay: string, createClosedDb: () => Promise<void>, installClosedEpoch: () => Promise<void>): Promise<void>;
};
