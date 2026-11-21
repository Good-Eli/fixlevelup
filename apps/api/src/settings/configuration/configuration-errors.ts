/**
 * Typed refusals for the internal P03-03 configuration ports.
 *
 * These are not HTTP errors: P03-03 exposes no route, controller or guard. A
 * later trusted command layer maps `code` to its own transport/response policy.
 * Messages never echo a submitted value, a database identifier or driver text, so
 * a refusal cannot become a log or response leak of settings, labels, titles or
 * contact data.
 */
export type ConfigurationErrorCode =
  /** The typed input was missing, malformed, oversized or carried an unexpected key. */
  | 'INVALID_INPUT'
  /** The named row does not exist in the requested type/scope/city. */
  | 'NOT_FOUND'
  /** The expected last version / row_version does not match the database. */
  | 'STALE_VERSION'
  /** The operation is incompatible with current state (archived entry, pointer, city). */
  | 'CONFLICT'
  /** The aggregate is archived and accepts no new revision. */
  | 'ARCHIVED'
  /** The configuration slice is incomplete; the readiness report lists what is missing. */
  | 'INCOMPLETE'
  /** The caller did not provide an explicit transaction (see configuration-port.ts). */
  | 'TRANSACTION_REQUIRED'
  /** Content may not claim a legal/security/retention/upload policy code. */
  | 'RESERVED_CODE';

export class ConfigurationError extends Error {
  constructor(readonly code: ConfigurationErrorCode, readonly field?: string) {
    super(field === undefined ? code : `${code}: ${field}`);
    this.name = 'ConfigurationError';
  }
}

/** Always throws; typed so callers can use it in a `never` position. */
export function invalid(field: string): never {
  throw new ConfigurationError('INVALID_INPUT', field);
}

export function notFound(field = 'id'): never {
  throw new ConfigurationError('NOT_FOUND', field);
}

export function staleVersion(field = 'expectedVersion'): never {
  throw new ConfigurationError('STALE_VERSION', field);
}

export function conflict(field: string): never {
  throw new ConfigurationError('CONFLICT', field);
}
