/**
 * Runtime-side admission gate (docs/P05-PLAN.md §7, "Все потребители БД").
 *
 * One immutable typed binding ties a DB-bound process to endpoint database
 * (name + OID), role, schema, profile and the launcher witness key. Before any
 * business work, every checked-out application connection is verified with a
 * single query: exact database/OID, exact role, exact schema and the live
 * launcher witness granted to another backend at the exact key. Driver errors
 * never surface: verification fails closed as a typed AdmissionError without
 * echoing connection details.
 */
import type { PoolClient } from 'pg';
import { ProofError, verifyProof } from './proof.js';
import type { LaunchProofPayload, ProofProfile } from './proof.js';

/** Minimal pg-like statement executor: any Client or checked-out PoolClient. */
export interface AdmissionConnection {
  query: PoolClient['query'];
}

export interface AdmissionExpectedFacts {
  readonly endpoint: string;
  readonly issuerGeneration: number;
  readonly launchNonce: string;
  readonly consumerKind: 'API' | 'WORKER' | 'TEST';
  readonly instanceId: string;
  readonly channelId: string;
  readonly artifactDigest: string;
  readonly historyManifestDigest: string;
  readonly physicalContractDigest: string;
}

export interface AdmissionBinding {
  readonly database: string;
  readonly databaseOid: number;
  readonly role: string;
  readonly schema: string;
  readonly witnessKey: { readonly classId: number; readonly objectId: number };
  readonly profile: ProofProfile;
  /**
   * Launcher backend pid from the verified proof: the witness lock must be
   * granted to exactly this pid; any other holder is rejected as
   * WITNESS_MISMATCH. Required — admission never accepts an unpinned witness.
   */
  readonly witnessHolderPid: number;
  /**
   * Exact expected proof facts (plan §7 item 1): the verified token must carry
   * exactly these values. Required and complete — a gate without a full
   * trusted fact set admits nothing. The endpoint identifies the configured
   * connection target.
   */
  readonly expected: AdmissionExpectedFacts;
}

export type AdmissionErrorCode =
  | 'WRONG_DATABASE'
  | 'WRONG_ROLE'
  | 'WRONG_SCHEMA'
  | 'WITNESS_MISSING'
  | 'WITNESS_MISMATCH'
  | 'PROOF_MISMATCH'
  | 'EXPIRED'
  | 'BAD_SIGNATURE';

export class AdmissionError extends Error {
  readonly code: AdmissionErrorCode;

  constructor(code: AdmissionErrorCode, message: string) {
    super(message);
    this.name = 'AdmissionError';
    this.code = code;
  }
}

interface ConnectionCheckRow {
  readonly db: string;
  readonly dboid: number | null;
  readonly role: string;
  readonly schema: string;
  readonly witness: number | null;
}

export class AdmissionGate {
  private readonly binding: AdmissionBinding;
  private readonly publicKeyPem: string;

  constructor(deps: { binding: AdmissionBinding; publicKeyPem: string }) {
    this.binding = deps.binding;
    this.publicKeyPem = deps.publicKeyPem;
  }

  /**
   * Single-query per-connection verification: current_database() and its OID,
   * current_user, current_schema() and a granted session advisory witness
   * (exact classid/objid, objsubid=2) held by a pid other than this backend.
   * When the binding pins witnessHolderPid, the same single query returns the
   * granted holder pid and it must equal the pinned launcher pid — any other
   * holder is rejected as WITNESS_MISMATCH. Throws a typed AdmissionError; a
   * broken connection fails closed as WITNESS_MISSING rather than surfacing a
   * driver error.
   */
  async verifyConnection(client: AdmissionConnection, now: Date): Promise<void> {
    // The database clock is authoritative for verification; `now` is reserved
    // for a future caller-side deadline and intentionally unused here.
    if (Number.isNaN(now.getTime())) { throw new AdmissionError('WITNESS_MISSING', 'Invalid verification clock'); }
    let row: ConnectionCheckRow | undefined;
    try {
      const result = await client.query<ConnectionCheckRow>(
        `SELECT current_database() AS db,
           (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = current_database()) AS dboid,
           current_user AS role,
           current_schema() AS schema,
           (SELECT l.pid FROM pg_catalog.pg_locks l
             WHERE l.locktype = 'advisory' AND l.granted AND l.mode = 'ExclusiveLock'
               AND l.classid = $1::int::oid AND l.objid = $2::int::oid AND l.objsubid = 2
               AND l.database = (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = current_database())
               AND l.pid <> pg_catalog.pg_backend_pid()
             ORDER BY l.pid
             LIMIT 1) AS witness`,
        [this.binding.witnessKey.classId, this.binding.witnessKey.objectId]);
      row = result.rows[0];
    } catch {
      throw new AdmissionError('WITNESS_MISSING', 'Connection verification failed');
    }
    if (!row || row.db !== this.binding.database || row.dboid === null || row.dboid !== this.binding.databaseOid) {
      throw new AdmissionError('WRONG_DATABASE', 'Connection database does not match the admission binding');
    }
    if (row.role !== this.binding.role) {
      throw new AdmissionError('WRONG_ROLE', 'Connection role does not match the admission binding');
    }
    if (row.schema !== this.binding.schema) {
      throw new AdmissionError('WRONG_SCHEMA', 'Connection schema does not match the admission binding');
    }
    if (row.witness === null) {
      throw new AdmissionError('WITNESS_MISSING', 'Launcher witness is not visible on this connection');
    }
    if (row.witness !== this.binding.witnessHolderPid) {
      throw new AdmissionError('WITNESS_MISMATCH', 'Launcher witness is held by a different backend');
    }
  }

  /**
   * Re-checks a presented proof token: signature, expiry against `now`, and
   * that the payload's target identity, profile and witness key exactly match
   * this gate's binding. Returns the verified payload.
   */
  verifyProofToken(token: string, now: Date): LaunchProofPayload {
    let payload: LaunchProofPayload;
    try {
      payload = verifyProof(token, this.publicKeyPem, now);
    } catch (error) {
      if (error instanceof ProofError) {
        if (error.code === 'EXPIRED') {
          throw new AdmissionError('EXPIRED', 'Launch proof expired');
        }
        throw new AdmissionError('BAD_SIGNATURE', 'Launch proof signature check failed');
      }
      throw error;
    }
    const binding = this.binding;
    const identity = payload.targetIdentity;
    if (identity.database !== binding.database
      || identity.databaseOid !== binding.databaseOid
      || identity.runtimeRole !== binding.role
      || identity.schema !== binding.schema
      || payload.profile !== binding.profile
      || payload.witness.classId !== binding.witnessKey.classId
      || payload.witness.objectId !== binding.witnessKey.objectId) {
      throw new AdmissionError('PROOF_MISMATCH', 'Launch proof does not match the admission binding');
    }
    const expected = binding.expected;
    if (payload.endpoint !== expected.endpoint
      || payload.issuerGeneration !== expected.issuerGeneration
      || payload.launchNonce !== expected.launchNonce
      || payload.consumerKind !== expected.consumerKind
      || payload.instanceId !== expected.instanceId
      || payload.channelId !== expected.channelId
      || payload.artifactDigest !== expected.artifactDigest
      || payload.historyManifestDigest !== expected.historyManifestDigest
      || payload.physicalContractDigest !== expected.physicalContractDigest) {
      throw new AdmissionError('PROOF_MISMATCH', 'Launch proof facts do not match the expected admission facts');
    }
    return payload;
  }
}
