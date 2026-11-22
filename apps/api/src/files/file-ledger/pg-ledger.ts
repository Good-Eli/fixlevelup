import { sign, type KeyObject } from 'node:crypto';
import type { Pool, QueryResultRow } from 'pg';
import { counter, decimal, decodeGraph, deny, encodeGraph, hash, headMessage, invalid, keyPin, ledgerLimits, ledgerScope, MAX_PROOF_BYTES, plain, sameNamespace, unavailable, uuid } from './codec.js';
import { FileLedgerError, type FileLedger, type LedgerEvent, type LedgerHead, type LedgerLimits, type LedgerScope } from './contract.js';

export interface LedgerSignerConfig {
  readonly mode: 'local-synthetic';
  readonly limits: LedgerLimits;
  readonly privateKey: KeyObject;
  readonly signerPool: Pool;
  readonly operatorPool?: Pool;
}
interface HeadRow extends QueryResultRow {
  namespace_id: unknown;
  incarnation_id: unknown;
  writer_epoch: unknown;
  seq: unknown;
  chain_sha256: unknown;
  key_sha256?: unknown;
}
export function pgHead(row: HeadRow | undefined): LedgerHead {
  if (!row) {deny();}
  return Object.freeze({ namespace: uuid(row.namespace_id, true), incarnation: uuid(row.incarnation_id, true),
    writerEpoch: decimal(row.writer_epoch), seq: decimal(row.seq, 0n), hash: hash(row.chain_sha256) });
}
export function pgError(error: unknown): never {
  // Runtime DB errors have no diagnostics across this boundary. SQLSTATE of the
  // trusted PG driver is the only distinction needed for fixed conflict codes.
  let code: unknown;
  try { code = typeof error === 'object' && error !== null ? Reflect.getOwnPropertyDescriptor(error, 'code')?.value : undefined; }
  catch { unavailable(); }
  if (code === 'FL001') {throw new FileLedgerError('LEDGER_CONFLICT');}
  if (code === 'FL002') {deny();}
  unavailable();
}
function scopeMatches(scope: LedgerScope, head: LedgerHead): void {
  if (!sameNamespace(scope, head) || scope.writerEpoch !== head.writerEpoch) {deny();}
}
export function createPgFileLedger(pool: Pool, config: LedgerSignerConfig): FileLedger {
  const v = plain(config, ['privateKey', 'signerPool', 'limits', 'mode'], 'operatorPool');
  const { signerPool, operatorPool, privateKey } = v as unknown as LedgerSignerConfig;
  if (v.mode !== 'local-synthetic' || privateKey.type !== 'private') { invalid(); }
  keyPin(privateKey);
  const limits = ledgerLimits(v.limits as LedgerLimits);
  const headSql = `SELECT namespace_id, incarnation_id, writer_epoch::text, seq::text, chain_sha256
    FROM file_ledger.namespace_heads WHERE namespace_id = $1 AND NOT pg_catalog.pg_is_in_recovery()`;
  return Object.freeze<FileLedger>({
    async append(input) {
      const { graph, payload } = encodeGraph(input, limits.maxItems);
      try {
        const { rows } = await pool.query<{ seq: string; sha256: string }>(`SELECT seq::text, sha256
          FROM file_ledger.append($1,$2,$3,$4,$5,$6,$7)`, [graph.namespace, graph.incarnation, graph.writerEpoch.toString(),
          graph.eventId, graph.intentId, graph.accessEpoch.toString(), payload]);
        if (rows.length !== 1 || !rows[0]) {deny();}
        return Object.freeze({ seq: decimal(rows[0].seq), hash: hash(rows[0].sha256) });
      } catch (error) { pgError(error); }
    },
    async getHead(input, challenge) {
      const scope = ledgerScope(input);
      hash(challenge);
      const { rows } = await signerPool.query<HeadRow>(headSql, [scope.namespace]).catch(pgError);
      let head: LedgerHead;
      try { head = pgHead(rows[0]); scopeMatches(scope, head); }
      catch { deny(); }
      return Object.freeze({ ...head, v: 1, challenge, signature: sign(null, headMessage(head, challenge), privateKey).toString('hex') });
    },
    async getEvents(input, afterSeq, throughSeq) {
      const scope = ledgerScope(input);
      counter(afterSeq, 0n); counter(throughSeq, 0n);
      if (throughSeq < afterSeq || throughSeq - afterSeq > BigInt(limits.maxProofEvents)) {invalid();}
      try {
        const { rows } = await signerPool.query<{ seq: string; writer_epoch: string; event_id: string; intent_id: string;
          access_epoch: string; prev_sha256: string; sha256: string; payload: Buffer }>(`
          WITH proof_window AS MATERIALIZED (
            SELECT e.* FROM file_ledger.events e JOIN file_ledger.namespace_heads h USING (namespace_id)
            WHERE e.namespace_id = $1 AND h.incarnation_id = $2 AND h.writer_epoch = $3 AND h.seq >= $5
              AND e.seq > $4 AND e.seq <= $5 AND NOT pg_catalog.pg_is_in_recovery()
          ) SELECT seq::text, writer_epoch::text, event_id, intent_id, access_epoch::text, prev_sha256, sha256, payload
          FROM proof_window WHERE (SELECT sum(octet_length(payload)) FROM proof_window) <= $6 ORDER BY proof_window.seq`,
        [scope.namespace, scope.incarnation, scope.writerEpoch.toString(), afterSeq.toString(), throughSeq.toString(), MAX_PROOF_BYTES]);
        if (rows.length !== Number(throughSeq - afterSeq)) {deny();}
        return Object.freeze(rows.map((row): LedgerEvent => {
          const graph = decodeGraph(row.payload, limits.maxItems);
          if (!sameNamespace(scope, graph) || graph.writerEpoch !== decimal(row.writer_epoch)
            || graph.eventId !== row.event_id || graph.intentId !== row.intent_id || graph.accessEpoch !== decimal(row.access_epoch)) {deny();}
          return Object.freeze({ graph, seq: decimal(row.seq), previousHash: hash(row.prev_sha256), hash: hash(row.sha256) });
        }));
      } catch (error) { pgError(error); }
    },
    async fenceLedgerWriter(input, nextEpoch, nextWriterRole) {
      const scope = ledgerScope(input);
      if (!operatorPool || counter(nextEpoch) <= scope.writerEpoch || typeof nextWriterRole !== 'string'
        || !/^file_ledger_writer_[a-z0-9_]{1,44}$/.test(nextWriterRole) || nextWriterRole.trim() !== nextWriterRole) { deny(); }
      const { rows } = await operatorPool.query<HeadRow>(`
        SELECT namespace_id, incarnation_id, writer_epoch::text, seq::text, chain_sha256
        FROM file_ledger.fence_writer($1,$2,$3,$4,$5)`,
      [scope.namespace, scope.incarnation, scope.writerEpoch.toString(), nextEpoch.toString(), nextWriterRole]).catch(pgError);
      return pgHead(rows[0]);
    },
  });
}