import type { KeyObject } from 'node:crypto';
import type { Pool } from 'pg';
import { counter, deny, genesisHash, keyPin, ledgerFloor, plain, sameNamespace, unavailable, uuid } from './codec.js';
import { pgError, pgHead } from './pg-ledger.js';
import type { DurableFloorStore, LedgerFloor } from './contract.js';

export function createPgFloorStore(pool: Pool): DurableFloorStore {
  return Object.freeze<DurableFloorStore>({
    async read(rawNamespace) {
      const namespace = uuid(rawNamespace, true);
      const { rows } = await pool.query<{ namespace_id: string; incarnation_id: string; writer_epoch: string;
        seq: string; chain_sha256: string; key_sha256: string }>(`
        SELECT namespace_id, incarnation_id, writer_epoch::text, seq::text, chain_sha256, key_sha256
        FROM file_floor.current_heads WHERE namespace_id = $1 AND NOT pg_catalog.pg_is_in_recovery()`, [namespace]).catch(pgError);
      const row = rows[0];
      if (!row) {deny();}
      return ledgerFloor({ ...pgHead(row), keySha256: row.key_sha256 });
    },
    async compareAndPin(expected, next) {
      const old = ledgerFloor(expected), head = ledgerFloor(next);
      if (!sameNamespace(old, head) || old.keySha256 !== head.keySha256 || head.seq < old.seq
        || head.writerEpoch < old.writerEpoch || (head.seq === old.seq && head.hash !== old.hash)) {deny();}
      const { rows } = await pool.query<{ pinned: boolean }>(`SELECT file_floor.pin($1,$2,$3,$4,$5,$6,$7,$8,$9) AS pinned`,
        [head.namespace, head.incarnation, head.keySha256, old.seq.toString(), old.hash, old.writerEpoch.toString(),
          head.seq.toString(), head.hash, head.writerEpoch.toString()]).catch(pgError);
      if (typeof rows[0]?.pinned !== 'boolean') {unavailable();}
      // PG is in autocommit mode (Pool.query), and the SQL function forces
      // synchronous_commit=on for the outer xact before returning a true CAS.
      return rows[0].pinned;
    },
  });
}
interface BootstrapConfig {
  readonly mode: 'local-synthetic';
  readonly ledgerOperatorPool: Pool;
  readonly floorOperatorPool: Pool;
  readonly signerPublicKey: KeyObject;
  readonly initialEpoch: bigint;
}
/** Trusted offline provisioning only. Never accepts a pre-existing namespace. */
export async function bootstrapFileLedgerNamespace(config: BootstrapConfig): Promise<LedgerFloor> {
  const v = plain(config, ['mode', 'ledgerOperatorPool', 'floorOperatorPool', 'signerPublicKey', 'initialEpoch']);
  const { signerPublicKey, initialEpoch, floorOperatorPool, ledgerOperatorPool } = v as unknown as BootstrapConfig;
  if (v.mode !== 'local-synthetic' || signerPublicKey.type !== 'public') { deny(); }
  const keySha256 = keyPin(signerPublicKey);
  const { rows } = await floorOperatorPool.query<{
    namespace_id: string; incarnation_id: string; writer_epoch: string; seq: string; chain_sha256: string; key_sha256: string;
  }>(`SELECT namespace_id, incarnation_id, writer_epoch::text, seq::text, chain_sha256, key_sha256
      FROM file_floor.initialize($1,$2)`, [counter(initialEpoch).toString(), keySha256]).catch(pgError);
  const row = rows[0];
  if (!row) {deny();}
  const floor = ledgerFloor({ ...pgHead(row), keySha256: row.key_sha256 });
  if (floor.seq !== 0n || floor.hash !== genesisHash(floor, keySha256) || floor.keySha256 !== keySha256) {deny();}
  // Both independent commits are required. If either fails/ack is ambiguous,
  // abandon the unopened synthetic namespace. Never repair/reset an old pin.
  await ledgerOperatorPool.query('SELECT file_ledger.initialize($1,$2,$3,$4)',
    [floor.namespace, floor.incarnation, floor.writerEpoch.toString(), floor.hash]).catch(pgError);
  return floor;
}