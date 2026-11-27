import type { GuardedPool } from '../../infrastructure/admission/pool-guard.js';
import { requireRequestEffectsPool } from '../../infrastructure/admission/pool-guard.js';
import { deny } from './errors.js';

export type WaitingCandidate = Readonly<{ id: string; cityId: string; version: number }>;

/** Trusted isolated preview only. The caller supplies a reviewed cutoff; no
 * scheduler, default waiting period, notification, deletion or auth grant. The
 * same generated DB predicate is used for reminder and cleanup candidates. */
export async function previewWaitingCandidates(pool: GuardedPool, input: { readonly cityId: string;
  readonly through: Date; readonly limit: number }): Promise<readonly WaitingCandidate[]> {
  requireRequestEffectsPool(pool);
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(input.cityId)
    || !(input.through instanceof Date) || !Number.isFinite(input.through.getTime())
    || !Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 100) { return deny('INVALID_REQUEST'); }
  const { rows } = await pool.query<WaitingCandidate>(`SELECT id,city_id AS "cityId",row_version AS version
    FROM foundation.requests WHERE is_waiting_link AND city_id=$1 AND updated_at<=$2::timestamptz
      AND updated_at<=clock_timestamp() ORDER BY updated_at,id LIMIT $3`, [input.cityId,input.through,input.limit]);
  return Object.freeze(rows.map(row => Object.freeze({ id:row.id,cityId:row.cityId,version:row.version })));
}
