/** Private SQL shared by the owner-lock checks and bounded recovery selection.
 * Only fixed, internal references may be interpolated; no command value is SQL.
 * Occupied claims and UNKNOWN/probe debts remain charged after lease expiry.
 */
export function ownerBudgetSql(owner: '$1' | 'a.owner_request_session_id'): string {
  return `WITH
    raw AS (SELECT count(*) AS attempts,coalesce(sum(charged_bytes) FILTER (WHERE state <> 'FAILED_NOBYTES'),0) AS bytes,
      count(*) FILTER (WHERE state IN ('REGISTERED','IN_FLIGHT','UNKNOWN')) + coalesce(sum(probe_held_slots::numeric),0) AS slots
      FROM foundation.file_upload_attempts WHERE owner_request_session_id=${owner}),
    sanitized AS (SELECT count(*) AS attempts,coalesce(sum(charged_bytes) FILTER (WHERE state <> 'FAILED_NOBYTES'),0) AS bytes,
      count(*) FILTER (WHERE state IN ('REGISTERED','IN_FLIGHT','UNKNOWN')) AS slots
      FROM foundation.file_sanitized_attempts WHERE owner_request_session_id=${owner}),
    claims AS (SELECT count(*) FILTER (WHERE c.read_lease_id IS NOT NULL) + count(*) FILTER (
      WHERE c.processing_lease_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM foundation.file_sanitized_attempts s
        WHERE s.intent_id=c.intent_id AND s.generation=c.processing_generation AND s.lease_id=c.processing_lease_id
          AND s.state IN ('REGISTERED','IN_FLIGHT','UNKNOWN'))) AS slots
      FROM foundation.file_privacy_controls c JOIN foundation.file_upload_intents i ON i.id=c.intent_id
      WHERE i.owner_request_session_id=${owner})
    SELECT (raw.attempts::numeric+sanitized.attempts)::text AS attempts,(raw.bytes+sanitized.bytes)::text AS bytes,
      (raw.slots+sanitized.slots+claims.slots)::text AS slots FROM raw,sanitized,claims`;
}
