import type { PoolClient } from 'pg';

/** SQL-only history predicate shared by S3 readiness and receipt reads. The
 * surrounding query supplies `e` (event) and `r` (exact joined receipt). This is
 * a structural check, not current call eligibility. Resolve the immutable
 * contact as of the event's version, not the request's current contact. */
export const REQUEST_PHONE_HISTORY_COMPLETE = `((e.actor_type<>'F' OR e.command NOT IN ('ChooseCallback','WithdrawPhonePermission','CancelRequest')
    OR EXISTS (SELECT FROM foundation.request_session_submits s
      JOIN foundation.request_events intake ON (intake.id,intake.request_id,intake.command)=(s.event_id,s.request_id,s.submit_command)
      JOIN foundation.request_command_receipts original ON (original.event_id,original.request_id,original.version,original.correlation_id,original.command)
        =(intake.id,intake.request_id,intake.resulting_version,intake.correlation_id,intake.command)
      WHERE s.request_id=e.request_id AND s.session_id=e.actor_session_id AND intake.actor_type='F'
        AND intake.actor_session_id=s.session_id AND intake.resulting_version=1
        AND original.resulting_status=intake.details->>'status')) AND (SELECT CASE expected.action
    WHEN 'NONE' THEN NOT EXISTS (SELECT FROM foundation.phone_permission_events p WHERE p.event_id=e.id)
    WHEN 'INVALID' THEN false
    ELSE EXISTS (SELECT FROM foundation.phone_permission_events p
      LEFT JOIN foundation.request_staff_evidence se ON se.id=p.staff_evidence_id AND se.request_id=p.request_id
      WHERE p.event_id=e.id AND p.request_id=e.request_id AND p.action=expected.action
        AND p.purpose='REQUEST_SERVICE_CALL'
        AND p.contact_revision_id=(SELECT c.id FROM foundation.request_contact_revisions c
          WHERE c.request_id=e.request_id AND c.revision<=e.resulting_version
            AND (e.command<>'ChooseCallback' OR c.revision<e.resulting_version) ORDER BY c.revision DESC LIMIT 1)
        AND NOT EXISTS (SELECT FROM foundation.requests q WHERE q.id=e.request_id AND q.row_version=e.resulting_version
          AND q.current_contact_revision_id IS DISTINCT FROM p.contact_revision_id)
        AND ((e.actor_type='F' AND p.staff_evidence_id IS NULL) OR
             (e.actor_type='STAFF' AND se.staff_id=e.actor_staff_id AND
             se.purpose=CASE p.action WHEN 'GIVEN' THEN 'PHONE_GIVE' ELSE 'PHONE_WITHDRAW' END))
        AND ((p.action='GIVEN' AND p.supersedes_given_id IS NULL) OR (p.action='REVOKED' AND EXISTS (
          SELECT FROM foundation.phone_permission_events g JOIN foundation.request_events origin ON origin.id=g.event_id
          WHERE g.id=p.supersedes_given_id AND g.action='GIVEN' AND g.purpose=p.purpose
            AND g.request_id=p.request_id AND g.contact_revision_id=p.contact_revision_id
            AND origin.resulting_version<e.resulting_version))))
    END FROM (SELECT CASE
      WHEN e.command IN ('CreateCallback','CreateRepair') THEN CASE
        WHEN ((e.command='CreateCallback' AND r.resulting_status='CALLBACK_REQUIRED')
          OR (e.command='CreateRepair' AND r.resulting_status='NEW' AND e.actor_type='STAFF')) AND EXISTS (
          SELECT FROM foundation.request_preference_revisions c WHERE c.request_id=e.request_id AND c.revision=1 AND c.contact_mode='PHONE')
          AND NOT EXISTS (SELECT FROM foundation.request_channel_choices ch WHERE ch.request_id=e.request_id)
          THEN 'GIVEN'
        WHEN e.command='CreateRepair' AND EXISTS (
          SELECT FROM foundation.request_preference_revisions c WHERE c.request_id=e.request_id AND c.revision=1 AND c.contact_mode='MESSENGER')
          AND EXISTS (SELECT FROM foundation.request_channel_choices ch WHERE ch.request_id=e.request_id AND
            ((r.resulting_status='WAITING_TELEGRAM_LINK' AND ch.provider='TG')
              OR (r.resulting_status='WAITING_CHANNEL_LINK' AND ch.provider IN ('VK','MAX'))))
          THEN 'NONE'
        ELSE 'INVALID' END
      WHEN e.command='ChooseCallback' THEN CASE WHEN e.actor_type='F' AND r.resulting_status='CALLBACK_REQUIRED'
        AND EXISTS (SELECT FROM foundation.request_session_submits s
          JOIN foundation.request_events intake ON (intake.id,intake.request_id)=(s.event_id,s.request_id)
          JOIN foundation.request_command_receipts first ON (first.event_id,first.request_id,first.version,first.correlation_id,first.command)
            =(intake.id,intake.request_id,intake.resulting_version,intake.correlation_id,intake.command)
          JOIN foundation.request_channel_choices ch ON ch.request_id=s.request_id
          JOIN foundation.request_preference_revisions initial ON initial.request_id=s.request_id AND initial.revision=1
          WHERE s.request_id=e.request_id AND s.session_id=e.actor_session_id AND s.submit_command='CreateRepair'
            AND intake.command='CreateRepair' AND intake.actor_type='F' AND intake.actor_session_id=s.session_id
            AND first.version=1 AND initial.contact_mode='MESSENGER'
            AND first.resulting_status=intake.details->>'status'
            AND ((first.resulting_status='WAITING_TELEGRAM_LINK' AND ch.provider='TG')
              OR (first.resulting_status='WAITING_CHANNEL_LINK' AND ch.provider IN ('VK','MAX'))))
        AND EXISTS (SELECT FROM foundation.request_events prior
          JOIN foundation.request_command_receipts p ON (p.event_id,p.request_id,p.version,p.correlation_id,p.command)
            =(prior.id,prior.request_id,prior.resulting_version,prior.correlation_id,prior.command)
          WHERE prior.request_id=e.request_id AND prior.resulting_version=e.resulting_version-1
            AND p.resulting_status=prior.details->>'status'
            AND p.resulting_status IN ('WAITING_TELEGRAM_LINK','WAITING_CHANNEL_LINK'))
        AND EXISTS (SELECT FROM foundation.request_preference_revisions next
          JOIN LATERAL (SELECT pr.contact_mode,pr.urgency,pr.preferred_windows
            FROM foundation.request_preference_revisions pr WHERE pr.request_id=e.request_id AND pr.revision<e.resulting_version
            ORDER BY pr.revision DESC LIMIT 1) prior ON true
          WHERE next.request_id=e.request_id AND next.revision=e.resulting_version AND next.contact_mode='PHONE'
            AND prior.contact_mode='MESSENGER' AND next.urgency IS NOT DISTINCT FROM prior.urgency
            AND next.preferred_windows IS NOT DISTINCT FROM prior.preferred_windows
            AND NOT EXISTS (SELECT FROM foundation.requests q WHERE q.id=e.request_id AND q.row_version=e.resulting_version
              AND (q.current_preference_revision_id IS DISTINCT FROM next.id OR q.type<>'REPAIR' OR q.status<>'CALLBACK_REQUIRED')))
        THEN 'GIVEN' ELSE 'INVALID' END
      WHEN e.command='WithdrawPhonePermission' THEN 'REVOKED'
      ELSE 'NONE' END AS action) expected))`;

/** Joined effect readiness on a known S3 client. The caller gates the physical
 * profile separately; the same predicate is usable inside a transaction before
 * its constraints have run, without relaxing checks or committing bad data. */
export async function requestEffectsHistoryComplete(client: Pick<PoolClient,'query'>): Promise<boolean> {
  const { rows: [state] } = await client.query<{ complete: boolean }>(`SELECT
    NOT EXISTS (SELECT FROM foundation.requests q WHERE NOT EXISTS (
      SELECT FROM foundation.request_command_receipts r WHERE r.request_id=q.id AND r.version=q.row_version))
    AND NOT EXISTS (SELECT FROM foundation.request_events e
      LEFT JOIN foundation.request_command_receipts r ON (r.event_id,r.request_id,r.version,r.correlation_id,r.command)
        =(e.id,e.request_id,e.resulting_version,e.correlation_id,e.command)
      LEFT JOIN foundation.audit_logs a ON a.id=r.audit_id
      LEFT JOIN foundation.outbox_events o ON o.id=r.outbox_id
      WHERE NOT coalesce(r.resulting_status=e.details->>'status' AND a.operation=e.command
        AND a.correlation_id=e.correlation_id AND a.details->>'requestId'=e.request_id::text
        AND o.event_id=e.id AND o.event_type=CASE e.command WHEN 'CreateCallback' THEN 'REQUEST_CALLBACK_INTENT'
          WHEN 'ReadyForDispatch' THEN 'REQUEST_READY_FOR_ASSIGNMENT' ELSE 'REQUEST_EFFECT_RECORDED' END
        AND o.payload->>'requestId'=e.request_id::text
        AND o.payload->>'version'=e.resulting_version::text,false)
        OR NOT ${REQUEST_PHONE_HISTORY_COMPLETE}
        OR (e.command IN ('CreateCallback','CreateRepair') AND ((e.actor_type='F' AND NOT EXISTS (
          SELECT FROM foundation.request_session_submits s WHERE s.event_id=e.id AND s.request_id=e.request_id
            AND s.session_id=e.actor_session_id AND s.submit_command=e.command)) OR (e.actor_type='STAFF' AND NOT EXISTS (
          SELECT FROM foundation.request_staff_evidence s WHERE s.request_id=e.request_id AND s.staff_id=e.actor_staff_id
            AND s.purpose='MANUAL_INTAKE'))))) AS complete`);
  return state?.complete === true;
}
