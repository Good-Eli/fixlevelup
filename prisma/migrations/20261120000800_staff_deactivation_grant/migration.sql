BEGIN;

-- P02-06 staff deactivation (POST /api/v1/staff/{id}/deactivate): the runtime role
-- needs to flip employment_state only. UPDATE stays column-scoped exactly like the
-- existing auth_version grant from 20261120000500_web_auth: role stays unwritable,
-- DELETE/TRUNCATE stay denied, so the staff row (history) survives deactivation.
-- No SECURITY DEFINER here on purpose: deactivation runs inside the caller's
-- authorizeForWrite transaction on the same staff row locks; a definer function
-- would add an owned-code surface without reducing any privilege.
-- Both auth channels already fail closed on
-- employment_state = 'ACTIVE' AND ws.auth_version = s.auth_version
-- (WebAuthService/TelegramAuthService, P02-03/P02-05), so deactivation only has to
-- set INACTIVE and bump auth_version; sessions are never deleted.
GRANT UPDATE ("employment_state") ON "foundation"."staff" TO "fixlevelup_runtime";

COMMIT;
