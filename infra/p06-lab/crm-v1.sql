-- P06 isolated CRM overlay. No inbound triggers on the pinned S3 tables.
BEGIN;

CREATE SCHEMA p06_crm;
REVOKE ALL ON SCHEMA p06_crm FROM PUBLIC;
GRANT USAGE ON SCHEMA p06_crm TO fixlevelup_runtime;

CREATE TABLE p06_crm.comment_grants (
    staff_id uuid NOT NULL,
    city_id uuid NOT NULL,
    can_read boolean NOT NULL,
    can_write boolean NOT NULL CHECK (NOT can_write OR can_read),
    PRIMARY KEY (staff_id,city_id)
);

CREATE TABLE p06_crm.contact_grants (
    staff_id uuid NOT NULL,
    city_id uuid NOT NULL,
    capability text NOT NULL CHECK (capability = 'customer.pii.read'),
    PRIMARY KEY (staff_id,city_id,capability)
);

CREATE TABLE p06_crm.comments (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    author_id uuid NOT NULL,
    auth_session_id uuid NOT NULL REFERENCES foundation.web_sessions(id) ON DELETE RESTRICT,
    request_version integer NOT NULL CHECK (request_version > 0),
    idempotency_key uuid NOT NULL,
    idem_key_id text NOT NULL,
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 8192),
    auth_tag bytea NOT NULL CHECK (octet_length(auth_tag) = 16),
    aad_context text NOT NULL,
    audit_id uuid NOT NULL UNIQUE REFERENCES foundation.audit_logs(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (request_id,author_id,idempotency_key)
);

CREATE INDEX comments_request_time_idx ON p06_crm.comments(request_id,created_at DESC,id DESC);

-- The table is read-only to the application role. Every write goes through the
-- SECURITY DEFINER function below, which performs the DB-verifiable P05 checks
-- and writes its audit row in the same transaction. The trigger is a second,
-- non-bypassable check on the row actually being inserted.
CREATE FUNCTION p06_crm.check_comment_binding() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF session_user <> 'fixlevelup_runtime' THEN
        RAISE EXCEPTION 'Internal comment writer is not admitted' USING ERRCODE = '42501';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock_shared(
        pg_catalog.hashtextextended('fixlevelup:admin-invariant',0)
    );

    IF NOT EXISTS (
        SELECT 1
        FROM foundation.requests AS request
        JOIN foundation.staff AS staff
          ON staff.id = NEW.author_id AND staff.employment_state = 'ACTIVE'
          AND staff.role IN ('ADMIN','MANAGER')
        JOIN foundation.web_sessions AS web_session
          ON web_session.id = NEW.auth_session_id AND web_session.staff_id = staff.id
          AND web_session.auth_version = staff.auth_version AND web_session.channel = 'CRM'
          AND web_session.telegram_link_id IS NULL AND web_session.revoked_at IS NULL
          AND web_session.idle_expires_at > statement_timestamp()
          AND web_session.absolute_expires_at > statement_timestamp()
        JOIN foundation.staff_role_assignments AS assignment
          ON assignment.staff_id = staff.id AND assignment.revoked_at IS NULL
        JOIN foundation.roles AS role
          ON role.id = assignment.role_id AND role.status = 'ACTIVE'
        JOIN foundation.role_permissions AS role_permission
          ON role_permission.role_id = role.id AND role_permission.permission_code = 'requests.read'
          AND role_permission.enabled
        JOIN foundation.permissions AS permission
          ON permission.code = role_permission.permission_code AND permission.active
          AND NOT permission.protected AND permission.module = 'requests'
        JOIN p06_crm.comment_grants AS comment_grant
          ON comment_grant.staff_id = staff.id AND comment_grant.city_id = request.city_id
          AND comment_grant.can_read AND comment_grant.can_write
        JOIN foundation.audit_logs AS audit
          ON audit.id = NEW.audit_id AND audit.operation = 'P06_ADD_INTERNAL_COMMENT'
          AND audit.correlation_id = NEW.id
          AND audit.details @> jsonb_build_object(
            'requestId',NEW.request_id::text,
            'commentId',NEW.id::text,
            'actorId',NEW.author_id::text,
            'sessionId',NEW.auth_session_id::text,
            'version',NEW.request_version
          )
        WHERE request.id = NEW.request_id AND request.row_version = NEW.request_version
          AND (
            (role.role_type = 'SYSTEM' AND role.code = staff.role)
            OR (role.role_type = 'CUSTOM' AND staff.role = 'MANAGER')
          )
          AND (
            (role.role_type = 'SYSTEM' AND role.code = 'ADMIN'
              AND role_permission.scope_type IN ('CITY','GLOBAL'))
            OR (role.role_type = 'SYSTEM' AND role.code = 'MANAGER'
              AND role_permission.scope_type = 'CITY')
            OR (role.role_type = 'CUSTOM' AND staff.role = 'MANAGER'
              AND role_permission.scope_type = 'CITY')
          )
          AND (
            (role_permission.scope_type = 'GLOBAL' AND role.role_type = 'SYSTEM' AND role.code = 'ADMIN')
            OR (role_permission.scope_type = 'CITY' AND EXISTS (
              SELECT 1 FROM foundation.staff_admin_city_assignments city_assignment
              WHERE city_assignment.staff_id = staff.id
                AND city_assignment.city_id = request.city_id
                AND city_assignment.revoked_at IS NULL
            ))
          )
          AND (
            EXISTS (
              SELECT 1
              FROM foundation.request_session_submits AS submit
              JOIN foundation.consent_records AS consent
                ON consent.id = submit.consent_id AND consent.session_id = submit.session_id
                AND consent.document_id = submit.document_id
                AND consent.document_version_id = submit.document_version_id
              JOIN foundation.legal_documents AS document
                ON document.id = submit.document_id AND document.current_version_id = submit.document_version_id
              WHERE submit.request_id = request.id
                AND consent.purpose = 'REQUEST_PROCESSING' AND consent.action = 'GIVEN'
                AND consent.source = 'FORM'
                AND document.purpose = 'REQUEST_PROCESSING' AND document.kind = 'CONSENT_FORM'
                AND NOT EXISTS (
                  SELECT 1 FROM foundation.consent_records AS revoked
                  WHERE revoked.supersedes_id = consent.id
                )
            )
            OR (
              NOT EXISTS (SELECT 1 FROM foundation.request_session_submits submit
                WHERE submit.request_id = request.id)
              AND EXISTS (
                SELECT 1 FROM foundation.request_staff_evidence AS evidence
                WHERE evidence.request_id = request.id AND evidence.purpose = 'MANUAL_INTAKE'
                  AND evidence.valid_until > statement_timestamp()
              )
            )
          )
    ) THEN
        RAISE EXCEPTION 'Invalid internal comment binding' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER check_comment_binding BEFORE INSERT ON p06_crm.comments
    FOR EACH ROW EXECUTE FUNCTION p06_crm.check_comment_binding();
REVOKE ALL ON FUNCTION p06_crm.check_comment_binding() FROM PUBLIC,fixlevelup_runtime;

-- There is intentionally no INSERT grant on comments. This narrow function
-- binds the authenticated CRM session, current P05 read authority, CITY/GLOBAL
-- scope, the independent comment grant and the DB-resident processing basis;
-- it then writes the audit and comment atomically. Application code additionally
-- verifies the out-of-database manual-evidence issuer and the durable key slot.
CREATE FUNCTION p06_crm.insert_internal_comment(
    p_comment_id uuid,
    p_request_id uuid,
    p_author_id uuid,
    p_auth_session_id uuid,
    p_request_version integer,
    p_idempotency_key uuid,
    p_idem_key_id text,
    p_fingerprint bytea,
    p_nonce bytea,
    p_ciphertext bytea,
    p_auth_tag bytea,
    p_aad_context text,
    p_audit_id uuid
) RETURNS TABLE(id uuid, request_version integer, created_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF session_user <> 'fixlevelup_runtime' THEN
        RAISE EXCEPTION 'Internal comment writer is not admitted' USING ERRCODE = '42501';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock_shared(
        pg_catalog.hashtextextended('fixlevelup:admin-invariant',0)
    );

    INSERT INTO foundation.audit_logs(id,operation,correlation_id,details)
    VALUES (
      p_audit_id,
      'P06_ADD_INTERNAL_COMMENT',
      p_comment_id,
      jsonb_build_object(
        'requestId',p_request_id::text,
        'commentId',p_comment_id::text,
        'actorId',p_author_id::text,
        'sessionId',p_auth_session_id::text,
        'version',p_request_version
      )
    );

    RETURN QUERY
      INSERT INTO p06_crm.comments(
        id,request_id,author_id,auth_session_id,request_version,idempotency_key,idem_key_id,
        fingerprint,nonce,ciphertext,auth_tag,aad_context,audit_id
      )
      VALUES (
        p_comment_id,p_request_id,p_author_id,p_auth_session_id,p_request_version,p_idempotency_key,p_idem_key_id,
        p_fingerprint,p_nonce,p_ciphertext,p_auth_tag,p_aad_context,p_audit_id
      )
      RETURNING p06_crm.comments.id,p06_crm.comments.request_version,p06_crm.comments.created_at;
END;
$$;

REVOKE ALL ON FUNCTION p06_crm.insert_internal_comment(
    uuid,uuid,uuid,uuid,integer,uuid,text,bytea,bytea,bytea,bytea,text,uuid
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION p06_crm.insert_internal_comment(
    uuid,uuid,uuid,uuid,integer,uuid,text,bytea,bytea,bytea,bytea,text,uuid
) TO fixlevelup_runtime;

GRANT SELECT ON p06_crm.comment_grants,p06_crm.contact_grants,p06_crm.comments TO fixlevelup_runtime;
REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON p06_crm.comments FROM PUBLIC,fixlevelup_runtime;

COMMIT;
