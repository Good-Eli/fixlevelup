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
    request_version integer NOT NULL CHECK (request_version > 0),
    idempotency_key uuid NOT NULL,
    idem_key_id text NOT NULL,
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 8192),
    auth_tag bytea NOT NULL CHECK (octet_length(auth_tag) = 16),
    aad_context text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (request_id,author_id,idempotency_key)
);

CREATE INDEX comments_request_time_idx ON p06_crm.comments(request_id,created_at DESC,id DESC);

CREATE FUNCTION p06_crm.check_comment_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM foundation.requests AS request
        JOIN p06_crm.comment_grants AS permission ON permission.city_id = request.city_id
        JOIN foundation.staff AS staff ON staff.id = permission.staff_id
        WHERE request.id = NEW.request_id AND request.row_version = NEW.request_version
          AND staff.id = NEW.author_id AND staff.employment_state = 'ACTIVE'
          AND permission.can_read AND permission.can_write
    ) THEN
        RAISE EXCEPTION 'Invalid internal comment binding' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER check_comment_binding BEFORE INSERT ON p06_crm.comments
    FOR EACH ROW EXECUTE FUNCTION p06_crm.check_comment_binding();
REVOKE ALL ON FUNCTION p06_crm.check_comment_binding() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION p06_crm.check_comment_binding() TO fixlevelup_runtime;

GRANT SELECT ON p06_crm.comment_grants,p06_crm.contact_grants,p06_crm.comments TO fixlevelup_runtime;
GRANT INSERT (id,request_id,author_id,request_version,idempotency_key,idem_key_id,fingerprint,nonce,ciphertext,auth_tag,aad_context)
    ON p06_crm.comments TO fixlevelup_runtime;

COMMIT;
