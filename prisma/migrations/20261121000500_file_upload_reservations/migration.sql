BEGIN;

-- P03-04 slice A: file-upload reservation intents (migration 014).
-- Data layer only and additive: one new table, one FK-target index on the existing
-- consent evidence table, and no change to any existing 013 table, column, constraint
-- or grant. No seed, no real operator/policy value, no object key, no file row, no
-- READY state, no byte IO, no scanner, no signed URL and no write to any working
-- database.
--
-- Deliberate non-goals:
--   * no byte transfer, no S3/object storage adapter, no download/stream ticket and
--     no READY/UPLOADING/DELETED state: this slice only reserves future capacity, so
--     the state vocabulary is exactly RESERVED and CANCELLED;
--   * no production quota, TTL, retention duration or policy text: every numeric
--     value is supplied by the trusted reviewed policy snapshot of the caller and is
--     stored verbatim as an immutable snapshot, never as a default;
--   * no SECURITY DEFINER function and no function EXECUTE privilege for the runtime:
--     every guard is SECURITY INVOKER with a fixed search_path and is reached through
--     triggers, not through a callable API;
--   * no DELETE or TRUNCATE privilege: an intent is history and is cancelled, never
--     deleted;
--   * no staff-owner caller path: the staff FK exists for the future P03-05 workflow,
--     but the runtime has no INSERT privilege on owner_staff_id, so a runtime caller
--     cannot create a staff-owned intent at all. A staff id from a request body is
--     never a credential.
--
-- Immutability model: the owner, the exact consent basis, the policy snapshot, the
-- declared MIME/bytes and the expiry are immutable for ordinary DML (including the
-- owner). The only transition is RESERVED -> CANCELLED; the database owns
-- created_at, the initial state/row_version, cancelled_at and row_version, so a
-- caller can never keep row_version constant and defeat the optimistic lock. A
-- caller uses
--   UPDATE ... SET state='CANCELLED' WHERE id=$1 AND owner_request_session_id=$2
--     AND state='RESERVED' AND row_version=$expected RETURNING ...
-- and retries on zero rows.
--
-- Lock order: request session anchor first, legal document second (the same order as
-- 013's consent write path). Nothing here takes those locks in the opposite order,
-- and no file -> session lock exists.

-- ---------------------------------------------------------------------------
-- 1. Consent-basis FK target on the existing 013 evidence table.
-- ---------------------------------------------------------------------------
-- Additive index only: no column, constraint or grant of consent_records changes.
-- `id` is the primary key, so this composite is unique by construction and can never
-- conflict with the legitimate GIVEN -> REVOKED -> GIVEN cycle of one
-- (session, purpose, document, version): those events differ by id. The index makes
-- one reference prove that the named consent event belongs to the same session, the
-- same document version and the same purpose as the intent.
CREATE UNIQUE INDEX consent_records_intent_basis_key
    ON foundation.consent_records(id,session_id,document_version_id,purpose);

-- ---------------------------------------------------------------------------
-- 2. Reservation intents: immutable owner/basis/policy snapshot, cancel only.
-- ---------------------------------------------------------------------------
-- Exactly one owner: an F-owned intent names a real pre-submit request session; the
-- staff variant exists only as schema shape for the future staff workflow (see the
-- ACL section). A request-session intent must carry the exact consent basis
-- (evidence id, document version id and purpose); a staff intent keeps all three
-- NULL and the composite FK is then skipped (MATCH SIMPLE), so a staff row can never
-- borrow a request session's consent evidence.
--
-- The policy snapshot is stored as typed columns, never as an opaque settings JSON:
-- version id, reviewed source reference, canonical SHA-256, closed MIME allowlist and
-- the three quotas. policy_expires_at is mandatory because a reservation must always
-- be able to prove which reviewed policy it was granted under; there is no default
-- policy and no default TTL anywhere in this migration.
--
-- MIME vocabulary is closed and technical only (PDF, JPEG, PNG, WebP). It is not
-- permission to upload or serve these types: the actual signature/byte check belongs
-- to slice B, and SVG/HTML/executables are deliberately absent.
CREATE TABLE foundation.file_upload_intents (
    id uuid PRIMARY KEY,
    owner_request_session_id uuid,
    owner_staff_id uuid,
    consent_record_id uuid,
    consent_document_version_id uuid,
    consent_purpose varchar(32),
    policy_version_id uuid NOT NULL,
    policy_source_ref text NOT NULL,
    policy_sha256 varchar(64) NOT NULL,
    allowed_mime_types jsonb NOT NULL,
    max_file_bytes bigint NOT NULL,
    max_owner_bytes bigint NOT NULL,
    max_owner_files integer NOT NULL,
    policy_expires_at timestamptz(6) NOT NULL,
    declared_mime varchar(100) NOT NULL,
    declared_bytes bigint NOT NULL,
    expires_at timestamptz(6) NOT NULL,
    created_at timestamptz(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    idempotency_key uuid NOT NULL,
    body_sha256 varchar(64) NOT NULL,
    state varchar(16) NOT NULL,
    cancelled_at timestamptz(6),
    row_version integer NOT NULL DEFAULT 1,
    CONSTRAINT file_upload_intents_owner_request_session_id_fkey FOREIGN KEY (owner_request_session_id)
        REFERENCES foundation.request_sessions(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT file_upload_intents_owner_staff_id_fkey FOREIGN KEY (owner_staff_id)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    -- Composite consent-basis FK: the referenced event must be of this session, this
    -- document version and this purpose in one reference. It cannot prove GIVEN /
    -- unrevoked / current - the INSERT guard below does that under the locks.
    CONSTRAINT file_upload_intents_consent_basis_fkey
        FOREIGN KEY (consent_record_id,owner_request_session_id,consent_document_version_id,consent_purpose)
        REFERENCES foundation.consent_records(id,session_id,document_version_id,purpose)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT file_upload_intents_owner_xor_check CHECK (
        num_nonnulls(owner_request_session_id,owner_staff_id) = 1),
    CONSTRAINT file_upload_intents_owner_basis_check CHECK (
        (owner_request_session_id IS NOT NULL
            AND consent_record_id IS NOT NULL
            AND consent_document_version_id IS NOT NULL
            AND consent_purpose = 'REQUEST_PROCESSING')
        OR (owner_staff_id IS NOT NULL
            AND consent_record_id IS NULL
            AND consent_document_version_id IS NULL
            AND consent_purpose IS NULL)),
    CONSTRAINT file_upload_intents_state_check CHECK (state IN ('RESERVED','CANCELLED')),
    CONSTRAINT file_upload_intents_state_stamp_check CHECK (
        (state = 'RESERVED' AND cancelled_at IS NULL)
        OR (state = 'CANCELLED' AND cancelled_at IS NOT NULL)),
    CONSTRAINT file_upload_intents_row_version_check CHECK (row_version >= 1),
    CONSTRAINT file_upload_intents_policy_sha256_check CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT file_upload_intents_body_sha256_check CHECK (body_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT file_upload_intents_policy_source_ref_check CHECK (
        policy_source_ref ~ '[^[:space:]]' AND length(policy_source_ref) <= 500),
    -- Closed, bounded MIME allowlist. `?` is the built-in jsonb membership operator,
    -- so no user-defined validator function (and therefore no runtime EXECUTE grant)
    -- is needed. The containment test rejects any element outside the closed set and
    -- any non-string element.
    CONSTRAINT file_upload_intents_mime_allowlist_check CHECK (
        jsonb_typeof(allowed_mime_types) = 'array'
        AND jsonb_array_length(allowed_mime_types) BETWEEN 1 AND 4
        AND allowed_mime_types <@ '["application/pdf","image/jpeg","image/png","image/webp"]'::jsonb),
    CONSTRAINT file_upload_intents_declared_mime_check CHECK (
        declared_mime IN ('application/pdf','image/jpeg','image/png','image/webp')),
    CONSTRAINT file_upload_intents_declared_mime_allowed_check CHECK (
        allowed_mime_types ? (declared_mime)::text),
    -- Sizes are positive, ordered and bounded by the JavaScript safe-integer ceiling:
    -- a bigint column may hold more, but a value the ports could not compare exactly
    -- must never be persisted as a quota.
    CONSTRAINT file_upload_intents_size_check CHECK (
        declared_bytes >= 1 AND max_file_bytes >= declared_bytes AND max_owner_bytes >= max_file_bytes),
    CONSTRAINT file_upload_intents_safe_integer_check CHECK (
        max_file_bytes <= 9007199254740991
        AND max_owner_bytes <= 9007199254740991
        AND declared_bytes <= 9007199254740991),
    CONSTRAINT file_upload_intents_max_owner_files_check CHECK (max_owner_files >= 1),
    -- Database-clock ordering: created_at is stamped by the INSERT guard, so a
    -- reservation can never be created already expired or already past its policy.
    CONSTRAINT file_upload_intents_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT file_upload_intents_policy_expiry_check CHECK (policy_expires_at > created_at),
    CONSTRAINT file_upload_intents_expires_policy_check CHECK (expires_at <= policy_expires_at)
);

-- One idempotency key per owner. Partial unique indexes keep one namespace per owner
-- variant without a nullable tenant column; a duplicate is a 23505 that the
-- application turns into IDEMPOTENCY_CONFLICT after re-reading the stored payload.
CREATE UNIQUE INDEX file_upload_intents_session_idempotency_key
    ON foundation.file_upload_intents(owner_request_session_id,idempotency_key)
    WHERE owner_request_session_id IS NOT NULL;
CREATE UNIQUE INDEX file_upload_intents_staff_idempotency_key
    ON foundation.file_upload_intents(owner_staff_id,idempotency_key)
    WHERE owner_staff_id IS NOT NULL;
-- Pending-quota scans of one owner only ever look at live RESERVED rows.
CREATE INDEX file_upload_intents_session_pending_idx
    ON foundation.file_upload_intents(owner_request_session_id,state,expires_at)
    WHERE owner_request_session_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 3. INSERT guard: database-owned stamps, live proof, exact current GIVEN, quota.
-- ---------------------------------------------------------------------------
-- The guard is the second, independent line of defence: the ports already check all
-- of this under the same locks, but a caller that bypasses them cannot write a
-- reservation the database would refuse.
--
-- 1. Explicit READ COMMITTED is part of the rule. A transaction that pinned a
--    stronger snapshot could still see a REVOKED consent event as active or count a
--    stale quota; a direct runtime INSERT inside REPEATABLE READ is therefore
--    refused with SQLSTATE 25001 (the retryable code the ports already map to
--    CONFLICT), before any lock is taken.
-- 2. Lock order is request session -> legal document, the same order as 013.
-- 3. created_at, state, cancelled_at and row_version are database-owned: a caller
--    cannot backdate a reservation, fabricate a CANCELLED row or keep row_version
--    constant.
-- 4. After the last lock the database clock is sampled again and the anchor
--    liveness, the policy expiry and the intent expiry are re-proven against that
--    same instant, so waiting for the document lock can never let an expired
--    reservation through. A reservation may not outlive its session anchor or its
--    policy snapshot.
-- 5. The quota counts only state='RESERVED' AND expires_at > clock rows of the same
--    owner and compares them with the *new* policy snapshot. The session row lock
--    held from step 2 serializes every reservation of one owner, so two concurrent
--    reservations of the last slot/byte cannot both commit.
CREATE FUNCTION foundation.file_upload_intents_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    isolation text;
    anchor_revoked timestamptz;
    anchor_expires timestamptz;
    consent_action varchar(16);
    consent_session uuid;
    consent_version uuid;
    consent_purpose_value varchar(32);
    consent_document uuid;
    document_kind varchar(24);
    document_current uuid;
    document_purpose varchar(32);
    accepted_at timestamptz;
    active_count integer;
    active_bytes bigint;
    active_elements integer;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'File upload intents are history; cancel instead of delete'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_history';
    END IF;

    IF TG_OP = 'UPDATE' THEN
        -- Exactly one transition, one way, and no second UPDATE at all: a CANCELLED
        -- row is terminal. There is no READY and no un-cancel.
        IF OLD.state <> 'RESERVED' OR NEW.state <> 'CANCELLED' THEN
            RAISE EXCEPTION 'File upload intent transition is exactly RESERVED -> CANCELLED'
                USING ERRCODE='23514', CONSTRAINT='file_upload_intents_state_transition';
        END IF;
        -- Everything but state/cancelled_at/row_version is an immutable snapshot. The
        -- guard refuses a caller that tries to change the owner, the basis, the policy
        -- or the declared size, so a cancel can never rewrite what was reserved.
        IF NEW.id IS DISTINCT FROM OLD.id
            OR NEW.owner_request_session_id IS DISTINCT FROM OLD.owner_request_session_id
            OR NEW.owner_staff_id IS DISTINCT FROM OLD.owner_staff_id
            OR NEW.consent_record_id IS DISTINCT FROM OLD.consent_record_id
            OR NEW.consent_document_version_id IS DISTINCT FROM OLD.consent_document_version_id
            OR NEW.consent_purpose IS DISTINCT FROM OLD.consent_purpose
            OR NEW.policy_version_id IS DISTINCT FROM OLD.policy_version_id
            OR NEW.policy_source_ref IS DISTINCT FROM OLD.policy_source_ref
            OR NEW.policy_sha256 IS DISTINCT FROM OLD.policy_sha256
            OR NEW.allowed_mime_types IS DISTINCT FROM OLD.allowed_mime_types
            OR NEW.max_file_bytes IS DISTINCT FROM OLD.max_file_bytes
            OR NEW.max_owner_bytes IS DISTINCT FROM OLD.max_owner_bytes
            OR NEW.max_owner_files IS DISTINCT FROM OLD.max_owner_files
            OR NEW.policy_expires_at IS DISTINCT FROM OLD.policy_expires_at
            OR NEW.declared_mime IS DISTINCT FROM OLD.declared_mime
            OR NEW.declared_bytes IS DISTINCT FROM OLD.declared_bytes
            OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
            OR NEW.created_at IS DISTINCT FROM OLD.created_at
            OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
            OR NEW.body_sha256 IS DISTINCT FROM OLD.body_sha256 THEN
            RAISE EXCEPTION 'File upload intent owner, basis, policy and declared size are immutable'
                USING ERRCODE='23514', CONSTRAINT='file_upload_intents_immutable';
        END IF;
        -- The database owns both the cancel stamp and the row version: a caller
        -- supplies only state and the expected version.
        NEW.cancelled_at := clock_timestamp();
        NEW.row_version := OLD.row_version + 1;
        RETURN NEW;
    END IF;

    -- ---------------- INSERT ----------------
    isolation := current_setting('transaction_isolation');
    IF isolation <> 'read committed' THEN
        RAISE EXCEPTION 'File upload reservation requires an explicit READ COMMITTED transaction (got %)', isolation
            USING ERRCODE='25001', CONSTRAINT='file_upload_intents_isolation';
    END IF;

    -- Database-owned stamps, forced before any CHECK: an owner-level INSERT cannot
    -- fabricate a CANCELLED row, a backdated created_at or a non-initial row_version.
    accepted_at := clock_timestamp();
    NEW.created_at := accepted_at;
    NEW.state := 'RESERVED';
    NEW.cancelled_at := NULL;
    NEW.row_version := 1;

    IF NEW.owner_request_session_id IS NULL THEN
        -- Staff-owned shape only (the runtime cannot reach it: no INSERT privilege on
        -- owner_staff_id). No consent basis, no session lock; the same policy and
        -- expiry rules and the staff-scoped quota still apply.
        IF NEW.consent_record_id IS NOT NULL OR NEW.consent_document_version_id IS NOT NULL
            OR NEW.consent_purpose IS NOT NULL THEN
            RAISE EXCEPTION 'A staff-owned file upload intent carries no request consent basis'
                USING ERRCODE='23514', CONSTRAINT='file_upload_intents_consent';
        END IF;
        IF NEW.policy_expires_at <= accepted_at THEN
            RAISE EXCEPTION 'File upload policy snapshot is already expired'
                USING ERRCODE='23514', CONSTRAINT='file_upload_intents_policy';
        END IF;
        IF NEW.expires_at <= accepted_at THEN
            RAISE EXCEPTION 'File upload intent expiry must be after the database clock'
                USING ERRCODE='23514', CONSTRAINT='file_upload_intents_expiry';
        END IF;
        IF NEW.expires_at > NEW.policy_expires_at THEN
            RAISE EXCEPTION 'File upload intent may not outlive its policy snapshot'
                USING ERRCODE='23514', CONSTRAINT='file_upload_intents_policy';
        END IF;
        SELECT count(*)::int, COALESCE(sum(declared_bytes),0)
          INTO active_count, active_bytes
          FROM foundation.file_upload_intents
         WHERE owner_staff_id = NEW.owner_staff_id
           AND state = 'RESERVED' AND expires_at > accepted_at;
        IF active_count + 1 > NEW.max_owner_files THEN
            RAISE EXCEPTION 'File upload reservation exceeds the owner file quota'
                USING ERRCODE='23514', CONSTRAINT='file_upload_intents_quota';
        END IF;
        IF active_bytes + NEW.declared_bytes > NEW.max_owner_bytes THEN
            RAISE EXCEPTION 'File upload reservation exceeds the owner byte quota'
                USING ERRCODE='23514', CONSTRAINT='file_upload_intents_quota';
        END IF;
        RETURN NEW;
    END IF;

    -- ---------------- F-owned (request session) INSERT ----------------
    IF NEW.consent_record_id IS NULL OR NEW.consent_document_version_id IS NULL
        OR NEW.consent_purpose IS NULL THEN
        RAISE EXCEPTION 'A request session file upload intent requires an exact consent basis'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_consent';
    END IF;

    -- Lock 1: the anchor row. The lock is held to the end of the statement, so no
    -- concurrent revoke of this anchor and no other reservation of this owner can
    -- commit while this decision is made.
    SELECT s.revoked_at, s.expires_at INTO anchor_revoked, anchor_expires
      FROM foundation.request_sessions s WHERE s.id = NEW.owner_request_session_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'File upload intent needs an existing request session anchor'
            USING ERRCODE='23503', CONSTRAINT='file_upload_intents_owner_request_session_id_fkey';
    END IF;
    IF anchor_revoked IS NOT NULL THEN
        RAISE EXCEPTION 'File upload intent needs a live request session anchor'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_session';
    END IF;
    IF anchor_expires <= accepted_at THEN
        RAISE EXCEPTION 'File upload intent needs an unexpired request session anchor'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_session';
    END IF;

    -- The named evidence must be this anchor's event of this version and purpose. The
    -- composite FK proves the same tuple, but the BEFORE trigger runs before the FK
    -- check, so it is re-proven here to keep the refusal precise.
    SELECT c.action, c.session_id, c.document_version_id, c.purpose, c.document_id
      INTO consent_action, consent_session, consent_version, consent_purpose_value, consent_document
      FROM foundation.consent_records c WHERE c.id = NEW.consent_record_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'File upload intent needs an existing consent evidence row'
            USING ERRCODE='23503', CONSTRAINT='file_upload_intents_consent_basis_fkey';
    END IF;
    IF consent_session IS DISTINCT FROM NEW.owner_request_session_id
        OR consent_version IS DISTINCT FROM NEW.consent_document_version_id
        OR consent_purpose_value IS DISTINCT FROM NEW.consent_purpose THEN
        -- The tuple is a foreign-key mismatch (the evidence belongs to another
        -- session/version/purpose), so it is reported as a reference violation.
        RAISE EXCEPTION 'File upload intent consent basis must match its session, version and purpose'
            USING ERRCODE='23503', CONSTRAINT='file_upload_intents_consent_basis_fkey';
    END IF;
    IF consent_action <> 'GIVEN' THEN
        RAISE EXCEPTION 'File upload intent needs a GIVEN consent event'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_consent';
    END IF;
    IF EXISTS (SELECT 1 FROM foundation.consent_records r WHERE r.supersedes_id = NEW.consent_record_id) THEN
        RAISE EXCEPTION 'File upload intent consent event is revoked'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_consent';
    END IF;

    -- Lock 2: the legal document. Same order as 013's consent path (anchor then
    -- document), so a publish/consent write and this reservation serialize on one row.
    SELECT d.kind, d.current_version_id, d.purpose INTO document_kind, document_current, document_purpose
      FROM foundation.legal_documents d WHERE d.id = consent_document FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'File upload intent needs an existing consent form document'
            USING ERRCODE='23503', CONSTRAINT='file_upload_intents_consent_basis_fkey';
    END IF;
    IF document_kind <> 'CONSENT_FORM' THEN
        RAISE EXCEPTION 'File upload intent consent basis must be a CONSENT_FORM document'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_consent';
    END IF;
    IF document_current IS NULL OR document_current IS DISTINCT FROM NEW.consent_document_version_id THEN
        RAISE EXCEPTION 'File upload intent consent basis must be the current document version'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_consent';
    END IF;
    IF document_purpose IS DISTINCT FROM NEW.consent_purpose THEN
        RAISE EXCEPTION 'File upload intent consent purpose must match its document'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_consent';
    END IF;

    -- Point of acceptance: the document lock above may have waited, so the clock is
    -- sampled again and every time rule is proven against that same instant.
    accepted_at := clock_timestamp();
    NEW.created_at := accepted_at;
    SELECT s.revoked_at, s.expires_at INTO anchor_revoked, anchor_expires
      FROM foundation.request_sessions s WHERE s.id = NEW.owner_request_session_id;
    IF anchor_revoked IS NOT NULL THEN
        RAISE EXCEPTION 'File upload intent anchor was revoked before the reservation was accepted'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_session';
    END IF;
    IF anchor_expires <= accepted_at THEN
        RAISE EXCEPTION 'File upload intent anchor expired before the reservation was accepted'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_session';
    END IF;
    IF NEW.policy_expires_at <= accepted_at THEN
        RAISE EXCEPTION 'File upload policy snapshot is already expired'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_policy';
    END IF;
    IF NEW.expires_at <= accepted_at THEN
        RAISE EXCEPTION 'File upload intent expiry must be after the database clock'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_expiry';
    END IF;
    IF NEW.expires_at > NEW.policy_expires_at THEN
        RAISE EXCEPTION 'File upload intent may not outlive its policy snapshot'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_policy';
    END IF;
    -- A reservation may not outlive its proof: the session expiry is the ceiling.
    IF NEW.expires_at > anchor_expires THEN
        RAISE EXCEPTION 'File upload intent may not outlive its request session anchor'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_policy';
    END IF;

    -- Allowlist integrity the CHECK cannot express: every element is a string and no
    -- MIME type repeats (the stored snapshot is a set).
    IF jsonb_typeof(NEW.allowed_mime_types) <> 'array' THEN
        RAISE EXCEPTION 'File upload policy allowlist must be a JSON array'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_policy';
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.allowed_mime_types) e
                WHERE jsonb_typeof(e.value) <> 'string') THEN
        RAISE EXCEPTION 'File upload policy allowlist holds a non-string entry'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_policy';
    END IF;
    SELECT jsonb_array_length(NEW.allowed_mime_types),
           (SELECT count(DISTINCT e.value)::int FROM jsonb_array_elements(NEW.allowed_mime_types) e)
      INTO active_elements, active_count;
    IF active_elements <> active_count THEN
        RAISE EXCEPTION 'File upload policy allowlist must not repeat a MIME type'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_policy';
    END IF;

    -- Quota: only live RESERVED rows of this owner count, so cancelled and expired
    -- intents release their slot, and an identical replay never consumes a second one
    -- (the replay path reads the stored row instead of inserting). The session lock
    -- held above serializes this count with every other reservation of the owner.
    SELECT count(*)::int, COALESCE(sum(declared_bytes),0)
      INTO active_count, active_bytes
      FROM foundation.file_upload_intents
     WHERE owner_request_session_id = NEW.owner_request_session_id
       AND state = 'RESERVED' AND expires_at > accepted_at;
    IF active_count + 1 > NEW.max_owner_files THEN
        RAISE EXCEPTION 'File upload reservation exceeds the owner file quota'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_quota';
    END IF;
    IF active_bytes + NEW.declared_bytes > NEW.max_owner_bytes THEN
        RAISE EXCEPTION 'File upload reservation exceeds the owner byte quota'
            USING ERRCODE='23514', CONSTRAINT='file_upload_intents_quota';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER file_upload_intents_guard BEFORE INSERT OR UPDATE OR DELETE ON foundation.file_upload_intents
    FOR EACH ROW EXECUTE FUNCTION foundation.file_upload_intents_guard();

-- Row triggers do not see TRUNCATE, so the whole history table is protected by a
-- statement trigger too.
CREATE FUNCTION foundation.file_upload_intents_reject_truncate() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'P03-04 file upload intents refuse TRUNCATE (%)', TG_TABLE_NAME USING ERRCODE='23514';
END $$;
CREATE TRIGGER file_upload_intents_reject_truncate BEFORE TRUNCATE ON foundation.file_upload_intents
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.file_upload_intents_reject_truncate();

-- ---------------------------------------------------------------------------
-- 4. Runtime privileges: narrow columns, cancel-only UPDATE, no delete/truncate.
-- ---------------------------------------------------------------------------
-- Not granted to the runtime: any DELETE or TRUNCATE, INSERT on the database-owned
-- stamps (created_at, state, cancelled_at, row_version) and INSERT on owner_staff_id
-- (there is no staff-owner caller path until P03-05 with real authorization), and
-- EXECUTE on any guard function (trigger functions need none, and the runtime never
-- calls them directly). Column-level privileges only: the runtime holds no
-- table-level privilege on this table. Nothing is granted on 013 objects; the new
-- consent index carries no ACL.
REVOKE ALL ON FUNCTION foundation.file_upload_intents_guard(),
    foundation.file_upload_intents_reject_truncate() FROM PUBLIC;
REVOKE ALL ON foundation.file_upload_intents FROM PUBLIC;

GRANT SELECT(id,owner_request_session_id,owner_staff_id,consent_record_id,consent_document_version_id,
        consent_purpose,policy_version_id,policy_source_ref,policy_sha256,allowed_mime_types,
        max_file_bytes,max_owner_bytes,max_owner_files,policy_expires_at,declared_mime,declared_bytes,
        expires_at,created_at,idempotency_key,body_sha256,state,cancelled_at,row_version),
    INSERT(id,owner_request_session_id,consent_record_id,consent_document_version_id,consent_purpose,
        policy_version_id,policy_source_ref,policy_sha256,allowed_mime_types,max_file_bytes,max_owner_bytes,
        max_owner_files,policy_expires_at,declared_mime,declared_bytes,expires_at,idempotency_key,body_sha256),
    UPDATE(state)
    ON foundation.file_upload_intents TO fixlevelup_runtime;

COMMIT;
