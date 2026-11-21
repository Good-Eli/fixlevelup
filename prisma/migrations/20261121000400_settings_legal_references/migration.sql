BEGIN;

-- P03-03 settings, reference data, content and legal/consent foundation (013).
-- Data layer only and additive: seven nullable provenance columns on the existing
-- immutable company settings revisions plus eight new foundation tables. No seed, no
-- real operator/legal value, no permission code, no staff/user row, no destructive
-- statement and no write to any working database.
--
-- Deliberate non-goals:
--   * no second copy of city timezone/contact/office hours - those stay only in
--     service_city_versions; company settings carry company-wide provenance only;
--   * no real legal text, legal basis, retention period or TTL: NULL/unknown company
--     fields stay NULL, and every document/consent row is synthetic evidence created by
--     the reviewed write path only;
--   * no public route, no form upload, no request/customer column: consent evidence is
--     anchored to a minimal pre-submit request_sessions row;
--   * no SECURITY DEFINER function and no function EXECUTE privilege for the runtime:
--     every guard is SECURITY INVOKER with a fixed search_path and is reached through
--     triggers, not through a callable API;
--   * no DELETE/TRUNCATE privilege and no UPDATE privilege on any immutable history
--     table; archived identity rows stay as history instead of being deleted.
--
-- Immutability model: every published revision/event row is append-only for ordinary
-- DML (including the owner), so a correction is a new row. Stable identity tables
-- (reference_entries, content_blocks, legal_documents) keep their id/type/scope/code
-- immutable and own only a current pointer plus archived_at; the database owns their
-- row_version (always OLD+1), so a caller can never keep it constant and defeat the
-- optimistic lock. A caller uses
--   UPDATE ... WHERE id=$1 AND row_version=$expected RETURNING row_version
-- and retries on zero rows.
--
-- Lock order for the consent write path (and for any future writer): request session
-- anchor row first, legal document row second, then append-only reads of the immutable
-- version/event history. Nothing here takes those locks in the opposite order.

-- ---------------------------------------------------------------------------
-- 1. Company settings provenance: nullable extension of existing revisions.
-- ---------------------------------------------------------------------------
-- NULL means "unknown"; a non-NULL value must be real non-blank text within a bounded
-- length, so an empty string can never pass as configured. The existing
-- business_settings_immutable trigger keeps every old revision (and therefore every
-- value added here) append-only; the extension only adds nullable columns, so existing
-- reviewed revisions are preserved untouched and keep meaning "unknown" for them.
ALTER TABLE foundation.business_settings_versions
    ADD COLUMN operator_name text,
    ADD COLUMN operator_registration_id text,
    ADD COLUMN operator_address text,
    ADD COLUMN legal_review_ref text,
    ADD COLUMN security_policy_ref text,
    ADD COLUMN retention_policy_ref text,
    ADD COLUMN upload_policy_ref text;

ALTER TABLE foundation.business_settings_versions
    ADD CONSTRAINT business_settings_versions_operator_name_check CHECK (
        operator_name IS NULL OR (operator_name ~ '[^[:space:]]' AND length(operator_name) <= 200)),
    ADD CONSTRAINT business_settings_versions_operator_registration_id_check CHECK (
        operator_registration_id IS NULL
        OR (operator_registration_id ~ '[^[:space:]]' AND length(operator_registration_id) <= 120)),
    ADD CONSTRAINT business_settings_versions_operator_address_check CHECK (
        operator_address IS NULL OR (operator_address ~ '[^[:space:]]' AND length(operator_address) <= 500)),
    ADD CONSTRAINT business_settings_versions_legal_review_ref_check CHECK (
        legal_review_ref IS NULL OR (legal_review_ref ~ '[^[:space:]]' AND length(legal_review_ref) <= 200)),
    ADD CONSTRAINT business_settings_versions_security_policy_ref_check CHECK (
        security_policy_ref IS NULL OR (security_policy_ref ~ '[^[:space:]]' AND length(security_policy_ref) <= 200)),
    ADD CONSTRAINT business_settings_versions_retention_policy_ref_check CHECK (
        retention_policy_ref IS NULL OR (retention_policy_ref ~ '[^[:space:]]' AND length(retention_policy_ref) <= 200)),
    ADD CONSTRAINT business_settings_versions_upload_policy_ref_check CHECK (
        upload_policy_ref IS NULL OR (upload_policy_ref ~ '[^[:space:]]' AND length(upload_policy_ref) <= 200));

-- ---------------------------------------------------------------------------
-- 2. Typed reference entries: stable identity, immutable versions, current pointer.
-- ---------------------------------------------------------------------------
-- CALLBACK_INTERVAL is strictly CITY scoped (a callback window belongs to one city);
-- PAYMENT_METHOD / CANCEL_REASON / DECLINE_REASON / REQUEST_SOURCE are strictly
-- COMPANY scoped. The scope/city pair is a CHECK, so a company row can never carry a
-- city and a callback row can never omit it. No implicit company fallback exists:
-- a consumer that needs a city-scoped value must ask for that city explicitly.
CREATE TABLE foundation.reference_entries (
    id uuid PRIMARY KEY,
    type varchar(32) NOT NULL,
    scope varchar(16) NOT NULL,
    city_id uuid,
    code varchar(64) NOT NULL,
    row_version integer NOT NULL DEFAULT 1,
    current_version_id uuid,
    archived_at timestamptz(6),
    CONSTRAINT reference_entries_city_id_fkey FOREIGN KEY (city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT reference_entries_type_check CHECK (type IN
        ('CALLBACK_INTERVAL','PAYMENT_METHOD','CANCEL_REASON','DECLINE_REASON','REQUEST_SOURCE')),
    CONSTRAINT reference_entries_scope_check CHECK (scope IN ('COMPANY','CITY')),
    CONSTRAINT reference_entries_scope_city_check CHECK (
        (type = 'CALLBACK_INTERVAL' AND scope = 'CITY' AND city_id IS NOT NULL)
        OR (type IN ('PAYMENT_METHOD','CANCEL_REASON','DECLINE_REASON','REQUEST_SOURCE')
            AND scope = 'COMPANY' AND city_id IS NULL)),
    CONSTRAINT reference_entries_code_check CHECK (code ~ '^[A-Za-z][A-Za-z0-9_.-]{0,63}$'),
    CONSTRAINT reference_entries_row_version_check CHECK (row_version >= 1)
);
-- COMPANY identity is (type, code); CITY identity adds the owning city. Two partial
-- indexes keep one namespace per scope without inventing a nullable tenant column.
CREATE UNIQUE INDEX reference_entries_company_code_key
    ON foundation.reference_entries(type,code) WHERE scope = 'COMPANY';
CREATE UNIQUE INDEX reference_entries_city_code_key
    ON foundation.reference_entries(city_id,type,code) WHERE scope = 'CITY';
-- Composite-FK target: a version can only name an entry of the same type.
CREATE UNIQUE INDEX reference_entries_type_id_key ON foundation.reference_entries(type,id);

-- Immutable reviewed revision of one entry. There is no DRAFT state: every row is a
-- published revision, so a correction is a new (entry_id, version) row and the old
-- snapshot keeps the exact label/source/window it was reviewed with. city_id /
-- city_version_id / start_minute / end_minute exist only for CALLBACK_INTERVAL; the
-- other types must keep all four NULL. city_version_id is creation provenance only:
-- consumers take the timezone from an explicitly passed trusted intake/visit city
-- version of the same city, never from this snapshot.
CREATE TABLE foundation.reference_entry_versions (
    id uuid PRIMARY KEY,
    entry_id uuid NOT NULL,
    type varchar(32) NOT NULL,
    city_id uuid,
    version integer NOT NULL,
    label text NOT NULL,
    valid_from timestamptz(6) NOT NULL,
    valid_until timestamptz(6),
    source_ref text NOT NULL,
    reviewed_by uuid NOT NULL,
    published_at timestamptz(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    city_version_id uuid,
    start_minute integer,
    end_minute integer,
    CONSTRAINT reference_entry_versions_type_entry_id_fkey FOREIGN KEY (type,entry_id)
        REFERENCES foundation.reference_entries(type,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT reference_entry_versions_city_id_fkey FOREIGN KEY (city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    -- Nullable-safe same-city FK: MATCH SIMPLE skips the check when the nullable
    -- provenance pair is NULL (company types), and enforces it for callback rows.
    CONSTRAINT reference_entry_versions_city_id_city_version_id_fkey
        FOREIGN KEY (city_id,city_version_id)
        REFERENCES foundation.service_city_versions(city_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT reference_entry_versions_reviewed_by_fkey FOREIGN KEY (reviewed_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT reference_entry_versions_version_check CHECK (version >= 1),
    CONSTRAINT reference_entry_versions_type_check CHECK (type IN
        ('CALLBACK_INTERVAL','PAYMENT_METHOD','CANCEL_REASON','DECLINE_REASON','REQUEST_SOURCE')),
    CONSTRAINT reference_entry_versions_type_fields_check CHECK (
        CASE WHEN type = 'CALLBACK_INTERVAL' THEN
            city_id IS NOT NULL AND city_version_id IS NOT NULL
            AND start_minute IS NOT NULL AND end_minute IS NOT NULL
        ELSE
            city_id IS NULL AND city_version_id IS NULL
            AND start_minute IS NULL AND end_minute IS NULL
        END),
    CONSTRAINT reference_entry_versions_interval_check CHECK (
        (start_minute IS NULL AND end_minute IS NULL)
        OR (start_minute IS NOT NULL AND end_minute IS NOT NULL
            AND start_minute >= 0 AND start_minute < end_minute AND end_minute <= 1440)),
    CONSTRAINT reference_entry_versions_label_check CHECK (label ~ '[^[:space:]]'),
    CONSTRAINT reference_entry_versions_source_check CHECK (source_ref ~ '[^[:space:]]'),
    CONSTRAINT reference_entry_versions_window_check CHECK (valid_until IS NULL OR valid_until > valid_from)
);
CREATE UNIQUE INDEX reference_entry_versions_entry_version_key
    ON foundation.reference_entry_versions(entry_id,version);
-- Pointer-FK target: pins the current pointer to one entry and one type.
CREATE UNIQUE INDEX reference_entry_versions_entry_type_id_key
    ON foundation.reference_entry_versions(entry_id,type,id);

-- The current pointer can only name a version of this entry and type (composite FK);
-- archived entries may keep their historical pointer but cannot move it again.
ALTER TABLE foundation.reference_entries ADD CONSTRAINT reference_entries_id_type_current_version_id_fkey
    FOREIGN KEY (id,type,current_version_id)
    REFERENCES foundation.reference_entry_versions(entry_id,type,id)
    ON DELETE RESTRICT ON UPDATE RESTRICT;

-- ---------------------------------------------------------------------------
-- 3. Content blocks: stable identity, immutable revisions, explicit city/company scope.
-- ---------------------------------------------------------------------------
-- A block never copies city contacts, hours or timezone: those remain only in
-- service_city_versions. allow_company_fallback is meaningful only for a COMPANY block:
-- it is the company row's explicit permission to be used when a city has no block of
-- the same code. Legal/retention/security policy is never overridden through content.
CREATE TABLE foundation.content_blocks (
    id uuid PRIMARY KEY,
    code varchar(64) NOT NULL,
    kind varchar(16) NOT NULL,
    scope varchar(16) NOT NULL,
    city_id uuid,
    allow_company_fallback boolean NOT NULL DEFAULT false,
    row_version integer NOT NULL DEFAULT 1,
    current_revision_id uuid,
    archived_at timestamptz(6),
    CONSTRAINT content_blocks_city_id_fkey FOREIGN KEY (city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT content_blocks_kind_check CHECK (kind IN ('FAQ','FACT','SEO')),
    CONSTRAINT content_blocks_scope_check CHECK (scope IN ('COMPANY','CITY')),
    CONSTRAINT content_blocks_scope_city_check CHECK (
        (scope = 'COMPANY' AND city_id IS NULL) OR (scope = 'CITY' AND city_id IS NOT NULL)),
    CONSTRAINT content_blocks_code_check CHECK (code ~ '^[A-Za-z][A-Za-z0-9_.-]{0,63}$'),
    CONSTRAINT content_blocks_row_version_check CHECK (row_version >= 1),
    CONSTRAINT content_blocks_fallback_scope_check CHECK (scope = 'COMPANY' OR NOT allow_company_fallback)
);
CREATE UNIQUE INDEX content_blocks_company_code_key
    ON foundation.content_blocks(code) WHERE scope = 'COMPANY';
CREATE UNIQUE INDEX content_blocks_city_code_key
    ON foundation.content_blocks(city_id,code) WHERE scope = 'CITY';

-- Immutable reviewed revision of one block: title/body/source are the reviewed
-- snapshot, so a published correction is always a new revision row.
CREATE TABLE foundation.content_block_revisions (
    id uuid PRIMARY KEY,
    block_id uuid NOT NULL,
    version integer NOT NULL,
    title text NOT NULL,
    body text NOT NULL,
    source_ref text NOT NULL,
    reviewed_by uuid NOT NULL,
    published_at timestamptz(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT content_block_revisions_block_id_fkey FOREIGN KEY (block_id)
        REFERENCES foundation.content_blocks(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT content_block_revisions_reviewed_by_fkey FOREIGN KEY (reviewed_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT content_block_revisions_version_check CHECK (version >= 1),
    CONSTRAINT content_block_revisions_text_check CHECK (
        title ~ '[^[:space:]]' AND body ~ '[^[:space:]]' AND source_ref ~ '[^[:space:]]')
);
CREATE UNIQUE INDEX content_block_revisions_block_version_key
    ON foundation.content_block_revisions(block_id,version);
-- Pointer-FK target: pins the current revision to one block.
CREATE UNIQUE INDEX content_block_revisions_block_id_key
    ON foundation.content_block_revisions(block_id,id);

ALTER TABLE foundation.content_blocks ADD CONSTRAINT content_blocks_id_current_revision_id_fkey
    FOREIGN KEY (id,current_revision_id)
    REFERENCES foundation.content_block_revisions(block_id,id)
    ON DELETE RESTRICT ON UPDATE RESTRICT;

-- ---------------------------------------------------------------------------
-- 4. Legal documents: purpose + kind identity and immutable reviewed versions.
-- ---------------------------------------------------------------------------
-- Purpose vocabulary is the three separate consent purposes. kind separates the
-- privacy POLICY, the CONSENT_FORM that a GIVEN consent must reference, and an
-- OPT_IN_NOTICE. A policy and a consent form for the same purpose are different
-- documents: (purpose, kind) is unique, purpose alone is not.
CREATE TABLE foundation.legal_documents (
    id uuid PRIMARY KEY,
    purpose varchar(32) NOT NULL,
    kind varchar(24) NOT NULL,
    row_version integer NOT NULL DEFAULT 1,
    current_version_id uuid,
    CONSTRAINT legal_documents_purpose_check CHECK (purpose IN
        ('REQUEST_PROCESSING','ADDRESS_COVERAGE','MARKETING')),
    CONSTRAINT legal_documents_kind_check CHECK (kind IN ('POLICY','CONSENT_FORM','OPT_IN_NOTICE')),
    CONSTRAINT legal_documents_row_version_check CHECK (row_version >= 1)
);
CREATE UNIQUE INDEX legal_documents_purpose_kind_key ON foundation.legal_documents(purpose,kind);
-- Composite-FK target: a version must match its document's purpose and kind.
CREATE UNIQUE INDEX legal_documents_id_purpose_kind_key ON foundation.legal_documents(id,purpose,kind);

-- Immutable reviewed legal text. checksum is the SHA-256 of the exact UTF-8 body and
-- is verified by the database with the built-in pg_catalog sha256()/convert_to()/encode()
-- (no pgcrypto extension is installed or needed). published_at defaults to the database
-- clock. A GIVEN consent can only reference a CONSENT_FORM version that is current.
CREATE TABLE foundation.legal_document_versions (
    id uuid PRIMARY KEY,
    document_id uuid NOT NULL,
    purpose varchar(32) NOT NULL,
    kind varchar(24) NOT NULL,
    version integer NOT NULL,
    title text NOT NULL,
    body text NOT NULL,
    checksum varchar(64) NOT NULL,
    legal_basis text NOT NULL,
    source_ref text NOT NULL,
    reviewed_by uuid NOT NULL,
    published_at timestamptz(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT legal_document_versions_document_id_purpose_kind_fkey
        FOREIGN KEY (document_id,purpose,kind)
        REFERENCES foundation.legal_documents(id,purpose,kind) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT legal_document_versions_reviewed_by_fkey FOREIGN KEY (reviewed_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT legal_document_versions_purpose_check CHECK (purpose IN
        ('REQUEST_PROCESSING','ADDRESS_COVERAGE','MARKETING')),
    CONSTRAINT legal_document_versions_kind_check CHECK (kind IN ('POLICY','CONSENT_FORM','OPT_IN_NOTICE')),
    CONSTRAINT legal_document_versions_version_check CHECK (version >= 1),
    CONSTRAINT legal_document_versions_checksum_check CHECK (
        checksum = encode(sha256(convert_to(body,'UTF8')),'hex')),
    CONSTRAINT legal_document_versions_text_check CHECK (
        title ~ '[^[:space:]]' AND body ~ '[^[:space:]]'
        AND legal_basis ~ '[^[:space:]]' AND source_ref ~ '[^[:space:]]')
);
CREATE UNIQUE INDEX legal_document_versions_document_version_key
    ON foundation.legal_document_versions(document_id,version);
-- Pointer-FK target: pins the current version to one document.
CREATE UNIQUE INDEX legal_document_versions_document_id_key
    ON foundation.legal_document_versions(document_id,id);
-- Consent-FK target: proves a consent event names this document, this version and the
-- same purpose in one reference.
CREATE UNIQUE INDEX legal_document_versions_document_id_purpose_key
    ON foundation.legal_document_versions(document_id,id,purpose);

ALTER TABLE foundation.legal_documents ADD CONSTRAINT legal_documents_id_current_version_id_fkey
    FOREIGN KEY (id,current_version_id)
    REFERENCES foundation.legal_document_versions(document_id,id)
    ON DELETE RESTRICT ON UPDATE RESTRICT;

-- ---------------------------------------------------------------------------
-- 5. Minimal pre-submit request anchor.
-- ---------------------------------------------------------------------------
-- Deliberately minimal: a server-generated secret hash and the trusted intake city
-- context only. No name, phone, address, request or customer column exists here, so a
-- pre-submit anchor cannot leak personal data even before Q02/Q13 are answered. The
-- caller's trusted policy supplies expires_at; there is no default TTL. Identity, hash,
-- city and both timestamps are stable; only a single revoke (NULL -> value) is allowed.
CREATE TABLE foundation.request_sessions (
    id uuid PRIMARY KEY,
    secret_hash varchar(64) NOT NULL,
    intake_city_id uuid NOT NULL,
    intake_city_version_id uuid NOT NULL,
    created_at timestamptz(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamptz(6) NOT NULL,
    revoked_at timestamptz(6),
    CONSTRAINT request_sessions_intake_city_id_fkey FOREIGN KEY (intake_city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    -- Same-city anchor: the version must belong to the named intake city.
    CONSTRAINT request_sessions_intake_city_id_intake_city_version_id_fkey
        FOREIGN KEY (intake_city_id,intake_city_version_id)
        REFERENCES foundation.service_city_versions(city_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_sessions_secret_hash_check CHECK (secret_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT request_sessions_expiry_check CHECK (expires_at > created_at)
);
CREATE UNIQUE INDEX request_sessions_secret_hash_key ON foundation.request_sessions(secret_hash);

-- ---------------------------------------------------------------------------
-- 6. Append-only consent evidence.
-- ---------------------------------------------------------------------------
-- One row per GIVEN/REVOKED event. There is no UPDATE and no DELETE: a correction or a
-- withdrawal is a new event. GIVEN is accepted only for a live, unexpired anchor and
-- the CURRENT CONSENT_FORM version (stale text is refused, not silently accepted);
-- REVOKED must name the exact GIVEN event of the same session/purpose/document/version
-- and only affects that event. occurred_at is forced from the database clock by the
-- guard below, and the runtime has no INSERT privilege on it. evidence_ref is a
-- non-PII reference (never a token or raw personal value); unique(session_id,
-- evidence_ref) makes a replay detectable, and a replay must not resurrect a revoked
-- consent or accept stale text.
CREATE TABLE foundation.consent_records (
    id uuid PRIMARY KEY,
    session_id uuid NOT NULL,
    document_id uuid NOT NULL,
    document_version_id uuid NOT NULL,
    purpose varchar(32) NOT NULL,
    action varchar(16) NOT NULL,
    legal_basis text NOT NULL,
    source varchar(32) NOT NULL DEFAULT 'FORM',
    evidence_ref uuid NOT NULL,
    occurred_at timestamptz(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    supersedes_id uuid,
    CONSTRAINT consent_records_session_id_fkey FOREIGN KEY (session_id)
        REFERENCES foundation.request_sessions(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    -- Composite document/version/purpose FK: a consent event cannot name a version of
    -- another document or another purpose.
    CONSTRAINT consent_records_document_id_document_version_id_purpose_fkey
        FOREIGN KEY (document_id,document_version_id,purpose)
        REFERENCES foundation.legal_document_versions(document_id,id,purpose)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT consent_records_supersedes_id_fkey FOREIGN KEY (supersedes_id)
        REFERENCES foundation.consent_records(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT consent_records_purpose_check CHECK (purpose IN
        ('REQUEST_PROCESSING','ADDRESS_COVERAGE','MARKETING')),
    CONSTRAINT consent_records_action_check CHECK (action IN ('GIVEN','REVOKED')),
    CONSTRAINT consent_records_source_check CHECK (source IN ('FORM')),
    CONSTRAINT consent_records_given_supersedes_check CHECK (
        (action = 'GIVEN' AND supersedes_id IS NULL)
        OR (action = 'REVOKED' AND supersedes_id IS NOT NULL)),
    CONSTRAINT consent_records_legal_basis_check CHECK (legal_basis ~ '[^[:space:]]')
);
-- Replay/idempotency key: one evidence reference per anchor.
CREATE UNIQUE INDEX consent_records_session_evidence_key
    ON foundation.consent_records(session_id,evidence_ref);
-- One revoke per GIVEN event: a second REVOKED of the same event is impossible.
CREATE UNIQUE INDEX consent_records_supersedes_id_key
    ON foundation.consent_records(supersedes_id);

-- ---------------------------------------------------------------------------
-- 7. Stable identity guards and database-owned row_version.
-- ---------------------------------------------------------------------------
-- id/type/scope/city/code never change; the database owns row_version (always OLD+1).
-- Archiving is one-way: once archived_at is set it can never be cleared or rewritten,
-- so an archived entry cannot be un-archived to accept a new revision. An archived entry
-- keeps its last pointer as history but may not move it again.
CREATE FUNCTION foundation.reference_entries_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Reference entries are history; archive instead of delete' USING ERRCODE='23514';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.type IS DISTINCT FROM OLD.type
            OR NEW.scope IS DISTINCT FROM OLD.scope OR NEW.city_id IS DISTINCT FROM OLD.city_id
            OR NEW.code IS DISTINCT FROM OLD.code THEN
            RAISE EXCEPTION 'Reference entry id, type, scope, city and code are stable' USING ERRCODE='23514';
        END IF;
        IF OLD.archived_at IS NOT NULL AND NEW.archived_at IS DISTINCT FROM OLD.archived_at THEN
            RAISE EXCEPTION 'Reference entry archive is one-way; archived_at cannot be cleared or changed'
                USING ERRCODE='23514';
        END IF;
        IF OLD.archived_at IS NOT NULL AND NEW.current_version_id IS DISTINCT FROM OLD.current_version_id THEN
            RAISE EXCEPTION 'Archived reference entry cannot move its current version' USING ERRCODE='23514';
        END IF;
        NEW.row_version := OLD.row_version + 1;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER reference_entries_guard BEFORE INSERT OR UPDATE OR DELETE ON foundation.reference_entries
    FOR EACH ROW EXECUTE FUNCTION foundation.reference_entries_guard();

-- A new revision is refused for an archived entry (that would be new use of archived
-- data) and a CALLBACK_INTERVAL revision must stay in its entry's city. The parent row
-- is locked first so an archive cannot slip between the check and the INSERT.
CREATE FUNCTION foundation.reference_entry_versions_pointer_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    parent_city uuid;
    parent_archived timestamptz;
BEGIN
    SELECT e.city_id, e.archived_at INTO parent_city, parent_archived
      FROM foundation.reference_entries e
     WHERE e.id = NEW.entry_id AND e.type = NEW.type
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Reference version needs an existing entry of the same type' USING ERRCODE='23503';
    END IF;
    IF parent_archived IS NOT NULL THEN
        RAISE EXCEPTION 'Archived reference entry cannot receive a new version' USING ERRCODE='23514';
    END IF;
    IF NEW.type = 'CALLBACK_INTERVAL' AND NEW.city_id IS DISTINCT FROM parent_city THEN
        RAISE EXCEPTION 'Callback interval version must belong to the same city as its entry' USING ERRCODE='23503';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER reference_entry_versions_pointer_guard BEFORE INSERT ON foundation.reference_entry_versions
    FOR EACH ROW EXECUTE FUNCTION foundation.reference_entry_versions_pointer_guard();

CREATE FUNCTION foundation.reference_entry_versions_immutable() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'Reference entry versions are append-only (%)', TG_OP USING ERRCODE='23514';
END $$;
CREATE TRIGGER reference_entry_versions_immutable BEFORE UPDATE OR DELETE ON foundation.reference_entry_versions
    FOR EACH ROW EXECUTE FUNCTION foundation.reference_entry_versions_immutable();

CREATE FUNCTION foundation.content_blocks_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Content blocks are history; archive instead of delete' USING ERRCODE='23514';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.code IS DISTINCT FROM OLD.code
            OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.scope IS DISTINCT FROM OLD.scope
            OR NEW.city_id IS DISTINCT FROM OLD.city_id THEN
            RAISE EXCEPTION 'Content block id, code, kind, scope and city are stable' USING ERRCODE='23514';
        END IF;
        IF OLD.archived_at IS NOT NULL AND NEW.archived_at IS DISTINCT FROM OLD.archived_at THEN
            RAISE EXCEPTION 'Content block archive is one-way; archived_at cannot be cleared or changed'
                USING ERRCODE='23514';
        END IF;
        IF OLD.archived_at IS NOT NULL AND NEW.current_revision_id IS DISTINCT FROM OLD.current_revision_id THEN
            RAISE EXCEPTION 'Archived content block cannot move its current revision' USING ERRCODE='23514';
        END IF;
        NEW.row_version := OLD.row_version + 1;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER content_blocks_guard BEFORE INSERT OR UPDATE OR DELETE ON foundation.content_blocks
    FOR EACH ROW EXECUTE FUNCTION foundation.content_blocks_guard();

CREATE FUNCTION foundation.content_block_revisions_pointer_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    parent_archived timestamptz;
BEGIN
    SELECT b.archived_at INTO parent_archived
      FROM foundation.content_blocks b WHERE b.id = NEW.block_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Content revision needs an existing content block' USING ERRCODE='23503';
    END IF;
    IF parent_archived IS NOT NULL THEN
        RAISE EXCEPTION 'Archived content block cannot receive a new revision' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER content_block_revisions_pointer_guard BEFORE INSERT ON foundation.content_block_revisions
    FOR EACH ROW EXECUTE FUNCTION foundation.content_block_revisions_pointer_guard();

CREATE FUNCTION foundation.content_block_revisions_immutable() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'Content block revisions are append-only (%)', TG_OP USING ERRCODE='23514';
END $$;
CREATE TRIGGER content_block_revisions_immutable BEFORE UPDATE OR DELETE ON foundation.content_block_revisions
    FOR EACH ROW EXECUTE FUNCTION foundation.content_block_revisions_immutable();

CREATE FUNCTION foundation.legal_documents_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Legal documents are history; a new document is a new row' USING ERRCODE='23514';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.purpose IS DISTINCT FROM OLD.purpose
            OR NEW.kind IS DISTINCT FROM OLD.kind THEN
            RAISE EXCEPTION 'Legal document id, purpose and kind are stable' USING ERRCODE='23514';
        END IF;
        NEW.row_version := OLD.row_version + 1;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER legal_documents_guard BEFORE INSERT OR UPDATE OR DELETE ON foundation.legal_documents
    FOR EACH ROW EXECUTE FUNCTION foundation.legal_documents_guard();

-- The document row is locked before a version is appended, so a concurrent pointer move
-- and the reviewed insertion serialize on one row. The composite FK already proves
-- purpose/kind equality; this guard re-proves it and fixes the lock order.
CREATE FUNCTION foundation.legal_document_versions_pointer_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    parent_purpose varchar(32);
    parent_kind varchar(24);
BEGIN
    SELECT d.purpose, d.kind INTO parent_purpose, parent_kind
      FROM foundation.legal_documents d WHERE d.id = NEW.document_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Legal document version needs an existing document' USING ERRCODE='23503';
    END IF;
    IF NEW.purpose IS DISTINCT FROM parent_purpose OR NEW.kind IS DISTINCT FROM parent_kind THEN
        RAISE EXCEPTION 'Legal document version purpose and kind must match its document' USING ERRCODE='23503';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER legal_document_versions_pointer_guard BEFORE INSERT ON foundation.legal_document_versions
    FOR EACH ROW EXECUTE FUNCTION foundation.legal_document_versions_pointer_guard();

CREATE FUNCTION foundation.legal_document_versions_immutable() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'Legal document versions are append-only (%)', TG_OP USING ERRCODE='23514';
END $$;
CREATE TRIGGER legal_document_versions_immutable BEFORE UPDATE OR DELETE ON foundation.legal_document_versions
    FOR EACH ROW EXECUTE FUNCTION foundation.legal_document_versions_immutable();

-- ---------------------------------------------------------------------------
-- 8. Anchor and consent guards.
-- ---------------------------------------------------------------------------
-- A request anchor is stable except for exactly one revoke (revoked_at NULL -> value).
-- Both anchor timestamps are database clocks, not caller values: created_at is forced to
-- clock_timestamp() on INSERT (the column has no INSERT grant, and the trigger overwrites
-- an owner-supplied value too), and the single revoke stamps revoked_at from
-- clock_timestamp() so a caller can neither backdate nor future-date the withdrawal.
-- expires_at stays explicitly supplied by the trusted policy and must be after the
-- database-stamped created_at, so an anchor can never be created already expired.
-- DELETE is refused; the minimal anchor is history, not a disposable row.
CREATE FUNCTION foundation.request_sessions_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Request session anchors are history; revoke instead of delete' USING ERRCODE='23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        NEW.created_at := clock_timestamp();
        -- A new anchor is always live: a supplied revoke stamp is discarded, so even an
        -- owner-level INSERT cannot create an already-revoked anchor with a backdated time.
        NEW.revoked_at := NULL;
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.secret_hash IS DISTINCT FROM OLD.secret_hash
        OR NEW.intake_city_id IS DISTINCT FROM OLD.intake_city_id
        OR NEW.intake_city_version_id IS DISTINCT FROM OLD.intake_city_version_id
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'Request session identity, hash, city and expiry are stable' USING ERRCODE='23514';
    END IF;
    IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL THEN
        RAISE EXCEPTION 'Request session can be revoked only once' USING ERRCODE='23514';
    END IF;
    NEW.revoked_at := clock_timestamp();
    RETURN NEW;
END $$;
CREATE TRIGGER request_sessions_guard BEFORE INSERT OR UPDATE OR DELETE ON foundation.request_sessions
    FOR EACH ROW EXECUTE FUNCTION foundation.request_sessions_guard();

-- Consent guard. The event time is the database clock taken at the moment of acceptance
-- (after every lock), the session anchor is locked before the legal document, and both
-- GIVEN and REVOKED require a live, unexpired anchor. Waiting for the document lock can
-- itself cross the anchor expiry, so the live/unexpired pair is re-proven after that lock
-- is acquired and the recorded occurred_at is read there - a caller can neither supply a
-- timestamp nor slip an event in after expiry while blocked. GIVEN needs the current
-- CONSENT_FORM version, the exact immutable legal basis and no other active GIVEN for the
-- same session/purpose/document VERSION; a duplicate active GIVEN of the same version is
-- rejected as a harmless unique violation. An older GIVEN of a superseded text version
-- stays as history and never blocks accepting the new current version. REVOKED must name
-- the exact GIVEN event of the same session/purpose/document/version.
CREATE FUNCTION foundation.consent_records_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    anchor_revoked timestamptz;
    anchor_expires timestamptz;
    target_kind varchar(24);
    target_current uuid;
    version_kind varchar(24);
    version_basis text;
    given_action varchar(16);
    given_session uuid;
    given_purpose varchar(32);
    given_document uuid;
    given_version uuid;
    active_given boolean;
BEGIN
    IF TG_OP = 'UPDATE' OR TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Consent records are append-only (%)', TG_OP USING ERRCODE='23514';
    END IF;
    -- Lock order: anchor first, document second. The anchor lock is held from here to the
    -- end of the statement, so no concurrent revoke can commit while this event is decided.
    SELECT s.revoked_at, s.expires_at INTO anchor_revoked, anchor_expires
      FROM foundation.request_sessions s WHERE s.id = NEW.session_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Consent record needs an existing request session anchor' USING ERRCODE='23503';
    END IF;
    IF anchor_revoked IS NOT NULL THEN
        RAISE EXCEPTION 'Consent record needs a live request session anchor' USING ERRCODE='23514';
    END IF;
    IF anchor_expires <= clock_timestamp() THEN
        RAISE EXCEPTION 'Consent record needs an unexpired request session anchor' USING ERRCODE='23514';
    END IF;
    SELECT d.kind, d.current_version_id INTO target_kind, target_current
      FROM foundation.legal_documents d WHERE d.id = NEW.document_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Consent record needs an existing legal document' USING ERRCODE='23503';
    END IF;
    -- Point of acceptance: the document lock above may have waited, so the event time is
    -- read from the database clock here and the anchor liveness/expiry is proven again
    -- against that same instant. occurred_at is never the caller's value.
    NEW.occurred_at := clock_timestamp();
    IF anchor_revoked IS NOT NULL THEN
        RAISE EXCEPTION 'Consent record needs a live request session anchor' USING ERRCODE='23514';
    END IF;
    IF anchor_expires <= NEW.occurred_at THEN
        RAISE EXCEPTION 'Consent record anchor expired before the event was accepted' USING ERRCODE='23514';
    END IF;
    IF target_kind <> 'CONSENT_FORM' THEN
        RAISE EXCEPTION 'Consent events are accepted only for a CONSENT_FORM document' USING ERRCODE='23514';
    END IF;
    SELECT v.kind, v.legal_basis INTO version_kind, version_basis
      FROM foundation.legal_document_versions v
     WHERE v.id = NEW.document_version_id AND v.document_id = NEW.document_id
       AND v.purpose = NEW.purpose;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Consent record needs a version of the same document and purpose' USING ERRCODE='23503';
    END IF;
    IF version_kind <> 'CONSENT_FORM' THEN
        RAISE EXCEPTION 'Consent record needs a CONSENT_FORM document version' USING ERRCODE='23514';
    END IF;
    IF NEW.legal_basis IS DISTINCT FROM version_basis THEN
        RAISE EXCEPTION 'Consent legal basis must equal the immutable document version basis' USING ERRCODE='23514';
    END IF;
    IF NEW.action = 'GIVEN' THEN
        IF target_current IS NULL OR target_current IS DISTINCT FROM NEW.document_version_id THEN
            RAISE EXCEPTION 'GIVEN requires the current document version; stale text is refused' USING ERRCODE='23514';
        END IF;
        -- Duplicate is scoped to the exact version: a still-unrevoked GIVEN of an older
        -- text version is history, not an active consent for the current document, so it
        -- must not block accepting the new current version.
        SELECT EXISTS (
            SELECT FROM foundation.consent_records c
             WHERE c.session_id = NEW.session_id AND c.purpose = NEW.purpose
               AND c.document_id = NEW.document_id
               AND c.document_version_id = NEW.document_version_id
               AND c.action = 'GIVEN'
               AND NOT EXISTS (SELECT FROM foundation.consent_records r WHERE r.supersedes_id = c.id)
        ) INTO active_given;
        IF active_given THEN
            RAISE EXCEPTION 'Active GIVEN already exists for this session, purpose, document version'
                USING ERRCODE='23505';
        END IF;
    ELSE
        SELECT c.action, c.session_id, c.purpose, c.document_id, c.document_version_id
          INTO given_action, given_session, given_purpose, given_document, given_version
          FROM foundation.consent_records c WHERE c.id = NEW.supersedes_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'REVOKED must reference an existing GIVEN event' USING ERRCODE='23503';
        END IF;
        IF given_action <> 'GIVEN' THEN
            RAISE EXCEPTION 'REVOKED must reference a GIVEN event' USING ERRCODE='23514';
        END IF;
        IF given_session IS DISTINCT FROM NEW.session_id OR given_purpose IS DISTINCT FROM NEW.purpose
            OR given_document IS DISTINCT FROM NEW.document_id
            OR given_version IS DISTINCT FROM NEW.document_version_id THEN
            RAISE EXCEPTION 'REVOKED must reference the GIVEN of the same session, purpose, document and version'
                USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER consent_records_guard BEFORE INSERT OR UPDATE OR DELETE ON foundation.consent_records
    FOR EACH ROW EXECUTE FUNCTION foundation.consent_records_guard();

-- ---------------------------------------------------------------------------
-- 9. TRUNCATE refusal for every new table (row triggers do not see TRUNCATE).
-- ---------------------------------------------------------------------------
CREATE FUNCTION foundation.settings_history_reject_truncate() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'P03-03 settings/legal history refuses TRUNCATE (%)', TG_TABLE_NAME USING ERRCODE='23514';
END $$;
CREATE TRIGGER reference_entries_reject_truncate BEFORE TRUNCATE ON foundation.reference_entries
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.settings_history_reject_truncate();
CREATE TRIGGER reference_entry_versions_reject_truncate BEFORE TRUNCATE ON foundation.reference_entry_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.settings_history_reject_truncate();
CREATE TRIGGER content_blocks_reject_truncate BEFORE TRUNCATE ON foundation.content_blocks
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.settings_history_reject_truncate();
CREATE TRIGGER content_block_revisions_reject_truncate BEFORE TRUNCATE ON foundation.content_block_revisions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.settings_history_reject_truncate();
CREATE TRIGGER legal_documents_reject_truncate BEFORE TRUNCATE ON foundation.legal_documents
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.settings_history_reject_truncate();
CREATE TRIGGER legal_document_versions_reject_truncate BEFORE TRUNCATE ON foundation.legal_document_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.settings_history_reject_truncate();
CREATE TRIGGER request_sessions_reject_truncate BEFORE TRUNCATE ON foundation.request_sessions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.settings_history_reject_truncate();
CREATE TRIGGER consent_records_reject_truncate BEFORE TRUNCATE ON foundation.consent_records
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.settings_history_reject_truncate();

-- ---------------------------------------------------------------------------
-- 10. Runtime privileges: column-scoped, least privilege, no callable guards.
-- ---------------------------------------------------------------------------
-- Not granted to the runtime: any DELETE or TRUNCATE, any UPDATE on an immutable
-- version/event table, INSERT on database-owned stamps (published_at, occurred_at,
-- created_at, row_version) and EXECUTE on any guard/validator function (trigger
-- functions need none, and the runtime never calls them directly). SELECT columns
-- below cover exactly what the internal ports and the trigger bodies read; the
-- runtime role gets no table-level privilege on any of these tables.
REVOKE ALL ON FUNCTION foundation.reference_entries_guard(),
    foundation.reference_entry_versions_pointer_guard(), foundation.reference_entry_versions_immutable(),
    foundation.content_blocks_guard(), foundation.content_block_revisions_pointer_guard(),
    foundation.content_block_revisions_immutable(), foundation.legal_documents_guard(),
    foundation.legal_document_versions_pointer_guard(), foundation.legal_document_versions_immutable(),
    foundation.request_sessions_guard(), foundation.consent_records_guard(),
    foundation.settings_history_reject_truncate() FROM PUBLIC;
REVOKE ALL ON foundation.reference_entries, foundation.reference_entry_versions,
    foundation.content_blocks, foundation.content_block_revisions,
    foundation.legal_documents, foundation.legal_document_versions,
    foundation.request_sessions, foundation.consent_records FROM PUBLIC;

-- Company settings provenance: the 010 grant already covers
-- SELECT(id,version,launch_mode,primary_city_id,reviewed_by,published_at) and
-- INSERT(id,version,launch_mode,primary_city_id,reviewed_by), and 012 re-granted the
-- same surface for the geography primary-pointer carry-forward. Column grants are
-- additive, so this is the narrow delta: read the last revision's provenance and
-- append a fully configured revision. No UPDATE/DELETE is granted; the existing 010
-- immutable trigger keeps every old revision append-only.
GRANT SELECT(operator_name,operator_registration_id,operator_address,legal_review_ref,
        security_policy_ref,retention_policy_ref,upload_policy_ref),
    INSERT(operator_name,operator_registration_id,operator_address,legal_review_ref,
        security_policy_ref,retention_policy_ref,upload_policy_ref)
    ON foundation.business_settings_versions TO fixlevelup_runtime;

-- Reference identity: create, read, archive and CAS the current pointer.
GRANT SELECT(id,type,scope,city_id,code,row_version,current_version_id,archived_at),
    INSERT(id,type,scope,city_id,code),
    UPDATE(current_version_id,archived_at)
    ON foundation.reference_entries TO fixlevelup_runtime;
-- Reference revisions: append and read only.
GRANT SELECT(id,entry_id,type,city_id,version,label,valid_from,valid_until,source_ref,
        reviewed_by,published_at,city_version_id,start_minute,end_minute),
    INSERT(id,entry_id,type,city_id,version,label,valid_from,valid_until,source_ref,
        reviewed_by,city_version_id,start_minute,end_minute)
    ON foundation.reference_entry_versions TO fixlevelup_runtime;

-- Content identity: create, read, archive and CAS the current revision.
GRANT SELECT(id,code,kind,scope,city_id,allow_company_fallback,row_version,current_revision_id,archived_at),
    INSERT(id,code,kind,scope,city_id,allow_company_fallback),
    UPDATE(current_revision_id,archived_at)
    ON foundation.content_blocks TO fixlevelup_runtime;
-- Content revisions: append and read only.
GRANT SELECT(id,block_id,version,title,body,source_ref,reviewed_by,published_at),
    INSERT(id,block_id,version,title,body,source_ref,reviewed_by)
    ON foundation.content_block_revisions TO fixlevelup_runtime;

-- Legal documents: create, read and CAS the current pointer.
GRANT SELECT(id,purpose,kind,row_version,current_version_id), INSERT(id,purpose,kind),
    UPDATE(current_version_id)
    ON foundation.legal_documents TO fixlevelup_runtime;
-- Legal versions: append and read only; the checksum CHECK is evaluated with built-in
-- pg_catalog functions that need no extra EXECUTE grant.
GRANT SELECT(id,document_id,purpose,kind,version,title,body,checksum,legal_basis,
        source_ref,reviewed_by,published_at),
    INSERT(id,document_id,purpose,kind,version,title,body,checksum,legal_basis,
        source_ref,reviewed_by)
    ON foundation.legal_document_versions TO fixlevelup_runtime;

-- Request anchors: create with a trusted expiry, read, and revoke once.
GRANT SELECT(id,secret_hash,intake_city_id,intake_city_version_id,created_at,expires_at,revoked_at),
    INSERT(id,secret_hash,intake_city_id,intake_city_version_id,expires_at),
    UPDATE(revoked_at)
    ON foundation.request_sessions TO fixlevelup_runtime;
-- Consent events: append and read only; occurred_at stays database-owned.
GRANT SELECT(id,session_id,document_id,document_version_id,purpose,action,legal_basis,
        source,evidence_ref,occurred_at,supersedes_id),
    INSERT(id,session_id,document_id,document_version_id,purpose,action,legal_basis,
        source,evidence_ref,supersedes_id)
    ON foundation.consent_records TO fixlevelup_runtime;

COMMIT;
