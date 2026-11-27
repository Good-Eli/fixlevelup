BEGIN;
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET LOCAL search_path = pg_catalog;

-- P05-01 (022, schema profile S1): request intake foundation.
-- Additive only over 021: customers, the request aggregate, immutable policy
-- packages, typed contact/address/appliance/fault/preference history, the
-- versioned ciphertext store and append-only business events. No routes, no
-- runtime seeding, no keys or real terms in this migration.
--
-- The unified GEO/CFG writer fence closes the phantom-basis gap recorded by
-- the pre-DDL baseline proof: every writer of the nine guarded basis relations
-- must hold pg_advisory_xact_lock(734305,1) before its first statement.

-- ---------------------------------------------------------------------------
-- 1. Immutable intake/workflow policy packages (no data in this migration).
-- ---------------------------------------------------------------------------
-- Reviewed metadata/hash pairs only; versions and conditions are provisioned
-- by the isolated test stand, never by a runtime seed. The runtime role may
-- read but not write them.
CREATE TABLE foundation.request_policy_packages (
    id uuid PRIMARY KEY,
    workflow_version varchar(64) NOT NULL,
    policy_revision varchar(68) NOT NULL,
    metadata_sha256 varchar(64) NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT request_policy_packages_workflow_version_check CHECK (
        workflow_version COLLATE "C" ~ '^[a-z0-9][a-z0-9.-]*-v[0-9]+$' AND length(workflow_version) <= 64),
    CONSTRAINT request_policy_packages_policy_revision_check CHECK (
        policy_revision COLLATE "C" ~ '^[a-z0-9][a-z0-9.-]*$' AND length(policy_revision) BETWEEN 3 AND 68),
    CONSTRAINT request_policy_packages_metadata_sha256_check CHECK (metadata_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT request_policy_packages_workflow_version_key UNIQUE (workflow_version),
    CONSTRAINT request_policy_packages_policy_revision_key UNIQUE (policy_revision)
);
CREATE TRIGGER request_policy_packages_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.request_policy_packages
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();

-- Public numbers are issued from one database sequence; the display form is
-- the caller's concern, the stored value is the stable identity.
CREATE SEQUENCE foundation.request_public_numbers AS bigint START WITH 100000;

-- ---------------------------------------------------------------------------
-- 2. Business customer record (Q03: not an auth principal).
-- ---------------------------------------------------------------------------
-- No plaintext personal column exists on this table; every personal value
-- lives in request_payload_cells as versioned ciphertext (§3).
CREATE TABLE foundation.customers (
    id uuid PRIMARY KEY,
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER customers_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.customers
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();

-- ---------------------------------------------------------------------------
-- 3. The request aggregate.
-- ---------------------------------------------------------------------------
CREATE TABLE foundation.requests (
    id uuid PRIMARY KEY,
    public_number bigint NOT NULL DEFAULT nextval('foundation.request_public_numbers'),
    type varchar(16) NOT NULL,
    status varchar(32) NOT NULL,
    row_version integer NOT NULL DEFAULT 1,
    customer_id uuid NOT NULL,
    city_id uuid NOT NULL,
    intake_city_version_id uuid NOT NULL,
    workflow_package_id uuid NOT NULL,
    intake_policy_revision_id uuid NOT NULL,
    current_contact_revision_id uuid,
    current_address_revision_id uuid,
    current_appliance_revision_id uuid,
    current_preference_revision_id uuid,
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    is_waiting_link boolean GENERATED ALWAYS AS (
        status IN ('WAITING_TELEGRAM_LINK','WAITING_CHANNEL_LINK')) STORED NOT NULL,
    CONSTRAINT requests_public_number_key UNIQUE (public_number),
    CONSTRAINT requests_type_check CHECK (type COLLATE "C" IN ('CALLBACK','REPAIR')),
    CONSTRAINT requests_status_check CHECK (status COLLATE "C" IN (
        'NEW','CALLBACK_REQUIRED','WAITING_TELEGRAM_LINK','WAITING_CHANNEL_LINK','MANAGER_REVIEW',
        'WAITING_ASSIGNMENT','ASSIGNED','TECHNICIAN_ACCEPTED','ON_THE_WAY','ARRIVED','DIAGNOSTICS',
        'WAITING_ESTIMATE_APPROVAL','IN_PROGRESS','WAITING_PARTS','PAUSED','TECHNICIAN_COMPLETED',
        'REVISIT_REQUIRED','CLOSED','CANCELLED')),
    CONSTRAINT requests_row_version_check CHECK (row_version >= 1),
    CONSTRAINT requests_customer_id_fkey FOREIGN KEY (customer_id)
        REFERENCES foundation.customers(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT requests_city_id_fkey FOREIGN KEY (city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    -- Same-city immutable intake context: the version must belong to the named city.
    CONSTRAINT requests_city_id_intake_city_version_id_fkey
        FOREIGN KEY (city_id,intake_city_version_id)
        REFERENCES foundation.service_city_versions(city_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT requests_workflow_package_id_fkey FOREIGN KEY (workflow_package_id)
        REFERENCES foundation.request_policy_packages(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT requests_intake_policy_revision_id_fkey FOREIGN KEY (intake_policy_revision_id)
        REFERENCES foundation.request_policy_packages(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    -- Composite FK targets for typed history, submit edges and receipts.
    CONSTRAINT requests_id_customer_id_key UNIQUE (id,customer_id),
    CONSTRAINT requests_id_city_id_intake_city_version_id_key UNIQUE (id,city_id,intake_city_version_id)
);
CREATE INDEX requests_is_waiting_link_idx ON foundation.requests(is_waiting_link) WHERE is_waiting_link;
CREATE INDEX requests_customer_id_idx ON foundation.requests(customer_id);

-- ---------------------------------------------------------------------------
-- 4. Versioned ciphertext store (separate from provenance rows).
-- ---------------------------------------------------------------------------
-- One random DEK per payload, wrapped under a versioned KEK outside the
-- database; AAD is rebuilt from environment/schema/purpose and the immutable
-- (request_id, kind, revision) identity. nonce is 96-bit, tag is full GCM.
CREATE TABLE foundation.request_payload_cells (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    kind varchar(24) NOT NULL,
    revision integer NOT NULL,
    key_id varchar(64) NOT NULL,
    wrapped_dek bytea NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    auth_tag bytea NOT NULL,
    aad_context varchar(128) NOT NULL,
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT request_payload_cells_request_id_fkey FOREIGN KEY (request_id)
        REFERENCES foundation.requests(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_payload_cells_kind_check CHECK (kind COLLATE "C" IN ('CONTACT','ADDRESS','DETAILS')),
    CONSTRAINT request_payload_cells_revision_check CHECK (revision >= 1),
    CONSTRAINT request_payload_cells_key_id_check CHECK (
        key_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._-]{3,63}$'),
    CONSTRAINT request_payload_cells_nonce_check CHECK (octet_length(nonce) = 12),
    CONSTRAINT request_payload_cells_tag_check CHECK (octet_length(auth_tag) = 16),
    CONSTRAINT request_payload_cells_ciphertext_check CHECK (octet_length(ciphertext) BETWEEN 16 AND 60000),
    CONSTRAINT request_payload_cells_aad_check CHECK (length(aad_context) BETWEEN 8 AND 128),
    CONSTRAINT request_payload_cells_request_kind_revision_key UNIQUE (request_id,kind,revision),
    -- Composite link target: a history row can only reference a payload of its
    -- own request (same-request provenance, not just same id).
    CONSTRAINT request_payload_cells_request_id_id_key UNIQUE (request_id,id)
);
CREATE TRIGGER request_payload_cells_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.request_payload_cells
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();

-- The database owns row_version/updated_at; identity, customer, immutable
-- intake context and the policy package can never be rewritten.
CREATE FUNCTION foundation.requests_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Requests are history' USING ERRCODE='23514';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.public_number IS DISTINCT FROM OLD.public_number
            OR NEW.customer_id IS DISTINCT FROM OLD.customer_id
            OR NEW.city_id IS DISTINCT FROM OLD.city_id
            OR NEW.intake_city_version_id IS DISTINCT FROM OLD.intake_city_version_id
            OR NEW.workflow_package_id IS DISTINCT FROM OLD.workflow_package_id
            OR NEW.intake_policy_revision_id IS DISTINCT FROM OLD.intake_policy_revision_id
            OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
            RAISE EXCEPTION 'Request identity, customer, intake context and creation are immutable' USING ERRCODE='23514';
        END IF;
        NEW.row_version := OLD.row_version + 1;
        NEW.updated_at := clock_timestamp();
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER requests_guard BEFORE INSERT OR UPDATE OR DELETE ON foundation.requests
    FOR EACH ROW EXECUTE FUNCTION foundation.requests_guard();

-- ---------------------------------------------------------------------------
-- 5. Typed history: contact, address, appliance, faults, preferences.
-- ---------------------------------------------------------------------------
CREATE TABLE foundation.request_contact_revisions (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    revision integer NOT NULL,
    mode varchar(16) NOT NULL,
    payload_cell_id uuid NOT NULL,
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT request_contact_revisions_revision_check CHECK (revision >= 1),
    CONSTRAINT request_contact_revisions_mode_check CHECK (mode COLLATE "C" IN ('PHONE','MESSENGER')),
    CONSTRAINT request_contact_revisions_request_id_fkey FOREIGN KEY (request_id)
        REFERENCES foundation.requests(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    -- Same-request payload provenance: the cell must belong to this request.
    CONSTRAINT request_contact_revisions_payload_fkey FOREIGN KEY (request_id,payload_cell_id)
        REFERENCES foundation.request_payload_cells(request_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_contact_revisions_request_revision_key UNIQUE (request_id,revision),
    CONSTRAINT request_contact_revisions_request_id_id_key UNIQUE (request_id,id)
);

-- District provenance: the district identity is referenced by immutable id
-- (row_version-free: existing district renames/archives must never be blocked
-- by historical request addresses), while the exact row_version observed at
-- intake is kept as provenance. The deferred guard below pins the observed
-- version to the district's CURRENT row_version at insert time only — later
-- district evolution does not invalidate stored history.
CREATE TABLE foundation.request_address_revisions (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    revision integer NOT NULL,
    district_id uuid,
    district_row_version integer,
    payload_cell_id uuid NOT NULL,
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT request_address_revisions_revision_check CHECK (revision >= 1),
    CONSTRAINT request_address_revisions_district_pair_check CHECK (
        (district_id IS NULL AND district_row_version IS NULL)
        OR (district_id IS NOT NULL AND district_row_version IS NOT NULL)),
    CONSTRAINT request_address_revisions_request_id_fkey FOREIGN KEY (request_id)
        REFERENCES foundation.requests(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_address_revisions_district_fkey FOREIGN KEY (district_id)
        REFERENCES foundation.administrative_districts(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_address_revisions_payload_fkey FOREIGN KEY (request_id,payload_cell_id)
        REFERENCES foundation.request_payload_cells(request_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_address_revisions_request_revision_key UNIQUE (request_id,revision),
    CONSTRAINT request_address_revisions_request_id_id_key UNIQUE (request_id,id)
);
CREATE TABLE foundation.request_appliance_revisions (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    revision integer NOT NULL,
    category_id uuid NOT NULL,
    category_kind varchar(16) NOT NULL DEFAULT 'CATEGORY',
    category_version_id uuid NOT NULL,
    model_id uuid,
    model_kind varchar(16) NOT NULL DEFAULT 'MODEL',
    model_version_id uuid,
    payload_cell_id uuid NOT NULL,
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT request_appliance_revisions_revision_check CHECK (revision >= 1),
    CONSTRAINT request_appliance_revisions_category_kind_check CHECK (category_kind = 'CATEGORY'),
    CONSTRAINT request_appliance_revisions_model_kind_check CHECK (model_kind = 'MODEL'),
    -- All-or-none model pair: an id without its version (or vice versa) is a
    -- partial provenance row and is refused outright, not left to MATCH SIMPLE.
    CONSTRAINT request_appliance_revisions_model_pair_check CHECK (
        (model_id IS NULL AND model_version_id IS NULL)
        OR (model_id IS NOT NULL AND model_version_id IS NOT NULL)),
    CONSTRAINT request_appliance_revisions_request_id_fkey FOREIGN KEY (request_id)
        REFERENCES foundation.requests(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_appliance_revisions_category_fkey FOREIGN KEY (category_id,category_kind)
        REFERENCES foundation.catalog_directory_entries(id,kind) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_appliance_revisions_model_fkey FOREIGN KEY (model_id,model_kind)
        REFERENCES foundation.catalog_directory_entries(id,kind) ON DELETE RESTRICT ON UPDATE RESTRICT,
    -- Exact published catalog revision provenance for the chosen entries.
    CONSTRAINT request_appliance_revisions_category_revision_fkey FOREIGN KEY (category_id,category_version_id)
        REFERENCES foundation.catalog_directory_versions(entry_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_appliance_revisions_model_revision_fkey FOREIGN KEY (model_id,model_version_id)
        REFERENCES foundation.catalog_directory_versions(entry_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_appliance_revisions_payload_fkey FOREIGN KEY (request_id,payload_cell_id)
        REFERENCES foundation.request_payload_cells(request_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_appliance_revisions_request_revision_key UNIQUE (request_id,revision),
    CONSTRAINT request_appliance_revisions_request_id_id_key UNIQUE (request_id,id)
);
CREATE FUNCTION foundation.request_appliance_revisions_guard_basis() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF EXISTS (
        SELECT FROM foundation.catalog_directory_entries e
        WHERE e.id = NEW.category_id AND e.kind = NEW.category_kind
          AND (e.current_version_id IS DISTINCT FROM NEW.category_version_id OR e.archived_at IS NOT NULL)) THEN
        RAISE EXCEPTION 'Appliance category must reference the live published revision' USING ERRCODE='23514';
    END IF;
    IF NEW.model_id IS NOT NULL THEN
        IF EXISTS (
            SELECT FROM foundation.catalog_directory_entries e
            WHERE e.id = NEW.model_id AND e.kind = NEW.model_kind
              AND (e.current_version_id IS DISTINCT FROM NEW.model_version_id OR e.archived_at IS NOT NULL)) THEN
            RAISE EXCEPTION 'Appliance model must reference the live published revision' USING ERRCODE='23514';
        END IF;
        -- The model must belong to the same chosen category: a model of another
        -- category is not a valid selection for this appliance revision.
        IF EXISTS (
            SELECT FROM foundation.catalog_directory_entries m
            WHERE m.id = NEW.model_id AND m.kind = 'MODEL'
              AND m.category_id IS DISTINCT FROM NEW.category_id) THEN
            RAISE EXCEPTION 'Appliance model must belong to the chosen category' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER request_appliance_revisions_basis_guard AFTER INSERT ON foundation.request_appliance_revisions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.request_appliance_revisions_guard_basis();

-- An address revision's district must belong to the request's own city AND the
-- recorded row_version must be the district's version current at insert time
-- (both checked deferred); later district evolution never rewrites history.
CREATE FUNCTION foundation.request_address_revisions_guard_city() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF NEW.district_id IS NOT NULL THEN
        IF EXISTS (
            SELECT FROM foundation.request_address_revisions a
            JOIN foundation.requests r ON r.id = a.request_id
            JOIN foundation.administrative_districts d ON d.id = a.district_id
            WHERE a.id = NEW.id AND (d.city_id IS DISTINCT FROM r.city_id
              OR d.row_version IS DISTINCT FROM a.district_row_version)) THEN
            RAISE EXCEPTION 'Address district must belong to the request city at the recorded revision' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER request_address_revisions_city_guard AFTER INSERT ON foundation.request_address_revisions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.request_address_revisions_guard_city();

-- The only set of selected symptoms: each row is one published fault of the
-- same category as its appliance revision, or the explicit "other" choice
-- whose non-empty description lives in the encrypted payload.
CREATE TABLE foundation.request_faults (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    appliance_revision_id uuid NOT NULL,
    is_other boolean NOT NULL DEFAULT false,
    fault_id uuid,
    fault_kind varchar(16) NOT NULL DEFAULT 'FAULT',
    fault_version_id uuid,
    category_id uuid NOT NULL,
    category_kind varchar(16) NOT NULL DEFAULT 'CATEGORY',
    CONSTRAINT request_faults_request_id_appliance_revision_id_fkey
        FOREIGN KEY (request_id,appliance_revision_id)
        REFERENCES foundation.request_appliance_revisions(request_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_faults_fault_kind_check CHECK (fault_kind = 'FAULT'),
    CONSTRAINT request_faults_category_kind_check CHECK (category_kind = 'CATEGORY'),
    CONSTRAINT request_faults_other_choice_check CHECK (
        (is_other AND fault_id IS NULL AND fault_version_id IS NULL)
        OR (NOT is_other AND fault_id IS NOT NULL AND fault_version_id IS NOT NULL)),
    -- Category match with the chosen appliance revision is enforced by the
    -- deferred trigger below; the FK only pins the published fault revision.
    CONSTRAINT request_faults_fault_revision_fkey FOREIGN KEY (fault_id,fault_version_id)
        REFERENCES foundation.catalog_directory_versions(entry_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_faults_fault_entry_fkey FOREIGN KEY (fault_id,fault_kind,category_id)
        REFERENCES foundation.catalog_directory_entries(id,kind,category_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_faults_request_revision_key UNIQUE (request_id,appliance_revision_id,fault_id)
);
CREATE FUNCTION foundation.request_faults_category_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM foundation.request_appliance_revisions a
        WHERE (a.request_id,a.id) = (NEW.request_id,NEW.appliance_revision_id)
          AND a.category_id = NEW.category_id) THEN
        RAISE EXCEPTION 'Selected fault category must match the appliance revision category' USING ERRCODE='23514';
    END IF;
    IF NOT NEW.is_other AND NOT EXISTS (
        SELECT FROM foundation.catalog_directory_entries e
        JOIN foundation.catalog_directory_versions v ON v.entry_id = e.id AND v.id = NEW.fault_version_id
        WHERE e.id = NEW.fault_id AND e.kind = 'FAULT' AND e.archived_at IS NULL
          AND e.current_version_id = NEW.fault_version_id) THEN
        RAISE EXCEPTION 'Selected fault must be the live published revision' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER request_faults_category_guard_trg AFTER INSERT ON foundation.request_faults
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.request_faults_category_guard();

-- Urgency/time preference only: no price, SLA or reservation semantics.
CREATE TABLE foundation.request_preference_revisions (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    revision integer NOT NULL,
    urgency varchar(16),
    preferred_windows jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT request_preference_revisions_revision_check CHECK (revision >= 1),
    CONSTRAINT request_preference_revisions_urgency_check CHECK (
        urgency IS NULL OR urgency COLLATE "C" IN ('FLEXIBLE','WITHIN_DAY','URGENT')),
    CONSTRAINT request_preference_revisions_windows_check CHECK (
        jsonb_typeof(preferred_windows) = 'array' AND jsonb_array_length(preferred_windows) <= 7),
    CONSTRAINT request_preference_revisions_request_id_fkey FOREIGN KEY (request_id)
        REFERENCES foundation.requests(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_preference_revisions_request_revision_key UNIQUE (request_id,revision),
    CONSTRAINT request_preference_revisions_request_id_id_key UNIQUE (request_id,id)
);

CREATE TRIGGER request_contact_revisions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.request_contact_revisions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER request_address_revisions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.request_address_revisions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER request_appliance_revisions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.request_appliance_revisions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER request_faults_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.request_faults
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER request_preference_revisions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.request_preference_revisions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();

-- Write-time payload provenance: each history row must reference a payload
-- cell of its OWN kind and revision (the AAD binds kind+revision for decrypt,
-- but the immutable snapshot must not even commit against a wrong cell).
CREATE FUNCTION foundation.request_history_payload_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE expected_kind varchar(24);
BEGIN
    expected_kind := CASE tg_relid::regclass::text
        WHEN 'foundation.request_contact_revisions' THEN 'CONTACT'
        WHEN 'foundation.request_address_revisions' THEN 'ADDRESS'
        WHEN 'foundation.request_appliance_revisions' THEN 'DETAILS'
        ELSE NULL END;
    IF expected_kind IS NULL OR EXISTS (
        SELECT FROM foundation.request_payload_cells c
        WHERE (c.request_id,c.id) = (NEW.request_id,NEW.payload_cell_id)
          AND (c.kind IS DISTINCT FROM expected_kind OR c.revision IS DISTINCT FROM NEW.revision)) THEN
        RAISE EXCEPTION 'History row must reference a payload cell of its own kind and revision' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER request_contact_revisions_payload_guard AFTER INSERT ON foundation.request_contact_revisions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.request_history_payload_guard();
CREATE CONSTRAINT TRIGGER request_address_revisions_payload_guard AFTER INSERT ON foundation.request_address_revisions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.request_history_payload_guard();
CREATE CONSTRAINT TRIGGER request_appliance_revisions_payload_guard AFTER INSERT ON foundation.request_appliance_revisions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.request_history_payload_guard();

-- Current pointers are composite: a pointer can only name a revision of its
-- own request (mixed-parent rows are impossible by FK, not by convention).
-- The pointer FKs are DEFERRABLE INITIALLY DEFERRED (the plan's deferred
-- completeness pattern): a request and its first history rows are created in
-- ONE transaction with the pointers already set, so row_version stays 1 at
-- creation (§6.1) instead of requiring a follow-up UPDATE.
CREATE UNIQUE INDEX requests_current_contact_key ON foundation.requests(id,current_contact_revision_id);
CREATE UNIQUE INDEX requests_current_address_key ON foundation.requests(id,current_address_revision_id);
CREATE UNIQUE INDEX requests_current_appliance_key ON foundation.requests(id,current_appliance_revision_id);
CREATE UNIQUE INDEX requests_current_preference_key ON foundation.requests(id,current_preference_revision_id);
ALTER TABLE foundation.requests ADD CONSTRAINT requests_current_contact_revision_fkey
    FOREIGN KEY (id,current_contact_revision_id)
    REFERENCES foundation.request_contact_revisions(request_id,id)
    ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE foundation.requests ADD CONSTRAINT requests_current_address_revision_fkey
    FOREIGN KEY (id,current_address_revision_id)
    REFERENCES foundation.request_address_revisions(request_id,id)
    ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE foundation.requests ADD CONSTRAINT requests_current_appliance_revision_fkey
    FOREIGN KEY (id,current_appliance_revision_id)
    REFERENCES foundation.request_appliance_revisions(request_id,id)
    ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE foundation.requests ADD CONSTRAINT requests_current_preference_revision_fkey
    FOREIGN KEY (id,current_preference_revision_id)
    REFERENCES foundation.request_preference_revisions(request_id,id)
    ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED;

-- ---------------------------------------------------------------------------
-- 6. Append-only business events and durable command identity.
-- ---------------------------------------------------------------------------
-- UNIQUE(principal,operation,idempotency_key) is the durable command identity
-- of §4.3; details never contain raw personal values, only IDs and versions.
CREATE TABLE foundation.request_events (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    command varchar(64) NOT NULL,
    principal varchar(160) NOT NULL,
    operation varchar(64) NOT NULL,
    idempotency_key uuid NOT NULL,
    actor_type varchar(12) NOT NULL,
    actor_session_id uuid,
    actor_staff_id uuid,
    resulting_version integer NOT NULL,
    correlation_id uuid NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT request_events_request_id_fkey FOREIGN KEY (request_id)
        REFERENCES foundation.requests(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_events_actor_type_check CHECK (actor_type COLLATE "C" IN ('F','STAFF','SYSTEM')),
    CONSTRAINT request_events_actor_session_id_fkey FOREIGN KEY (actor_session_id)
        REFERENCES foundation.request_sessions(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_events_actor_staff_id_fkey FOREIGN KEY (actor_staff_id)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT request_events_resulting_version_check CHECK (resulting_version >= 1),
    CONSTRAINT request_events_command_check CHECK (length(command) BETWEEN 3 AND 64),
    CONSTRAINT request_events_principal_operation_key_key UNIQUE (principal,operation,idempotency_key)
);
CREATE INDEX request_events_request_idx ON foundation.request_events(request_id,created_at);
CREATE TRIGGER request_events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.request_events
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();

-- ---------------------------------------------------------------------------
-- 7. Unified GEO/CFG writer fence on the nine basis relations.
-- ---------------------------------------------------------------------------
-- Strict semantics (audit-fixed): the writer's OWN backend must ALREADY hold a
-- granted ExclusiveLock on (734305,1) — a session that never called the fence
-- port is refused here and never acquires it implicitly. pg_locks cannot
-- distinguish session- from xact-scoped advisory locks, so the second step
-- re-fixes the hold transaction-scoped with a non-waiting try-lock: reentrant
-- when the writer already holds the xact lock, a conversion when it only held
-- a session lock, and a refusal when anyone else holds a conflicting lock.
-- The guard is not authorization and never waits under a row lock.
CREATE FUNCTION foundation.geo_cfg_fence_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_locks
        WHERE locktype='advisory' AND granted AND pid=pg_backend_pid()
          AND classid='734305'::int::oid AND objid='1'::int::oid AND objsubid=2
          AND mode='ExclusiveLock') THEN
        RAISE EXCEPTION 'GEO/CFG basis writes require the unified writer fence taken before the statement'
            USING ERRCODE='42501';
    END IF;
    IF NOT pg_try_advisory_xact_lock(734305, 1) THEN
        RAISE EXCEPTION 'GEO/CFG basis writes require a transaction-scoped fence hold'
            USING ERRCODE='42501';
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER business_settings_versions_geo_cfg_fence
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON foundation.business_settings_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.geo_cfg_fence_guard();
CREATE TRIGGER service_cities_geo_cfg_fence
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON foundation.service_cities
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.geo_cfg_fence_guard();
CREATE TRIGGER service_city_versions_geo_cfg_fence
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON foundation.service_city_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.geo_cfg_fence_guard();
CREATE TRIGGER administrative_districts_geo_cfg_fence
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON foundation.administrative_districts
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.geo_cfg_fence_guard();
CREATE TRIGGER service_areas_geo_cfg_fence
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON foundation.service_areas
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.geo_cfg_fence_guard();
CREATE TRIGGER service_area_versions_geo_cfg_fence
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON foundation.service_area_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.geo_cfg_fence_guard();
CREATE TRIGGER service_area_district_coverage_geo_cfg_fence
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON foundation.service_area_district_coverage
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.geo_cfg_fence_guard();
CREATE TRIGGER reference_entries_geo_cfg_fence
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON foundation.reference_entries
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.geo_cfg_fence_guard();
CREATE TRIGGER reference_entry_versions_geo_cfg_fence
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON foundation.reference_entry_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.geo_cfg_fence_guard();

-- ---------------------------------------------------------------------------
-- 8. Privileges: exact column grants, no PUBLIC access, no DELETE anywhere.
-- ---------------------------------------------------------------------------
REVOKE ALL ON foundation.request_policy_packages, foundation.customers,
    foundation.request_payload_cells, foundation.requests,
    foundation.request_contact_revisions, foundation.request_address_revisions,
    foundation.request_appliance_revisions, foundation.request_faults,
    foundation.request_preference_revisions, foundation.request_events
    FROM PUBLIC, fixlevelup_runtime;
REVOKE ALL ON FUNCTION foundation.geo_cfg_fence_guard(), foundation.requests_guard(),
    foundation.request_faults_category_guard(), foundation.request_appliance_revisions_guard_basis(),
    foundation.request_address_revisions_guard_city(), foundation.request_history_payload_guard()
    FROM PUBLIC, fixlevelup_runtime;
REVOKE ALL ON SEQUENCE foundation.request_public_numbers FROM PUBLIC, fixlevelup_runtime;

GRANT SELECT(id,workflow_version,policy_revision,metadata_sha256,metadata,created_at)
    ON foundation.request_policy_packages TO fixlevelup_runtime;
GRANT SELECT(id,created_at) ON foundation.customers TO fixlevelup_runtime;
GRANT INSERT(id) ON foundation.customers TO fixlevelup_runtime;
GRANT SELECT(id,request_id,kind,revision,key_id,created_at),
    INSERT(id,request_id,kind,revision,key_id,wrapped_dek,nonce,ciphertext,auth_tag,aad_context)
    ON foundation.request_payload_cells TO fixlevelup_runtime;
GRANT SELECT(id,public_number,type,status,row_version,customer_id,city_id,intake_city_version_id,
    workflow_package_id,intake_policy_revision_id,current_contact_revision_id,current_address_revision_id,
    current_appliance_revision_id,current_preference_revision_id,created_at,updated_at,is_waiting_link),
    INSERT(id,type,status,customer_id,city_id,intake_city_version_id,
    workflow_package_id,intake_policy_revision_id,current_contact_revision_id,
    current_address_revision_id,current_appliance_revision_id,current_preference_revision_id),
    UPDATE(status,current_contact_revision_id,current_address_revision_id,
    current_appliance_revision_id,current_preference_revision_id,row_version,updated_at)
    ON foundation.requests TO fixlevelup_runtime;
GRANT USAGE ON SEQUENCE foundation.request_public_numbers TO fixlevelup_runtime;
GRANT SELECT(id,request_id,revision,mode,payload_cell_id,created_at),
    INSERT(id,request_id,revision,mode,payload_cell_id)
    ON foundation.request_contact_revisions TO fixlevelup_runtime;
GRANT SELECT(id,request_id,revision,district_id,district_row_version,payload_cell_id,created_at),
    INSERT(id,request_id,revision,district_id,district_row_version,payload_cell_id)
    ON foundation.request_address_revisions TO fixlevelup_runtime;
GRANT SELECT(id,request_id,revision,category_id,category_kind,category_version_id,model_id,model_kind,model_version_id,payload_cell_id,created_at),
    INSERT(id,request_id,revision,category_id,category_kind,category_version_id,model_id,model_kind,model_version_id,payload_cell_id)
    ON foundation.request_appliance_revisions TO fixlevelup_runtime;
GRANT SELECT(id,request_id,appliance_revision_id,is_other,fault_id,fault_kind,fault_version_id,category_id,category_kind),
    INSERT(id,request_id,appliance_revision_id,is_other,fault_id,fault_kind,fault_version_id,category_id,category_kind)
    ON foundation.request_faults TO fixlevelup_runtime;
GRANT SELECT(id,request_id,revision,urgency,preferred_windows,created_at),
    INSERT(id,request_id,revision,urgency,preferred_windows)
    ON foundation.request_preference_revisions TO fixlevelup_runtime;
GRANT SELECT(id,request_id,command,principal,operation,idempotency_key,actor_type,actor_session_id,actor_staff_id,resulting_version,correlation_id,details,created_at),
    INSERT(id,request_id,command,principal,operation,idempotency_key,
    actor_type,actor_session_id,actor_staff_id,resulting_version,correlation_id,details)
    ON foundation.request_events TO fixlevelup_runtime;

COMMIT;
