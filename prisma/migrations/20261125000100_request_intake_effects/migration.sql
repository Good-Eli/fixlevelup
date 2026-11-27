BEGIN;
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET LOCAL search_path = pg_catalog;

-- S3: additive command evidence, submit receipts and file retention interlock.
-- The migration provisions capability *codes*, never grants, procedures, keys or policy.
SELECT pg_advisory_xact_lock(hashtextextended('fixlevelup:admin-invariant',0));
LOCK TABLE foundation.permissions IN SHARE ROW EXCLUSIVE MODE NOWAIT;
LOCK TABLE foundation.role_permissions IN ACCESS EXCLUSIVE MODE NOWAIT;

INSERT INTO foundation.permissions(code,module,description,protected,active)
SELECT code,'requests',description,false,true FROM (VALUES
    ('requests.read','Просмотр минимальной записи заявки'),
    ('requests.create','Ручной приём заявки'),
    ('requests.review','Рассмотрение и уточнение заявки'),
    ('requests.coverage.assess','Оценка покрытия адреса заявки'),
    ('requests.contact.manage','Управление контактом заявки'),
    ('requests.ready','Готовность к назначению'),
    ('requests.cancel','Отмена заявки')
) AS catalog(code,description);

ALTER TABLE foundation.role_permissions DROP CONSTRAINT role_permissions_scope_check;
ALTER TABLE foundation.role_permissions ADD CONSTRAINT role_permissions_scope_check CHECK (
    CASE
        WHEN permission_code LIKE 'staff.self.%' THEN scope_type='SELF'
        WHEN permission_code IN ('geography.read','geography.manage','geography.publish',
            'staff.geography.read','staff.geography.manage','references.callbackinterval.read',
            'references.callbackinterval.manage','content.read','content.manage','content.publish',
            'pricing.read','pricing.manage','requests.read','requests.create','requests.review',
            'requests.coverage.assess','requests.contact.manage','requests.ready','requests.cancel')
            THEN scope_type IN ('CITY','GLOBAL')
        ELSE scope_type='GLOBAL'
    END);

CREATE FUNCTION foundation.request_role_grant_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='UPDATE' AND OLD.permission_code IN ('requests.read','requests.create','requests.review',
        'requests.coverage.assess','requests.contact.manage','requests.ready','requests.cancel')
        AND ROW(OLD.role_id,OLD.permission_code,OLD.scope_type) IS DISTINCT FROM ROW(NEW.role_id,NEW.permission_code,NEW.scope_type) THEN
        RAISE EXCEPTION 'Immutable request grant identity' USING ERRCODE='23514';
    END IF;
    IF NEW.permission_code NOT IN ('requests.read','requests.create','requests.review',
        'requests.coverage.assess','requests.contact.manage','requests.ready','requests.cancel') THEN RETURN NEW; END IF;
    -- Runtime may revoke an existing request grant, but it may not INSERT even a
    -- disabled placeholder or reactivate one. Otherwise a direct runtime INSERT
    -- could reserve the unique (role, permission) key and poison a later reviewed
    -- grant operation without ever becoming an effective permission.
    -- A revocation/no-op is safe only when the old row was already a P05 grant.
    -- Do not let a runtime repurpose a legacy row into a disabled P05 placeholder.
    IF TG_OP='UPDATE' AND OLD.permission_code IN ('requests.read','requests.create','requests.review',
        'requests.coverage.assess','requests.contact.manage','requests.ready','requests.cancel')
        AND ROW(OLD.role_id,OLD.permission_code,OLD.scope_type)
            IS NOT DISTINCT FROM ROW(NEW.role_id,NEW.permission_code,NEW.scope_type)
        AND (NOT NEW.enabled OR OLD.enabled) THEN RETURN NEW; END IF;
    IF current_user<>'fixlevelup_migrator' OR current_database() COLLATE "C" !~
        '^fixlevelup_(p05_[a-z0-9_]+|configuration_test_[0-9a-f]{24})$' THEN
        RAISE EXCEPTION 'Request grants are not issued by the runtime' USING ERRCODE='42501';
    END IF;
    IF NOT EXISTS (SELECT FROM foundation.permissions p WHERE p.code=NEW.permission_code AND p.active
        AND NOT p.protected AND p.module='requests') OR NOT EXISTS (SELECT FROM foundation.roles r
        WHERE r.id=NEW.role_id AND r.status='ACTIVE' AND (
            (r.role_type='SYSTEM' AND r.code='ADMIN') OR
            (NEW.scope_type='CITY' AND (r.role_type='CUSTOM' OR (r.role_type='SYSTEM' AND r.code='MANAGER'))))) THEN
        RAISE EXCEPTION 'Invalid request grant scope or role' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER request_role_grant_guard BEFORE INSERT OR UPDATE ON foundation.role_permissions
    FOR EACH ROW EXECUTE FUNCTION foundation.request_role_grant_guard();

-- Same-request and exact-parent FK targets. Pre-S3 writers keep their original ACL.
CREATE UNIQUE INDEX request_sessions_intake_tuple_key
    ON foundation.request_sessions(id,intake_city_id,intake_city_version_id);
CREATE UNIQUE INDEX consent_records_request_given_tuple_key
    ON foundation.consent_records(id,session_id,document_id,document_version_id,purpose,action);
CREATE UNIQUE INDEX request_events_receipt_tuple_key
    ON foundation.request_events(id,request_id,resulting_version,correlation_id,command);
CREATE UNIQUE INDEX request_events_request_version_key
    ON foundation.request_events(request_id,resulting_version);
CREATE UNIQUE INDEX request_events_form_submit_key
    ON foundation.request_events(id,request_id,command,actor_session_id);
CREATE UNIQUE INDEX file_publications_intent_file_key ON foundation.file_publications(intent_id,id);
CREATE UNIQUE INDEX file_privacy_controls_intent_open_key ON foundation.file_privacy_controls(intent_id,delete_state);

CREATE UNIQUE INDEX requests_id_city_key ON foundation.requests(id,city_id);
-- Multiple reviewed policy revisions can pin the same workflow package semantics.
ALTER TABLE foundation.request_policy_packages DROP CONSTRAINT request_policy_packages_workflow_version_key;
ALTER TABLE foundation.requests ADD CONSTRAINT requests_package_pair_check
    CHECK (workflow_package_id=intake_policy_revision_id);

CREATE TABLE foundation.request_staff_evidence (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL REFERENCES foundation.requests(id) ON DELETE RESTRICT,
    staff_id uuid NOT NULL REFERENCES foundation.staff(id) ON DELETE RESTRICT,
    purpose varchar(32) NOT NULL CHECK (purpose IN ('MANUAL_INTAKE','PHONE_GIVE','CONTACT_CHANGE','PHONE_WITHDRAW')),
    procedure_revision varchar(68) NOT NULL CHECK (procedure_revision COLLATE "C" ~ '^[a-z0-9][a-z0-9.-]{2,67}$'),
    valid_until timestamptz(6) NOT NULL CHECK (isfinite(valid_until)),
    declared_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(id,request_id)
);
CREATE UNIQUE INDEX request_staff_one_source_key ON foundation.request_staff_evidence(request_id) WHERE purpose='MANUAL_INTAKE';

CREATE TABLE foundation.request_command_receipts (
    event_id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    version integer NOT NULL CHECK (version>0),
    correlation_id uuid NOT NULL,
    command varchar(64) NOT NULL,
    key_id varchar(64) NOT NULL CHECK (key_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._-]{3,63}$'),
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint)=32),
    resulting_status varchar(32) NOT NULL CHECK (resulting_status IN (
        'NEW','CALLBACK_REQUIRED','WAITING_TELEGRAM_LINK','WAITING_CHANNEL_LINK','MANAGER_REVIEW',
        'WAITING_ASSIGNMENT','ASSIGNED','TECHNICIAN_ACCEPTED','ON_THE_WAY','ARRIVED','DIAGNOSTICS',
        'WAITING_ESTIMATE_APPROVAL','IN_PROGRESS','WAITING_PARTS','PAUSED','TECHNICIAN_COMPLETED',
        'REVISIT_REQUIRED','CLOSED','CANCELLED')),
    audit_id uuid NOT NULL UNIQUE REFERENCES foundation.audit_logs(id) ON DELETE RESTRICT,
    outbox_id uuid NOT NULL UNIQUE REFERENCES foundation.outbox_events(id) ON DELETE RESTRICT,
    FOREIGN KEY (event_id,request_id,version,correlation_id,command)
      REFERENCES foundation.request_events(id,request_id,resulting_version,correlation_id,command) ON DELETE RESTRICT,
    UNIQUE(event_id,request_id)
);

CREATE TABLE foundation.request_session_submits (
    session_id uuid PRIMARY KEY,
    request_id uuid NOT NULL UNIQUE,
    customer_id uuid NOT NULL,
    intake_city_id uuid NOT NULL,
    intake_city_version_id uuid NOT NULL,
    consent_id uuid NOT NULL,
    document_id uuid NOT NULL,
    document_version_id uuid NOT NULL,
    purpose varchar(32) NOT NULL DEFAULT 'REQUEST_PROCESSING' CHECK (purpose='REQUEST_PROCESSING'),
    action varchar(16) NOT NULL DEFAULT 'GIVEN' CHECK (action='GIVEN'),
    event_id uuid NOT NULL UNIQUE,
    submit_command varchar(64) NOT NULL CHECK (submit_command IN ('CreateCallback','CreateRepair')),
    FOREIGN KEY (event_id,request_id,submit_command,session_id)
      REFERENCES foundation.request_events(id,request_id,command,actor_session_id) ON DELETE RESTRICT,
    FOREIGN KEY (session_id,intake_city_id,intake_city_version_id)
      REFERENCES foundation.request_sessions(id,intake_city_id,intake_city_version_id) ON DELETE RESTRICT,
    FOREIGN KEY (request_id,intake_city_id,intake_city_version_id)
      REFERENCES foundation.requests(id,city_id,intake_city_version_id) ON DELETE RESTRICT,
    FOREIGN KEY (request_id,customer_id) REFERENCES foundation.requests(id,customer_id) ON DELETE RESTRICT,
    FOREIGN KEY (consent_id,session_id,document_id,document_version_id,purpose,action)
      REFERENCES foundation.consent_records(id,session_id,document_id,document_version_id,purpose,action) ON DELETE RESTRICT,
    FOREIGN KEY (event_id,request_id) REFERENCES foundation.request_command_receipts(event_id,request_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    UNIQUE(request_id,session_id)
);

CREATE TABLE foundation.phone_permission_events (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    contact_revision_id uuid NOT NULL,
    purpose varchar(32) NOT NULL DEFAULT 'REQUEST_SERVICE_CALL' CHECK (purpose='REQUEST_SERVICE_CALL'),
    action varchar(16) NOT NULL CHECK (action IN ('GIVEN','REVOKED')),
    supersedes_given_id uuid UNIQUE,
    given_action varchar(16) NOT NULL DEFAULT 'GIVEN' CHECK (given_action='GIVEN'),
    event_id uuid NOT NULL UNIQUE,
    staff_evidence_id uuid,
    occurred_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CHECK ((action='GIVEN' AND supersedes_given_id IS NULL) OR (action='REVOKED' AND supersedes_given_id IS NOT NULL)),
    UNIQUE(id,request_id,contact_revision_id,purpose,action),
    FOREIGN KEY (request_id,contact_revision_id) REFERENCES foundation.request_contact_revisions(request_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (supersedes_given_id,request_id,contact_revision_id,purpose,given_action)
      REFERENCES foundation.phone_permission_events(id,request_id,contact_revision_id,purpose,action) ON DELETE RESTRICT,
    FOREIGN KEY (event_id,request_id) REFERENCES foundation.request_command_receipts(event_id,request_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (staff_evidence_id,request_id) REFERENCES foundation.request_staff_evidence(id,request_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX request_one_phone_given_key ON foundation.phone_permission_events(request_id,contact_revision_id)
    WHERE action='GIVEN';

-- PHONE permission completeness, part 1 of 2 — the row-to-command direction.
-- A call permission exists only as the effect of an exact reviewed command, with
-- the exact actor provenance: GIVEN by CreateCallback / PHONE CreateRepair /
-- ChooseCallback, REVOKED only by WithdrawPhonePermission. Both the actor kind and
-- the evidence purpose/owner are checked here, at INSERT time, because a deferred
-- event-side guard cannot see a permission row appended against an OLD event.
CREATE FUNCTION foundation.request_phone_permission_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    command_name varchar(64);
    event_status varchar(32);
    event_version integer;
    event_actor_type varchar(12);
    event_actor_staff_id uuid;
    request_version integer;
    current_contact uuid;
    original_mode varchar(16);
    evidence record;
BEGIN
    SELECT r.command,r.resulting_status,e.actor_type,e.actor_staff_id,e.resulting_version
      INTO command_name,event_status,event_actor_type,event_actor_staff_id,event_version
      FROM foundation.request_command_receipts r
      JOIN foundation.request_events e ON e.id=r.event_id AND e.request_id=r.request_id
      WHERE r.event_id=NEW.event_id AND r.request_id=NEW.request_id;
    IF command_name IS NULL THEN
        RAISE EXCEPTION 'Phone permission without a request command' USING ERRCODE='23514';
    END IF;
    SELECT q.current_contact_revision_id,q.row_version INTO current_contact,request_version
      FROM foundation.requests q WHERE q.id=NEW.request_id;
    -- An allow/revoke always concerns the request's CURRENT contact revision.
    IF current_contact IS DISTINCT FROM NEW.contact_revision_id THEN
        RAISE EXCEPTION 'Phone permission is not for the current contact' USING ERRCODE='23514';
    END IF;
    -- ...and the command it belongs to must be the request's CURRENT version, so a
    -- historical event can never be used to append a permission afterwards.
    -- `phone_permission_events.event_id` is UNIQUE, so an event that already carries
    -- its row cannot receive a second one either.
    IF event_version IS DISTINCT FROM request_version THEN
        RAISE EXCEPTION 'Phone permission belongs to a superseded request version' USING ERRCODE='23514';
    END IF;
    IF NEW.action='GIVEN' THEN
        IF command_name='CreateCallback' THEN
            -- A callback intake is ALWAYS a phone-mode intake: the stored
            -- preference mode is never trusted for it.
            IF event_status<>'CALLBACK_REQUIRED' THEN
                RAISE EXCEPTION 'Callback intake is not in the callback state' USING ERRCODE='23514';
            END IF;
        ELSIF command_name='CreateRepair' THEN
            -- A repair intake authorises a call only as a STAFF manual intake whose
            -- ORIGINAL (first) preference was PHONE and which did not land in a
            -- channel-waiting state. The current revision is irrelevant here: many
            -- later preference versions must not retro-authorise an old intake.
            SELECT pr.contact_mode INTO original_mode FROM foundation.request_preference_revisions pr
              WHERE pr.request_id=NEW.request_id AND pr.revision=1;
            IF event_actor_type<>'STAFF' OR event_status<>'NEW' OR original_mode IS DISTINCT FROM 'PHONE' THEN
                RAISE EXCEPTION 'Phone permission on a non-phone repair intake' USING ERRCODE='23514';
            END IF;
        ELSIF command_name<>'ChooseCallback' THEN
            RAISE EXCEPTION 'Phone permission issued by an unrelated command' USING ERRCODE='23514';
        END IF;
    ELSIF command_name<>'WithdrawPhonePermission' THEN
        RAISE EXCEPTION 'Phone permission revoked by an unrelated command' USING ERRCODE='23514';
    END IF;
    IF event_actor_type='STAFF' THEN
        SELECT e.staff_id,e.purpose,e.request_id INTO evidence
          FROM foundation.request_staff_evidence e WHERE e.id=NEW.staff_evidence_id;
        IF NEW.staff_evidence_id IS NULL OR evidence.request_id IS DISTINCT FROM NEW.request_id
            OR evidence.staff_id IS DISTINCT FROM event_actor_staff_id
            OR evidence.purpose IS DISTINCT FROM (CASE NEW.action WHEN 'GIVEN' THEN 'PHONE_GIVE' ELSE 'PHONE_WITHDRAW' END) THEN
            RAISE EXCEPTION 'Incomplete phone permission evidence' USING ERRCODE='23514';
        END IF;
    ELSIF NEW.staff_evidence_id IS NOT NULL THEN
        -- A customer action carries no staff provenance at all.
        RAISE EXCEPTION 'Unexpected staff evidence on a customer phone permission' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER phone_permission_complete BEFORE INSERT ON foundation.phone_permission_events
    FOR EACH ROW EXECUTE FUNCTION foundation.request_phone_permission_guard();

CREATE TABLE foundation.request_files (
    request_id uuid NOT NULL,
    owner_session_id uuid NOT NULL,
    intent_id uuid NOT NULL UNIQUE,
    file_id uuid NOT NULL UNIQUE,
    open_state varchar(24) NOT NULL DEFAULT 'OPEN' CHECK (open_state='OPEN'),
    PRIMARY KEY(request_id,file_id),
    FOREIGN KEY (request_id,owner_session_id) REFERENCES foundation.request_session_submits(request_id,session_id) ON DELETE RESTRICT,
    FOREIGN KEY (intent_id,owner_session_id) REFERENCES foundation.file_upload_intents(id,owner_request_session_id) ON DELETE RESTRICT,
    FOREIGN KEY (intent_id,file_id) REFERENCES foundation.file_publications(intent_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (intent_id,open_state) REFERENCES foundation.file_privacy_controls(intent_id,delete_state)
      ON UPDATE RESTRICT ON DELETE RESTRICT
);

-- Existing (S1 lab) snapshots may lack the explicit contact preference. No
-- legacy data is reclassified as permission; new command rows always set it.
ALTER TABLE foundation.request_preference_revisions ADD COLUMN contact_mode varchar(16);
ALTER TABLE foundation.request_preference_revisions ADD CONSTRAINT request_preference_contact_mode_check
    CHECK (contact_mode IN ('PHONE','MESSENGER'));

CREATE TABLE foundation.request_appliance_brands (
    appliance_revision_id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    brand_id uuid NOT NULL,
    brand_kind varchar(16) NOT NULL DEFAULT 'BRAND' CHECK (brand_kind='BRAND'),
    brand_version_id uuid NOT NULL,
    FOREIGN KEY (request_id,appliance_revision_id) REFERENCES foundation.request_appliance_revisions(request_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (brand_id,brand_kind) REFERENCES foundation.catalog_directory_entries(id,kind) ON DELETE RESTRICT,
    FOREIGN KEY (brand_id,brand_version_id) REFERENCES foundation.catalog_directory_versions(entry_id,id) ON DELETE RESTRICT
);

CREATE TABLE foundation.request_channel_choices (
    request_id uuid PRIMARY KEY REFERENCES foundation.requests(id) ON DELETE RESTRICT,
    provider varchar(8) NOT NULL CHECK (provider IN ('TG','VK','MAX')),
    catalog_version_id uuid NOT NULL,
    option_version_id uuid NOT NULL,
    readiness_basis_id uuid NOT NULL,
    checked_at timestamptz(6) NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE foundation.request_address_review_attempts (
    -- Deliberately no FK: this bounded append-only audit is committed on a
    -- separate guarded connection while the business transaction holds locks.
    evidence_id uuid PRIMARY KEY,
    staff_id uuid NOT NULL,
    request_id uuid NOT NULL,
    address_revision_id uuid NOT NULL,
    purpose varchar(24) NOT NULL CHECK (purpose='COVERAGE_REVIEW'),
    correlation_id uuid NOT NULL UNIQUE,
    occurred_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(correlation_id,request_id,address_revision_id,staff_id)
);

CREATE TABLE foundation.request_coverage_assessments (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL,
    address_revision_id uuid NOT NULL,
    city_id uuid NOT NULL,
    city_version_id uuid NOT NULL,
    area_id uuid,
    area_version_id uuid,
    basis_digest varchar(64) NOT NULL CHECK (basis_digest COLLATE "C" ~ '^[a-f0-9]{64}$'),
    outcome varchar(16) NOT NULL CHECK (outcome IN ('IN_ZONE','OUTSIDE','REVIEW','EXCEPTION')),
    reason varchar(24) CHECK (reason IN ('OVERLAP_REVIEW','OUTSIDE_REVIEW','OPERATOR_REVIEW')),
    staff_id uuid NOT NULL REFERENCES foundation.staff(id) ON DELETE RESTRICT,
    attempt_correlation_id uuid NOT NULL UNIQUE,
    event_id uuid NOT NULL UNIQUE,
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CHECK ((area_id IS NULL)=(area_version_id IS NULL)),
    CHECK (outcome NOT IN ('IN_ZONE','EXCEPTION') OR area_id IS NOT NULL),
    CHECK (outcome NOT IN ('OUTSIDE','EXCEPTION') OR reason IS NOT NULL),
    FOREIGN KEY (request_id,address_revision_id) REFERENCES foundation.request_address_revisions(request_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (city_id,city_version_id) REFERENCES foundation.service_city_versions(city_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (area_id,city_id,area_version_id) REFERENCES foundation.service_area_versions(area_id,city_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (request_id,city_id) REFERENCES foundation.requests(id,city_id) ON DELETE RESTRICT,
    FOREIGN KEY (attempt_correlation_id,request_id,address_revision_id,staff_id)
      REFERENCES foundation.request_address_review_attempts(correlation_id,request_id,address_revision_id,staff_id) ON DELETE RESTRICT,
    FOREIGN KEY (event_id,request_id) REFERENCES foundation.request_command_receipts(event_id,request_id)
      ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    UNIQUE(request_id,address_revision_id,id)
);

ALTER TABLE foundation.requests ADD COLUMN current_assessment_id uuid;
ALTER TABLE foundation.requests ADD CONSTRAINT requests_current_assessment_fkey
    FOREIGN KEY (id,current_address_revision_id,current_assessment_id)
    REFERENCES foundation.request_coverage_assessments(request_id,address_revision_id,id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE foundation.requests ADD CONSTRAINT requests_assessment_requires_address_check
    CHECK (current_assessment_id IS NULL OR current_address_revision_id IS NOT NULL);

CREATE TABLE foundation.request_intake_provenance (
    request_id uuid PRIMARY KEY REFERENCES foundation.requests(id) ON DELETE RESTRICT,
    source_entry_id uuid NOT NULL,
    source_version_id uuid NOT NULL,
    source_type varchar(32) NOT NULL DEFAULT 'REQUEST_SOURCE' CHECK (source_type='REQUEST_SOURCE'),
    callback_entry_id uuid,
    callback_version_id uuid,
    callback_type varchar(32) NOT NULL DEFAULT 'CALLBACK_INTERVAL' CHECK (callback_type='CALLBACK_INTERVAL'),
    CHECK ((callback_entry_id IS NULL)=(callback_version_id IS NULL)),
    FOREIGN KEY (source_entry_id,source_type,source_version_id)
      REFERENCES foundation.reference_entry_versions(entry_id,type,id) ON DELETE RESTRICT,
    FOREIGN KEY (callback_entry_id,callback_type,callback_version_id)
      REFERENCES foundation.reference_entry_versions(entry_id,type,id) ON DELETE RESTRICT
);

CREATE FUNCTION foundation.request_effect_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    receipt record;
    state record;
    preference_mode varchar(16);
BEGIN
    SELECT r.version,r.resulting_status,r.audit_id,r.outbox_id INTO receipt
      FROM foundation.request_command_receipts r WHERE r.event_id=NEW.id AND r.request_id=NEW.request_id;
    SELECT q.type,q.status,q.row_version,q.current_contact_revision_id,q.current_preference_revision_id,
      q.current_address_revision_id,q.current_appliance_revision_id,q.current_assessment_id INTO state
      FROM foundation.requests q WHERE q.id=NEW.request_id;
    IF receipt.version IS DISTINCT FROM NEW.resulting_version OR state.row_version IS DISTINCT FROM NEW.resulting_version
        OR receipt.resulting_status IS DISTINCT FROM state.status OR NEW.details->>'status' IS DISTINCT FROM state.status
        OR NEW.command IS DISTINCT FROM NEW.operation OR NEW.principal IS DISTINCT FROM
            (CASE WHEN NEW.actor_type='F' THEN 'F:'||NEW.actor_session_id::text ELSE 'STAFF:'||NEW.actor_staff_id::text END)
        OR NOT ((NEW.actor_type='F' AND NEW.actor_session_id IS NOT NULL AND NEW.actor_staff_id IS NULL
                AND NEW.command IN ('CreateCallback','CreateRepair','ChooseCallback','WithdrawPhonePermission','CancelRequest'))
             OR (NEW.actor_type='STAFF' AND NEW.actor_staff_id IS NOT NULL AND NEW.actor_session_id IS NULL
                AND NEW.command IN ('CreateCallback','CreateRepair','StartReview','ConvertCallback','ChangeDetails',
                    'RecordCoverageAssessment','ChangeContact','ReadyForDispatch','WithdrawPhonePermission','CancelRequest'))) THEN
        RAISE EXCEPTION 'Incomplete request effect' USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS (SELECT FROM foundation.audit_logs a WHERE a.id=receipt.audit_id AND a.operation=NEW.command
        AND a.correlation_id=NEW.correlation_id AND a.details->>'requestId'=NEW.request_id::text)
        OR NOT EXISTS (SELECT FROM foundation.outbox_events o WHERE o.id=receipt.outbox_id AND o.event_id=NEW.id
        AND o.event_type=CASE NEW.command WHEN 'CreateCallback' THEN 'REQUEST_CALLBACK_INTENT'
            WHEN 'ReadyForDispatch' THEN 'REQUEST_READY_FOR_ASSIGNMENT' ELSE 'REQUEST_EFFECT_RECORDED' END
        AND o.payload->>'requestId'=NEW.request_id::text AND o.payload->>'version'=NEW.resulting_version::text) THEN
        RAISE EXCEPTION 'Incomplete request audit or outbox' USING ERRCODE='23514';
    END IF;
    IF NEW.command IN ('CreateCallback','CreateRepair') THEN
        IF NEW.resulting_version<>1 OR state.current_contact_revision_id IS NULL OR state.current_preference_revision_id IS NULL
            OR NOT EXISTS (SELECT FROM foundation.request_intake_provenance p WHERE p.request_id=NEW.request_id) OR
            (NEW.command='CreateCallback' AND (state.type<>'CALLBACK' OR state.status<>'CALLBACK_REQUIRED'
                OR state.current_address_revision_id IS NOT NULL OR state.current_appliance_revision_id IS NOT NULL)) OR
            (NEW.command='CreateRepair' AND (state.type<>'REPAIR' OR state.current_address_revision_id IS NULL
                OR state.current_appliance_revision_id IS NULL)) THEN
            RAISE EXCEPTION 'Incomplete request intake' USING ERRCODE='23514';
        END IF;
        IF NEW.actor_type='F' THEN
            IF NOT EXISTS (SELECT FROM foundation.request_session_submits s WHERE s.event_id=NEW.id
                AND s.request_id=NEW.request_id AND s.session_id=NEW.actor_session_id)
                OR EXISTS (SELECT FROM foundation.request_staff_evidence e WHERE e.request_id=NEW.request_id AND e.purpose='MANUAL_INTAKE') THEN
                RAISE EXCEPTION 'Incomplete form submit' USING ERRCODE='23514';
            END IF;
        ELSE
            IF NOT EXISTS (SELECT FROM foundation.request_staff_evidence e WHERE e.request_id=NEW.request_id
                AND e.purpose='MANUAL_INTAKE' AND e.staff_id=NEW.actor_staff_id)
                OR EXISTS (SELECT FROM foundation.request_session_submits s WHERE s.request_id=NEW.request_id) THEN
                RAISE EXCEPTION 'Incomplete manual submit' USING ERRCODE='23514';
            END IF;
        END IF;
    END IF;
    -- The exact own-form owner for CUSTOMER follow-up commands. A customer command
    -- is only a genuine follow-up when the request was created by THIS SAME form
    -- session and the submit edge still names that session's own intake event. This
    -- keeps a mis-attributed actor from remaining valid next to the stricter
    -- `ChooseCallback` proof: it is the same failure, answered for every F follow-up.
    -- `ChooseCallback` is deliberately NOT covered here — it owns its own, stricter
    -- message below.
    IF NEW.actor_type='F' AND NEW.command IN ('WithdrawPhonePermission','CancelRequest') THEN
        IF NOT EXISTS (SELECT FROM foundation.request_session_submits s
            JOIN foundation.request_events e ON (e.id,e.request_id)=(s.event_id,s.request_id)
            WHERE s.request_id=NEW.request_id AND s.session_id=NEW.actor_session_id
              AND e.actor_type='F' AND e.actor_session_id=NEW.actor_session_id
              AND e.command=s.submit_command) THEN
            RAISE EXCEPTION 'Incomplete form submit for a follow-up command' USING ERRCODE='23514';
        END IF;
    END IF;
    --
    -- Every command is classified EXHAUSTIVELY; there is no permissive fall-through.
    -- The count is always exact (1 or 0), never "at most".
    --  b) the permission must belong to the CURRENT request version. The row-level
    --     `BEFORE INSERT` guard above refuses a permission attached to a superseded
    --     event, and `event_id` is UNIQUE, so a valid issued/withdrawn event cannot
    --     receive a second row later either.
    -- Ordering: the permission row is written AFTER its receipt/event (the row-level
    -- guard looks the command up), and this deferred trigger then re-checks the
    -- pair at COMMIT time, so both directions are covered without allowing a
    -- permission to be created first.
    SELECT pr.contact_mode INTO preference_mode FROM foundation.request_preference_revisions pr
      WHERE pr.id=state.current_preference_revision_id;
    IF NEW.command='CreateCallback' THEN
        -- A callback intake is ALWAYS a phone-mode intake: the storage preference
        -- must say PHONE, no channel choice may exist, and exactly one GIVEN must
        -- be present. The stored mode is never used as a pretext to skip the fact.
        IF preference_mode IS DISTINCT FROM 'PHONE'
            OR EXISTS (SELECT FROM foundation.request_channel_choices c WHERE c.request_id=NEW.request_id)
            OR (SELECT count(*) FROM foundation.phone_permission_events p
                WHERE p.event_id=NEW.id AND p.request_id=NEW.request_id AND p.action='GIVEN'
                  AND p.contact_revision_id=state.current_contact_revision_id)<>1 THEN
            RAISE EXCEPTION 'Incomplete phone permission for a callback request' USING ERRCODE='23514';
        END IF;
    ELSIF NEW.command='CreateRepair' THEN
        -- Exactly two valid repair forms, and everything else is refused:
        --   (1) PHONE  : STAFF actor, resulting status NEW, stored preference PHONE
        --                → exactly one GIVEN for the current contact, NO channel choice
        --                (the row-level guard additionally requires the ORIGINAL
        --                revision-1 preference to be PHONE, so a later preference
        --                change can never retro-authorise an old intake);
        --   (2) NO-CALL: a channel-waiting status with stored preference MESSENGER
        --                → exactly one channel choice whose provider MATCHES the
        --                status, and ZERO phone rows.
        -- A partial `NEW` + MESSENGER/null aggregate matches neither form and is
        -- refused, which is the gap this exhaustive disjunction closes.
        IF NEW.actor_type='STAFF' AND state.status='NEW' AND preference_mode='PHONE' THEN
            IF EXISTS (SELECT FROM foundation.request_channel_choices c WHERE c.request_id=NEW.request_id)
                OR (SELECT count(*) FROM foundation.phone_permission_events p
                    WHERE p.event_id=NEW.id AND p.request_id=NEW.request_id AND p.action='GIVEN'
                      AND p.contact_revision_id=state.current_contact_revision_id)<>1 THEN
                RAISE EXCEPTION 'Incomplete phone permission for a call repair' USING ERRCODE='23514';
            END IF;
        ELSIF state.status IN ('WAITING_TELEGRAM_LINK','WAITING_CHANNEL_LINK') AND preference_mode='MESSENGER' THEN
            IF EXISTS (SELECT FROM foundation.phone_permission_events p WHERE p.event_id=NEW.id)
                OR (SELECT count(*) FROM foundation.request_channel_choices c
                    WHERE c.request_id=NEW.request_id
                      AND ((state.status='WAITING_TELEGRAM_LINK' AND c.provider='TG')
                        OR (state.status='WAITING_CHANNEL_LINK' AND c.provider IN ('VK','MAX'))))<>1 THEN
                RAISE EXCEPTION 'Incomplete channel intake for a repair' USING ERRCODE='23514';
            END IF;
        ELSE
            RAISE EXCEPTION 'Repair intake matches no reviewed form' USING ERRCODE='23514';
        END IF;
    ELSIF NEW.command='ChooseCallback' THEN
        -- The customer's channel→call switch, proven as a REAL new revision of THIS
        -- command version, and as the effect of the SAME form session that created
        -- the request as a waiting channel intake. Nothing here can be satisfied by
        -- a late append or by an artificially assembled state:
        --  * REPAIR that has just landed in CALLBACK_REQUIRED;
        --  * exactly ONE new PHONE preference at the command's own version, and it
        --    must be the request's current pointer;
        --  * the previous effective preference (the newest one below that version)
        --    must be MESSENGER, and the ORIGINAL revision-1 preference must also be
        --    MESSENGER — the switch only ever moves channel -> phone, and it must
        --    have started as one;
        --  * the new PHONE preference must PRESERVE the previous effective choice:
        --    identical `urgency` and identical `preferred_windows`, compared through
        --    one LATERAL lookup of that previous effective row (the production
        --    `clonePhonePreference` copies exactly these and only flips the mode);
        --  * the request's current contact pointer must be the LATEST effective
        --    contact revision (< resulting_version) — the same row the runtime reads
        --    with `ORDER BY revision DESC LIMIT 1`: the switch keeps the contact and
        --    cannot point at any older or brand-new revision;
        --  * the IMMEDIATE predecessor event must have been accepted into a
        --    channel-waiting status, so the switch follows the real waiting intake;
        --  * the ORIGINAL own form intake must be this session's own `CreateRepair`
        --    (version 1, F actor, same session, matching submit edge) whose receipt
        --    accepted a waiting status with channel provenance that matches it;
        --  * exactly one GIVEN for the current contact, issued by this command.
        IF state.type<>'REPAIR' OR state.status<>'CALLBACK_REQUIRED'
            OR (SELECT count(*) FROM foundation.request_preference_revisions pr
                WHERE pr.request_id=NEW.request_id AND pr.revision=NEW.resulting_version
                  AND pr.contact_mode='PHONE' AND pr.id=state.current_preference_revision_id)<>1
            OR (SELECT pr.contact_mode FROM foundation.request_preference_revisions pr
                WHERE pr.request_id=NEW.request_id AND pr.revision<NEW.resulting_version
                ORDER BY pr.revision DESC LIMIT 1) IS DISTINCT FROM 'MESSENGER'
            OR (SELECT pr.contact_mode FROM foundation.request_preference_revisions pr
                WHERE pr.request_id=NEW.request_id AND pr.revision=1) IS DISTINCT FROM 'MESSENGER'
            OR NOT EXISTS (SELECT FROM foundation.request_preference_revisions cur
                JOIN LATERAL (SELECT prev.urgency,prev.preferred_windows
                    FROM foundation.request_preference_revisions prev
                    WHERE prev.request_id=cur.request_id AND prev.revision<cur.revision
                    ORDER BY prev.revision DESC LIMIT 1) prev ON true
                WHERE cur.request_id=NEW.request_id AND cur.revision=NEW.resulting_version
                  AND cur.contact_mode='PHONE'
                  AND cur.urgency IS NOT DISTINCT FROM prev.urgency
                  AND cur.preferred_windows IS NOT DISTINCT FROM prev.preferred_windows)
            OR state.current_contact_revision_id IS DISTINCT FROM (SELECT cr.id
                FROM foundation.request_contact_revisions cr
                WHERE cr.request_id=NEW.request_id AND cr.revision<NEW.resulting_version
                ORDER BY cr.revision DESC LIMIT 1)
            OR NOT EXISTS (SELECT FROM foundation.request_events e
                JOIN foundation.request_command_receipts r ON (r.event_id,r.request_id)=(e.id,e.request_id)
                WHERE e.request_id=NEW.request_id AND e.resulting_version=NEW.resulting_version-1
                  AND r.resulting_status IN ('WAITING_TELEGRAM_LINK','WAITING_CHANNEL_LINK'))
            OR NOT EXISTS (SELECT FROM foundation.request_events o
                JOIN foundation.request_command_receipts r ON (r.event_id,r.request_id)=(o.id,o.request_id)
                WHERE o.request_id=NEW.request_id AND o.resulting_version=1 AND o.command='CreateRepair'
                  AND o.actor_type='F' AND o.actor_session_id=NEW.actor_session_id
                  AND EXISTS (SELECT FROM foundation.request_session_submits s
                      WHERE s.request_id=NEW.request_id AND s.session_id=NEW.actor_session_id
                        AND s.event_id=o.id AND s.submit_command='CreateRepair')
                  AND ((r.resulting_status='WAITING_TELEGRAM_LINK'
                        AND EXISTS (SELECT FROM foundation.request_channel_choices c
                            WHERE c.request_id=NEW.request_id AND c.provider='TG'))
                    OR (r.resulting_status='WAITING_CHANNEL_LINK'
                        AND EXISTS (SELECT FROM foundation.request_channel_choices c
                            WHERE c.request_id=NEW.request_id AND c.provider IN ('VK','MAX')))))
            OR (SELECT count(*) FROM foundation.phone_permission_events p
                WHERE p.event_id=NEW.id AND p.request_id=NEW.request_id AND p.action='GIVEN'
                  AND p.contact_revision_id=state.current_contact_revision_id)<>1 THEN
            RAISE EXCEPTION 'Incomplete callback switch' USING ERRCODE='23514';
        END IF;
    ELSIF NEW.command='WithdrawPhonePermission' THEN
        IF (SELECT count(*) FROM foundation.phone_permission_events p
            WHERE p.event_id=NEW.id AND p.request_id=NEW.request_id AND p.action='REVOKED')<>1 THEN
            RAISE EXCEPTION 'Incomplete phone withdrawal' USING ERRCODE='23514';
        END IF;
    ELSIF EXISTS (SELECT FROM foundation.phone_permission_events p WHERE p.event_id=NEW.id) THEN
        RAISE EXCEPTION 'Phone permission on a no-call or unrelated command' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER request_effect_complete AFTER INSERT ON foundation.request_events
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.request_effect_guard();

CREATE FUNCTION foundation.request_aggregate_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF NOT EXISTS (SELECT FROM foundation.request_events e WHERE e.request_id=NEW.id
        AND e.resulting_version=NEW.row_version) THEN
        RAISE EXCEPTION 'Request version requires a durable command' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER request_aggregate_complete AFTER INSERT OR UPDATE ON foundation.requests
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.request_aggregate_guard();

DO $$
DECLARE rel text;
BEGIN
    FOREACH rel IN ARRAY ARRAY['request_staff_evidence','request_command_receipts','request_session_submits',
        'phone_permission_events','request_files','request_appliance_brands','request_channel_choices','request_address_review_attempts',
        'request_coverage_assessments','request_intake_provenance'] LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.%I FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change()',rel||'_immutable',rel);
        EXECUTE format('REVOKE ALL ON foundation.%I FROM PUBLIC,fixlevelup_runtime',rel);
    END LOOP;
END $$;
REVOKE ALL ON FUNCTION foundation.request_role_grant_guard(),foundation.request_effect_guard(),foundation.request_aggregate_guard(),
  foundation.request_phone_permission_guard()
    FROM PUBLIC,fixlevelup_runtime;

GRANT UPDATE(type,current_assessment_id), SELECT(current_assessment_id) ON foundation.requests TO fixlevelup_runtime;
GRANT SELECT(wrapped_dek,nonce,ciphertext,auth_tag,aad_context) ON foundation.request_payload_cells TO fixlevelup_runtime;
GRANT SELECT(contact_mode),INSERT(contact_mode) ON foundation.request_preference_revisions TO fixlevelup_runtime;
GRANT SELECT(appliance_revision_id,request_id,brand_id,brand_kind,brand_version_id),
    INSERT(appliance_revision_id,request_id,brand_id,brand_version_id) ON foundation.request_appliance_brands TO fixlevelup_runtime;
GRANT SELECT(id,request_id,staff_id,purpose,procedure_revision,valid_until,declared_at),
    INSERT(id,request_id,staff_id,purpose,procedure_revision,valid_until) ON foundation.request_staff_evidence TO fixlevelup_runtime;
GRANT SELECT(event_id,request_id,version,correlation_id,command,key_id,fingerprint,resulting_status,audit_id,outbox_id),
    INSERT(event_id,request_id,version,correlation_id,command,key_id,fingerprint,resulting_status,audit_id,outbox_id)
    ON foundation.request_command_receipts TO fixlevelup_runtime;
GRANT SELECT(session_id,request_id,customer_id,intake_city_id,intake_city_version_id,consent_id,document_id,document_version_id,purpose,action,event_id,submit_command),
    INSERT(session_id,request_id,customer_id,intake_city_id,intake_city_version_id,consent_id,document_id,document_version_id,event_id,submit_command)
    ON foundation.request_session_submits TO fixlevelup_runtime;
GRANT SELECT(id,request_id,contact_revision_id,purpose,action,supersedes_given_id,event_id,staff_evidence_id,occurred_at),
    INSERT(id,request_id,contact_revision_id,action,supersedes_given_id,event_id,staff_evidence_id)
    ON foundation.phone_permission_events TO fixlevelup_runtime;
GRANT SELECT(request_id,owner_session_id,intent_id,file_id), INSERT(request_id,owner_session_id,intent_id,file_id)
    ON foundation.request_files TO fixlevelup_runtime;
GRANT SELECT(request_id,provider,catalog_version_id,option_version_id,readiness_basis_id,checked_at),
    INSERT(request_id,provider,catalog_version_id,option_version_id,readiness_basis_id)
    ON foundation.request_channel_choices TO fixlevelup_runtime;
GRANT INSERT(evidence_id,staff_id,request_id,address_revision_id,purpose,correlation_id)
    ON foundation.request_address_review_attempts TO fixlevelup_runtime;
GRANT SELECT(id,request_id,address_revision_id,city_id,city_version_id,area_id,area_version_id,basis_digest,outcome,reason,staff_id,attempt_correlation_id,event_id,created_at),
    INSERT(id,request_id,address_revision_id,city_id,city_version_id,area_id,area_version_id,basis_digest,outcome,reason,staff_id,attempt_correlation_id,event_id)
    ON foundation.request_coverage_assessments TO fixlevelup_runtime;
GRANT SELECT(request_id,source_entry_id,source_version_id,source_type,callback_entry_id,callback_version_id,callback_type),
    INSERT(request_id,source_entry_id,source_version_id,callback_entry_id,callback_version_id)
    ON foundation.request_intake_provenance TO fixlevelup_runtime;

COMMIT;
