BEGIN;

-- P03-04C: additive only. These unique indexes are FK targets for existing
-- immutable rows; no historical row is changed and no runtime epoch is seeded.
CREATE UNIQUE INDEX file_upload_intents_file_owner_key
    ON foundation.file_upload_intents(id,owner_request_session_id);
CREATE UNIQUE INDEX file_quarantine_objects_intent_object_key
    ON foundation.file_quarantine_objects(intent_id,id);
CREATE UNIQUE INDEX file_quarantine_objects_raw_tuple_key
    ON foundation.file_quarantine_objects(intent_id,id,actual_bytes,sha256);

CREATE TABLE foundation.file_runtime_epochs (
    singleton boolean PRIMARY KEY,
    namespace_id uuid NOT NULL,
    epoch bigint NOT NULL,
    mode varchar(16) NOT NULL,
    opened_at timestamptz(6),
    CONSTRAINT file_runtime_epochs_singleton_check CHECK (singleton),
    CONSTRAINT file_runtime_epochs_namespace_check CHECK (
        namespace_id::text COLLATE "C" ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CONSTRAINT file_runtime_epochs_epoch_check CHECK (epoch > 0),
    CONSTRAINT file_runtime_epochs_mode_check CHECK (mode IN ('ACTIVE','RESTORE_CLOSED','FENCED')),
    CONSTRAINT file_runtime_epochs_opened_check CHECK (
        (mode = 'RESTORE_CLOSED' AND opened_at IS NULL)
        OR (mode IN ('ACTIVE','FENCED') AND opened_at IS NOT NULL AND isfinite(opened_at)))
);

CREATE TABLE foundation.file_privacy_controls (
    intent_id uuid PRIMARY KEY,
    row_version bigint NOT NULL DEFAULT 1,
    access_epoch bigint NOT NULL DEFAULT 1,
    processing_generation integer NOT NULL DEFAULT 0,
    processing_lease_id uuid,
    processing_expires_at timestamptz(6),
    read_generation integer NOT NULL DEFAULT 0,
    read_lease_id uuid,
    read_expires_at timestamptz(6),
    CONSTRAINT file_privacy_controls_intent_id_fkey FOREIGN KEY (intent_id)
        REFERENCES foundation.file_upload_intents(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT file_privacy_controls_versions_check CHECK (row_version > 0 AND access_epoch > 0),
    CONSTRAINT file_privacy_controls_processing_check CHECK (
        processing_generation >= 0
        AND (processing_lease_id IS NULL) = (processing_expires_at IS NULL)
        AND (processing_lease_id IS NULL OR (processing_generation > 0 AND isfinite(processing_expires_at)))),
    CONSTRAINT file_privacy_controls_read_check CHECK (
        read_generation >= 0
        AND (read_lease_id IS NULL) = (read_expires_at IS NULL)
        AND (read_lease_id IS NULL OR (read_generation > 0 AND isfinite(read_expires_at))))
);

CREATE TABLE foundation.file_sanitized_attempts (
    id uuid PRIMARY KEY,
    intent_id uuid NOT NULL,
    owner_request_session_id uuid NOT NULL,
    quarantine_id uuid NOT NULL,
    generation integer NOT NULL,
    lease_id uuid NOT NULL,
    lease_expires_at timestamptz(6) NOT NULL,
    object_key varchar(83) NOT NULL,
    storage_endpoint varchar(32) NOT NULL,
    storage_bucket varchar(63) NOT NULL,
    storage_region varchar(63) NOT NULL,
    mime varchar(100) NOT NULL,
    charged_bytes bigint NOT NULL,
    expected_sha256 varchar(64) NOT NULL,
    state varchar(16) NOT NULL DEFAULT 'REGISTERED',
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    dispatched_at timestamptz(6),
    verified_bytes bigint,
    verified_sha256 varchar(64),
    CONSTRAINT file_sanitized_attempts_intent_owner_fkey FOREIGN KEY (intent_id,owner_request_session_id)
        REFERENCES foundation.file_upload_intents(id,owner_request_session_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT file_sanitized_attempts_quarantine_fkey FOREIGN KEY (intent_id,quarantine_id)
        REFERENCES foundation.file_quarantine_objects(intent_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT file_sanitized_attempts_intent_generation_key UNIQUE (intent_id,generation),
    CONSTRAINT file_sanitized_attempts_object_key_key UNIQUE (object_key),
    CONSTRAINT file_sanitized_attempts_verified_tuple_key UNIQUE (intent_id,quarantine_id,id,mime,verified_bytes,verified_sha256),
    CONSTRAINT file_sanitized_attempts_generation_check CHECK (generation > 0),
    CONSTRAINT file_sanitized_attempts_charge_check CHECK (charged_bytes BETWEEN 1 AND 9007199254740991),
    CONSTRAINT file_sanitized_attempts_digest_check CHECK (expected_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT file_sanitized_attempts_lease_check CHECK (
        isfinite(created_at) AND isfinite(lease_expires_at) AND lease_expires_at > created_at),
    CONSTRAINT file_sanitized_attempts_key_check CHECK (
        left(object_key,47) COLLATE "C" = 'sanitized/' || id::text || '/'
        AND substring(object_key FROM 48) COLLATE "C" ~
            '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CONSTRAINT file_sanitized_attempts_endpoint_check CHECK (
        CASE WHEN storage_endpoint COLLATE "C" ~ '^http://127[.]0[.]0[.]1:[1-9][0-9]{0,4}$'
             THEN substring(storage_endpoint FROM 18)::integer BETWEEN 1 AND 65535
             ELSE false END),
    CONSTRAINT file_sanitized_attempts_storage_names_check CHECK (
        storage_bucket COLLATE "C" ~ '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'
        AND storage_region COLLATE "C" ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    CONSTRAINT file_sanitized_attempts_mime_check CHECK (mime IN ('image/jpeg','image/png','image/webp')),
    CONSTRAINT file_sanitized_attempts_state_check CHECK (
        state IN ('REGISTERED','IN_FLIGHT','FAILED_NOBYTES','UNKNOWN','VERIFIED')),
    CONSTRAINT file_sanitized_attempts_dispatch_check CHECK (
        (state IN ('IN_FLIGHT','UNKNOWN','VERIFIED')) = (dispatched_at IS NOT NULL)
        AND (dispatched_at IS NULL OR (dispatched_at >= created_at AND dispatched_at < lease_expires_at))),
    CONSTRAINT file_sanitized_attempts_verified_check CHECK (
        (state <> 'VERIFIED' AND verified_bytes IS NULL AND verified_sha256 IS NULL)
        OR (state = 'VERIFIED' AND verified_bytes IS NOT NULL AND verified_bytes = charged_bytes
            AND verified_sha256 IS NOT NULL AND verified_sha256 COLLATE "C" = expected_sha256))
);

-- Expiry is a denial fence, never a release. Retire the active row explicitly.
CREATE UNIQUE INDEX file_sanitized_attempts_active_intent_key
    ON foundation.file_sanitized_attempts(intent_id) WHERE state IN ('REGISTERED','IN_FLIGHT');
CREATE INDEX file_sanitized_attempts_owner_budget_idx
    ON foundation.file_sanitized_attempts(owner_request_session_id,state);

CREATE TABLE foundation.file_publications (
    id uuid PRIMARY KEY,
    intent_id uuid NOT NULL,
    quarantine_id uuid NOT NULL,
    raw_bytes bigint NOT NULL,
    raw_sha256 varchar(64) NOT NULL,
    sanitized_attempt_id uuid NOT NULL,
    mime varchar(100) NOT NULL,
    served_bytes bigint NOT NULL,
    served_sha256 varchar(64) NOT NULL,
    processing_policy_id uuid NOT NULL,
    processing_policy_sha256 varchar(64) NOT NULL,
    engine_version varchar(32) NOT NULL,
    engine_image_sha256 varchar(64) NOT NULL,
    defs_sha256 varchar(64) NOT NULL,
    defs_built_at timestamptz(6) NOT NULL,
    published_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT file_publications_intent_id_key UNIQUE (intent_id),
    CONSTRAINT file_publications_quarantine_id_key UNIQUE (quarantine_id),
    CONSTRAINT file_publications_sanitized_attempt_id_key UNIQUE (sanitized_attempt_id),
    CONSTRAINT file_publications_raw_tuple_fkey FOREIGN KEY (intent_id,quarantine_id,raw_bytes,raw_sha256)
        REFERENCES foundation.file_quarantine_objects(intent_id,id,actual_bytes,sha256)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT file_publications_served_tuple_fkey FOREIGN KEY (intent_id,quarantine_id,sanitized_attempt_id,mime,served_bytes,served_sha256)
        REFERENCES foundation.file_sanitized_attempts(intent_id,quarantine_id,id,mime,verified_bytes,verified_sha256)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT file_publications_mime_check CHECK (mime IN ('image/jpeg','image/png','image/webp')),
    CONSTRAINT file_publications_bytes_check CHECK (
        raw_bytes BETWEEN 1 AND 9007199254740991 AND served_bytes BETWEEN 1 AND 9007199254740991),
    CONSTRAINT file_publications_digest_check CHECK (
        raw_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$' AND served_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$'
        AND processing_policy_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$'
        AND engine_image_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$' AND defs_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT file_publications_engine_version_check CHECK (
        engine_version COLLATE "C" ~ '^[0-9]+[.][0-9]+[.][0-9]+$'),
    CONSTRAINT file_publications_timestamps_check CHECK (
        isfinite(defs_built_at) AND isfinite(published_at) AND defs_built_at <= published_at)
);

-- PostgreSQL requires UPDATE on at least one column for SELECT ... FOR SHARE.
-- The runtime's lock-only UPDATE(singleton) grant allows that row lock, but no
-- UPDATE (even to the same value) or INSERT through this trigger. The existing
-- isolated migrator credential is the trusted ops credential, never the API one.
-- External restore/handoff evidence is verified by the trusted operator, not SQL.
CREATE FUNCTION foundation.file_runtime_epochs_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF current_user <> 'fixlevelup_migrator' THEN
        RAISE EXCEPTION 'File epoch mutation is operator-only' USING ERRCODE='42501';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.mode = 'ACTIVE' THEN
            NEW.opened_at := clock_timestamp();
        ELSIF NEW.mode = 'RESTORE_CLOSED' THEN
            NEW.opened_at := NULL;
        ELSE
            RAISE EXCEPTION 'Invalid initial file runtime mode'
                USING ERRCODE='23514', CONSTRAINT='file_runtime_epochs_initial_mode';
        END IF;
        RETURN NEW;
    END IF;

    IF (NEW.singleton,NEW.namespace_id,NEW.opened_at)
        IS DISTINCT FROM (OLD.singleton,OLD.namespace_id,OLD.opened_at) THEN
        RAISE EXCEPTION 'File runtime identity and opening stamp cannot be supplied by an update'
            USING ERRCODE='23514', CONSTRAINT='file_runtime_epochs_immutable';
    END IF;

    IF OLD.mode = 'ACTIVE' AND NEW.mode = 'FENCED' AND NEW.epoch = OLD.epoch THEN
        RETURN NEW;
    ELSIF OLD.mode = 'RESTORE_CLOSED' AND NEW.mode = 'ACTIVE' AND NEW.epoch > OLD.epoch THEN
        NEW.opened_at := clock_timestamp();
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'Invalid file runtime mode or epoch transition'
        USING ERRCODE='23514', CONSTRAINT='file_runtime_epochs_transition';
END $$;
CREATE TRIGGER file_runtime_epochs_guard BEFORE INSERT OR UPDATE ON foundation.file_runtime_epochs
    FOR EACH ROW EXECUTE FUNCTION foundation.file_runtime_epochs_guard();

-- Keep this control transition guard independent of the later deletion protocol.
-- The caller already holds the forward locks; the trigger takes no new row locks.
-- Release requires an exact old generation/id CAS and proven settlement in the
-- trusted application. SQL enforces shape only; it cannot prove a holder settled.
CREATE FUNCTION foundation.file_privacy_controls_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    processing_changed boolean;
    read_changed boolean;
    claim_is_new boolean;
    decision_at timestamptz;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF (NEW.row_version,NEW.access_epoch,NEW.processing_generation,NEW.read_generation)
            IS DISTINCT FROM (1::bigint,1::bigint,0,0)
            OR NEW.processing_lease_id IS NOT NULL OR NEW.processing_expires_at IS NOT NULL
            OR NEW.read_lease_id IS NOT NULL OR NEW.read_expires_at IS NOT NULL THEN
            RAISE EXCEPTION 'A file control must start unclaimed at version one'
                USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_initial_state';
        END IF;
        RETURN NEW;
    END IF;

    IF (NEW.intent_id,NEW.row_version,NEW.access_epoch) IS DISTINCT FROM (OLD.intent_id,OLD.row_version,OLD.access_epoch) THEN
        RAISE EXCEPTION 'File control identity and versions cannot be supplied by an update'
            USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_immutable';
    END IF;

    processing_changed := (NEW.processing_generation,NEW.processing_lease_id,NEW.processing_expires_at)
        IS DISTINCT FROM (OLD.processing_generation,OLD.processing_lease_id,OLD.processing_expires_at);
    read_changed := (NEW.read_generation,NEW.read_lease_id,NEW.read_expires_at)
        IS DISTINCT FROM (OLD.read_generation,OLD.read_lease_id,OLD.read_expires_at);
    IF processing_changed = read_changed THEN
        RAISE EXCEPTION 'Exactly one file claim must change'
            USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_claim_transition';
    END IF;

    decision_at := clock_timestamp();
    IF processing_changed THEN
        claim_is_new := NEW.processing_lease_id IS NOT NULL;
        IF claim_is_new THEN
            IF OLD.processing_lease_id IS NOT NULL
                OR NEW.processing_generation::bigint IS DISTINCT FROM OLD.processing_generation::bigint + 1
                OR NEW.processing_expires_at IS NULL OR NOT isfinite(NEW.processing_expires_at)
                OR NEW.processing_expires_at <= decision_at THEN
                RAISE EXCEPTION 'Invalid processing claim acquisition'
                    USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_processing_claim';
            END IF;
        ELSIF OLD.processing_lease_id IS NULL OR NEW.processing_expires_at IS NOT NULL
            OR NEW.processing_generation IS DISTINCT FROM OLD.processing_generation THEN
            RAISE EXCEPTION 'Invalid processing claim release'
                USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_processing_release';
        END IF;
    ELSE
        claim_is_new := NEW.read_lease_id IS NOT NULL;
        IF claim_is_new THEN
            IF OLD.read_lease_id IS NOT NULL
                OR NEW.read_generation::bigint IS DISTINCT FROM OLD.read_generation::bigint + 1
                OR NEW.read_expires_at IS NULL OR NOT isfinite(NEW.read_expires_at)
                OR NEW.read_expires_at <= decision_at THEN
                RAISE EXCEPTION 'Invalid read claim acquisition'
                    USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_read_claim';
            END IF;
        ELSIF OLD.read_lease_id IS NULL OR NEW.read_expires_at IS NOT NULL
            OR NEW.read_generation IS DISTINCT FROM OLD.read_generation THEN
            RAISE EXCEPTION 'Invalid read claim release'
                USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_read_release';
        END IF;
    END IF;

    IF claim_is_new AND NOT EXISTS (
        SELECT 1 FROM foundation.file_runtime_epochs WHERE singleton AND mode = 'ACTIVE'
    ) THEN
        RAISE EXCEPTION 'New file claims require an active runtime'
            USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_active_runtime';
    END IF;
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END $$;
CREATE TRIGGER file_privacy_controls_guard BEFORE INSERT OR UPDATE ON foundation.file_privacy_controls
    FOR EACH ROW EXECUTE FUNCTION foundation.file_privacy_controls_guard();

CREATE FUNCTION foundation.file_sanitized_attempts_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    decision_at timestamptz;
    claim_expires_at timestamptz;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'REGISTERED' OR NEW.dispatched_at IS NOT NULL
            OR NEW.verified_bytes IS NOT NULL OR NEW.verified_sha256 IS NOT NULL THEN
            RAISE EXCEPTION 'Sanitized attempt must start REGISTERED without evidence'
                USING ERRCODE='23514', CONSTRAINT='file_sanitized_attempts_initial_state';
        END IF;
    ELSE
        IF (NEW.id,NEW.intent_id,NEW.owner_request_session_id,NEW.quarantine_id,NEW.generation,NEW.lease_id,
            NEW.lease_expires_at,NEW.object_key,NEW.storage_endpoint,NEW.storage_bucket,NEW.storage_region,
            NEW.mime,NEW.charged_bytes,NEW.expected_sha256,NEW.created_at,NEW.dispatched_at)
            IS DISTINCT FROM
           (OLD.id,OLD.intent_id,OLD.owner_request_session_id,OLD.quarantine_id,OLD.generation,OLD.lease_id,
            OLD.lease_expires_at,OLD.object_key,OLD.storage_endpoint,OLD.storage_bucket,OLD.storage_region,
            OLD.mime,OLD.charged_bytes,OLD.expected_sha256,OLD.created_at,OLD.dispatched_at) THEN
            RAISE EXCEPTION 'Sanitized attempt identity, lease, target, charge and stamps are immutable'
                USING ERRCODE='23514', CONSTRAINT='file_sanitized_attempts_immutable';
        END IF;

        -- Conservative technical retirement must still be possible after a fence
        -- or lease expiry. These transitions cannot create verification evidence.
        IF (OLD.state = 'REGISTERED' AND NEW.state = 'FAILED_NOBYTES')
            OR (OLD.state = 'IN_FLIGHT' AND NEW.state = 'UNKNOWN') THEN
            RETURN NEW;
        END IF;
        IF NOT ((OLD.state = 'REGISTERED' AND NEW.state = 'IN_FLIGHT')
                OR (OLD.state = 'IN_FLIGHT' AND NEW.state = 'VERIFIED')) OR NEW.state IS NULL THEN
            RAISE EXCEPTION 'Invalid sanitized attempt state transition'
                USING ERRCODE='23514', CONSTRAINT='file_sanitized_attempts_state_transition';
        END IF;
    END IF;

    -- Read only: the application takes runtime, intent and control locks before
    -- locking attempts. No backwards FOR UPDATE/SHARE from this trigger.
    SELECT c.processing_expires_at INTO claim_expires_at
    FROM foundation.file_privacy_controls AS c
    CROSS JOIN foundation.file_runtime_epochs AS r
    WHERE r.singleton AND r.mode = 'ACTIVE' AND c.intent_id = NEW.intent_id
      AND c.processing_generation = NEW.generation AND c.processing_lease_id = NEW.lease_id
      AND c.processing_expires_at = NEW.lease_expires_at;
    decision_at := clock_timestamp();
    IF NOT FOUND OR claim_expires_at <= decision_at THEN
        RAISE EXCEPTION 'Sanitized attempt requires an active runtime and its exact live processing claim'
            USING ERRCODE='23514', CONSTRAINT='file_sanitized_attempts_live_claim';
    END IF;

    IF TG_OP = 'INSERT' THEN
        NEW.created_at := decision_at;
    ELSIF NEW.state = 'IN_FLIGHT' THEN
        NEW.dispatched_at := decision_at;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER file_sanitized_attempts_guard BEFORE INSERT OR UPDATE ON foundation.file_sanitized_attempts
    FOR EACH ROW EXECUTE FUNCTION foundation.file_sanitized_attempts_guard();

-- SQL can enforce exact tuples, a live claim and immutable evidence shape. It
-- cannot attest to engine identity/freshness, bytes, F consent or transport facts.
-- Those proofs are required by the application in the same transaction as insert.
CREATE FUNCTION foundation.file_publications_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    decision_at timestamptz;
    claim_expires_at timestamptz;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'File publication is immutable'
            USING ERRCODE='23514', CONSTRAINT='file_publications_immutable';
    END IF;

    SELECT c.processing_expires_at INTO claim_expires_at
    FROM foundation.file_quarantine_objects AS q
    JOIN foundation.file_sanitized_attempts AS a ON (a.intent_id,a.quarantine_id) = (q.intent_id,q.id)
    JOIN foundation.file_privacy_controls AS c ON c.intent_id = a.intent_id
    CROSS JOIN foundation.file_runtime_epochs AS r
    WHERE r.singleton AND r.mode = 'ACTIVE'
      AND (q.intent_id,q.id,q.actual_bytes,q.sha256) = (NEW.intent_id,NEW.quarantine_id,NEW.raw_bytes,NEW.raw_sha256)
      AND (a.id,a.mime,a.verified_bytes,a.verified_sha256) = (NEW.sanitized_attempt_id,NEW.mime,NEW.served_bytes,NEW.served_sha256)
      AND a.state = 'VERIFIED' AND c.processing_generation = a.generation AND c.processing_lease_id = a.lease_id
      AND c.processing_expires_at = a.lease_expires_at;
    decision_at := clock_timestamp();
    IF NOT FOUND OR claim_expires_at <= decision_at THEN
        RAISE EXCEPTION 'File publication requires exact verified tuples and a live processing claim in the active runtime'
            USING ERRCODE='23514', CONSTRAINT='file_publications_live_verified_claim';
    END IF;
    NEW.published_at := decision_at;
    RETURN NEW;
END $$;
CREATE TRIGGER file_publications_guard BEFORE INSERT OR UPDATE ON foundation.file_publications
    FOR EACH ROW EXECUTE FUNCTION foundation.file_publications_guard();

CREATE FUNCTION foundation.file_processing_history_reject_removal() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'File processing and access history cannot be removed'
        USING ERRCODE='23514', CONSTRAINT='file_processing_history_immutable';
END $$;
CREATE TRIGGER file_runtime_epochs_reject_removal BEFORE DELETE OR TRUNCATE ON foundation.file_runtime_epochs
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.file_processing_history_reject_removal();
CREATE TRIGGER file_privacy_controls_reject_removal BEFORE DELETE OR TRUNCATE ON foundation.file_privacy_controls
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.file_processing_history_reject_removal();
CREATE TRIGGER file_sanitized_attempts_reject_removal BEFORE DELETE OR TRUNCATE ON foundation.file_sanitized_attempts
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.file_processing_history_reject_removal();
CREATE TRIGGER file_publications_reject_removal BEFORE DELETE OR TRUNCATE ON foundation.file_publications
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.file_processing_history_reject_removal();

REVOKE ALL ON FUNCTION foundation.file_runtime_epochs_guard(), foundation.file_privacy_controls_guard(),
    foundation.file_sanitized_attempts_guard(), foundation.file_publications_guard(),
    foundation.file_processing_history_reject_removal() FROM PUBLIC, fixlevelup_runtime;
REVOKE ALL ON foundation.file_runtime_epochs, foundation.file_privacy_controls, foundation.file_sanitized_attempts,
    foundation.file_publications FROM PUBLIC, fixlevelup_runtime;

GRANT SELECT(singleton,namespace_id,epoch,mode,opened_at), UPDATE(singleton)
    ON foundation.file_runtime_epochs TO fixlevelup_runtime;
GRANT SELECT(intent_id,row_version,access_epoch,processing_generation,processing_lease_id,processing_expires_at,
        read_generation,read_lease_id,read_expires_at),
    INSERT(intent_id), UPDATE(processing_generation,processing_lease_id,processing_expires_at,
        read_generation,read_lease_id,read_expires_at)
    ON foundation.file_privacy_controls TO fixlevelup_runtime;
GRANT SELECT(id,intent_id,owner_request_session_id,quarantine_id,generation,lease_id,lease_expires_at,object_key,
        storage_endpoint,storage_bucket,storage_region,mime,charged_bytes,expected_sha256,state,created_at,
        dispatched_at,verified_bytes,verified_sha256),
    INSERT(id,intent_id,owner_request_session_id,quarantine_id,generation,lease_id,lease_expires_at,object_key,
        storage_endpoint,storage_bucket,storage_region,mime,charged_bytes,expected_sha256),
    UPDATE(state,verified_bytes,verified_sha256)
    ON foundation.file_sanitized_attempts TO fixlevelup_runtime;
GRANT SELECT(id,intent_id,quarantine_id,raw_bytes,raw_sha256,sanitized_attempt_id,mime,served_bytes,served_sha256,
        processing_policy_id,processing_policy_sha256,engine_version,engine_image_sha256,defs_sha256,defs_built_at,
        published_at),
    INSERT(id,intent_id,quarantine_id,raw_bytes,raw_sha256,sanitized_attempt_id,mime,served_bytes,served_sha256,
        processing_policy_id,processing_policy_sha256,engine_version,engine_image_sha256,defs_sha256,defs_built_at)
    ON foundation.file_publications TO fixlevelup_runtime;

COMMIT;
