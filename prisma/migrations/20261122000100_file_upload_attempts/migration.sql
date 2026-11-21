BEGIN;

-- P03-04B2: durable attempts and a private quarantine binding. No change to
-- migration 014 or its grants. The extra unique index is only an FK target: the
-- attempt is tied to the exact immutable session-owned reservation and its charge.
CREATE UNIQUE INDEX file_upload_intents_attempt_basis_key
    ON foundation.file_upload_intents(id,owner_request_session_id,declared_bytes);

CREATE TABLE foundation.file_upload_attempts (
    id uuid PRIMARY KEY,
    intent_id uuid NOT NULL,
    owner_request_session_id uuid NOT NULL,
    idempotency_key uuid NOT NULL,
    generation integer NOT NULL,
    upload_lease_id uuid NOT NULL,
    upload_lease_expires_at timestamptz(6) NOT NULL,
    object_key varchar(84) NOT NULL,
    storage_endpoint varchar(32) NOT NULL,
    storage_bucket varchar(63) NOT NULL,
    storage_region varchar(63) NOT NULL,
    charged_bytes bigint NOT NULL,
    state varchar(16) NOT NULL DEFAULT 'REGISTERED',
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    dispatched_at timestamptz(6),
    verified_bytes bigint,
    verified_sha256 varchar(64),
    probe_generation integer NOT NULL DEFAULT 0,
    probe_held_slots integer NOT NULL DEFAULT 0,
    probe_lease_id uuid,
    probe_lease_expires_at timestamptz(6),
    observed_at timestamptz(6),
    observation varchar(24),
    observed_bytes bigint,
    observed_sha256 varchar(64),
    CONSTRAINT file_upload_attempts_intent_basis_fkey
        FOREIGN KEY (intent_id,owner_request_session_id,charged_bytes)
        REFERENCES foundation.file_upload_intents(id,owner_request_session_id,declared_bytes)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT file_upload_attempts_owner_idempotency_key UNIQUE (owner_request_session_id,idempotency_key),
    CONSTRAINT file_upload_attempts_intent_generation_key UNIQUE (intent_id,generation),
    CONSTRAINT file_upload_attempts_object_key_key UNIQUE (object_key),
    CONSTRAINT file_upload_attempts_verified_tuple_key UNIQUE (intent_id,id,verified_bytes,verified_sha256),
    CONSTRAINT file_upload_attempts_generation_check CHECK (generation > 0),
    CONSTRAINT file_upload_attempts_charge_check CHECK (charged_bytes BETWEEN 1 AND 9007199254740991),
    CONSTRAINT file_upload_attempts_upload_lease_check CHECK (
        isfinite(upload_lease_expires_at) AND upload_lease_expires_at > created_at),
    CONSTRAINT file_upload_attempts_key_check CHECK (
        left(object_key,48) = 'quarantine/' || id::text || '/'
        AND substring(object_key FROM 49) COLLATE "C" ~
            '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CONSTRAINT file_upload_attempts_endpoint_check CHECK (
        CASE WHEN storage_endpoint COLLATE "C" ~ '^http://127[.]0[.]0[.]1:[1-9][0-9]{0,4}$'
             THEN substring(storage_endpoint FROM 18)::integer BETWEEN 1 AND 65535
             ELSE false END),
    CONSTRAINT file_upload_attempts_storage_names_check CHECK (
        storage_bucket COLLATE "C" ~ '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'
        AND storage_region COLLATE "C" ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    CONSTRAINT file_upload_attempts_state_check CHECK (
        state IN ('REGISTERED','IN_FLIGHT','FAILED_NOBYTES','UNKNOWN','VERIFIED')),
    CONSTRAINT file_upload_attempts_dispatch_check CHECK (
        (state IN ('IN_FLIGHT','UNKNOWN','VERIFIED')) = (dispatched_at IS NOT NULL)
        AND (dispatched_at IS NULL OR dispatched_at < upload_lease_expires_at)),
    CONSTRAINT file_upload_attempts_verified_check CHECK (
        (state <> 'VERIFIED' AND verified_bytes IS NULL AND verified_sha256 IS NULL)
        OR (state = 'VERIFIED' AND verified_bytes IS NOT NULL AND verified_bytes = charged_bytes
            AND verified_sha256 IS NOT NULL AND verified_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$')),
    CONSTRAINT file_upload_attempts_probe_check CHECK (
        probe_generation >= 0 AND probe_held_slots BETWEEN 0 AND probe_generation
        AND (probe_lease_id IS NULL) = (probe_lease_expires_at IS NULL)
        AND (probe_lease_id IS NULL OR (probe_held_slots >= 1 AND isfinite(probe_lease_expires_at)))
        AND (state = 'UNKNOWN' OR (probe_generation = 0 AND probe_held_slots = 0
                                   AND probe_lease_id IS NULL AND observed_at IS NULL))),
    CONSTRAINT file_upload_attempts_observation_check CHECK (
        (observed_at IS NULL AND observation IS NULL AND observed_bytes IS NULL AND observed_sha256 IS NULL)
        OR (observed_at IS NOT NULL AND probe_generation > 0 AND observation IS NOT NULL
            AND ((observation = 'PRESENT' AND observed_bytes IS NOT NULL
                  AND observed_bytes BETWEEN 0 AND charged_bytes
                  AND observed_sha256 IS NOT NULL AND observed_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$')
                OR (observation IN ('NOT_OBSERVED','INDETERMINATE')
                    AND observed_bytes IS NULL AND observed_sha256 IS NULL))))
);

-- An expired marker holds its active registration until it is retired explicitly.
CREATE UNIQUE INDEX file_upload_attempts_active_intent_key
    ON foundation.file_upload_attempts(intent_id) WHERE state IN ('REGISTERED','IN_FLIGHT');
CREATE INDEX file_upload_attempts_owner_budget_idx
    ON foundation.file_upload_attempts(owner_request_session_id,state);
CREATE INDEX file_upload_attempts_retirement_idx
    ON foundation.file_upload_attempts(upload_lease_expires_at,id) WHERE state IN ('REGISTERED','IN_FLIGHT');
CREATE INDEX file_upload_attempts_probe_idx
    ON foundation.file_upload_attempts(storage_endpoint,storage_bucket,storage_region,observed_at NULLS FIRST,id)
    WHERE state = 'UNKNOWN';

CREATE TABLE foundation.file_quarantine_objects (
    id uuid PRIMARY KEY,
    intent_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    actual_bytes bigint NOT NULL,
    sha256 varchar(64) NOT NULL,
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT file_quarantine_objects_intent_id_key UNIQUE (intent_id),
    CONSTRAINT file_quarantine_objects_attempt_id_key UNIQUE (attempt_id),
    CONSTRAINT file_quarantine_objects_verified_attempt_fkey
        FOREIGN KEY (intent_id,attempt_id,actual_bytes,sha256)
        REFERENCES foundation.file_upload_attempts(intent_id,id,verified_bytes,verified_sha256)
        ON DELETE RESTRICT ON UPDATE RESTRICT
);

-- This guard only fences transitions on the locked attempt. It never locks or
-- reads session/document/intent backwards from an attempt UPDATE. The coordinator
-- owns the forward lock order, raw proof/current basis, budgets, matching grant
-- CAS (including holder vs. expiry retirement), storage facts and audit/outbox.
-- No trigger can prove the caller held the lease token or the transport settled.
CREATE FUNCTION foundation.file_upload_attempts_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    decision_at timestamptz;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'REGISTERED' OR NEW.dispatched_at IS NOT NULL
            OR NEW.verified_bytes IS NOT NULL OR NEW.verified_sha256 IS NOT NULL
            OR NEW.probe_generation IS DISTINCT FROM 0 OR NEW.probe_held_slots IS DISTINCT FROM 0
            OR NEW.probe_lease_id IS NOT NULL OR NEW.probe_lease_expires_at IS NOT NULL
            OR NEW.observed_at IS NOT NULL OR NEW.observation IS NOT NULL
            OR NEW.observed_bytes IS NOT NULL OR NEW.observed_sha256 IS NOT NULL THEN
            RAISE EXCEPTION 'Upload attempt must start REGISTERED without evidence or probes'
                USING ERRCODE='23514', CONSTRAINT='file_upload_attempts_initial_state';
        END IF;
        NEW.created_at := clock_timestamp();
        RETURN NEW;
    END IF;

    IF (NEW.id,NEW.intent_id,NEW.owner_request_session_id,NEW.idempotency_key,
        NEW.generation,NEW.upload_lease_id,NEW.upload_lease_expires_at,NEW.object_key,
        NEW.storage_endpoint,NEW.storage_bucket,NEW.storage_region,NEW.charged_bytes,
        NEW.created_at,NEW.dispatched_at,NEW.observed_at)
        IS DISTINCT FROM
       (OLD.id,OLD.intent_id,OLD.owner_request_session_id,OLD.idempotency_key,
        OLD.generation,OLD.upload_lease_id,OLD.upload_lease_expires_at,OLD.object_key,
        OLD.storage_endpoint,OLD.storage_bucket,OLD.storage_region,OLD.charged_bytes,
        OLD.created_at,OLD.dispatched_at,OLD.observed_at) THEN
        RAISE EXCEPTION 'Upload attempt identity, lease, target, charge and stamps are not writable'
            USING ERRCODE='23514', CONSTRAINT='file_upload_attempts_immutable';
    END IF;

    -- UPDATE's row lock is already held; do not use a statement/transaction start time.
    decision_at := clock_timestamp();
    IF OLD.state = 'UNKNOWN' AND NEW.state = 'UNKNOWN' THEN
        IF NEW.probe_lease_id IS NOT NULL THEN
            -- A claim needs a new generation and an additional slot, even when
            -- replacing an expired claim. No observation changes on claim.
            IF NEW.probe_lease_id IS NOT DISTINCT FROM OLD.probe_lease_id
                OR (OLD.probe_lease_id IS NOT NULL AND OLD.probe_lease_expires_at > decision_at)
                OR NEW.probe_lease_expires_at IS NULL OR NEW.probe_lease_expires_at <= decision_at
                OR NEW.probe_generation::bigint IS DISTINCT FROM OLD.probe_generation::bigint + 1
                OR NEW.probe_held_slots::bigint IS DISTINCT FROM OLD.probe_held_slots::bigint + 1
                OR (NEW.observation,NEW.observed_bytes,NEW.observed_sha256)
                    IS DISTINCT FROM (OLD.observation,OLD.observed_bytes,OLD.observed_sha256) THEN
                RAISE EXCEPTION 'Invalid upload attempt probe claim'
                    USING ERRCODE='23514', CONSTRAINT='file_upload_attempts_probe_claim';
            END IF;
        ELSE
            -- A finish must clear the current live lease, retain the generation,
            -- and record one observation. Only its own slot can possibly release;
            -- the coordinator must still prove the matched grant and local settle.
            IF OLD.probe_lease_id IS NULL OR OLD.probe_lease_expires_at <= decision_at
                OR NEW.probe_lease_expires_at IS NOT NULL
                OR NEW.probe_generation IS DISTINCT FROM OLD.probe_generation
                OR NEW.probe_held_slots IS NULL
                OR NEW.probe_held_slots NOT IN (OLD.probe_held_slots, OLD.probe_held_slots - 1)
                OR NEW.observation IS NULL THEN
                RAISE EXCEPTION 'Invalid upload attempt probe finish'
                    USING ERRCODE='23514', CONSTRAINT='file_upload_attempts_probe_finish';
            END IF;
            NEW.observed_at := decision_at;
        END IF;
        RETURN NEW;
    END IF;

    -- In particular, entering UNKNOWN may not create or finish a probe.
    IF (NEW.probe_generation,NEW.probe_held_slots,NEW.probe_lease_id,
        NEW.probe_lease_expires_at,NEW.observation,NEW.observed_bytes,NEW.observed_sha256)
        IS DISTINCT FROM
       (OLD.probe_generation,OLD.probe_held_slots,OLD.probe_lease_id,
        OLD.probe_lease_expires_at,OLD.observation,OLD.observed_bytes,OLD.observed_sha256) THEN
        RAISE EXCEPTION 'Upload attempt probes require an existing UNKNOWN state'
            USING ERRCODE='23514', CONSTRAINT='file_upload_attempts_probe_transition';
    END IF;

    IF OLD.state = 'REGISTERED' AND NEW.state = 'FAILED_NOBYTES' THEN
        RETURN NEW;
    ELSIF OLD.state = 'IN_FLIGHT' AND NEW.state = 'UNKNOWN' THEN
        RETURN NEW;
    ELSIF (OLD.state = 'REGISTERED' AND NEW.state = 'IN_FLIGHT')
        OR (OLD.state = 'IN_FLIGHT' AND NEW.state = 'VERIFIED') THEN
        IF OLD.upload_lease_expires_at <= decision_at THEN
            RAISE EXCEPTION 'Upload attempt requires a live lease'
                USING ERRCODE='23514', CONSTRAINT='file_upload_attempts_live_lease';
        END IF;
        IF NEW.state = 'IN_FLIGHT' THEN
            NEW.dispatched_at := decision_at;
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'Invalid upload attempt state transition'
        USING ERRCODE='23514', CONSTRAINT='file_upload_attempts_state_transition';
END $$;
CREATE TRIGGER file_upload_attempts_guard BEFORE INSERT OR UPDATE ON foundation.file_upload_attempts
    FOR EACH ROW EXECUTE FUNCTION foundation.file_upload_attempts_guard();

CREATE FUNCTION foundation.file_quarantine_objects_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'Quarantine binding is immutable'
            USING ERRCODE='23514', CONSTRAINT='file_quarantine_objects_immutable';
    END IF;
    NEW.created_at := clock_timestamp();
    RETURN NEW;
END $$;
CREATE TRIGGER file_quarantine_objects_guard BEFORE INSERT OR UPDATE ON foundation.file_quarantine_objects
    FOR EACH ROW EXECUTE FUNCTION foundation.file_quarantine_objects_guard();

CREATE FUNCTION foundation.file_upload_history_reject_removal() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'Upload history cannot be removed'
        USING ERRCODE='23514', CONSTRAINT='file_upload_history_immutable';
END $$;
CREATE TRIGGER file_upload_attempts_reject_removal BEFORE DELETE OR TRUNCATE ON foundation.file_upload_attempts
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.file_upload_history_reject_removal();
CREATE TRIGGER file_quarantine_objects_reject_removal BEFORE DELETE OR TRUNCATE ON foundation.file_quarantine_objects
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.file_upload_history_reject_removal();

REVOKE ALL ON FUNCTION foundation.file_upload_attempts_guard(), foundation.file_quarantine_objects_guard(),
    foundation.file_upload_history_reject_removal() FROM PUBLIC, fixlevelup_runtime;
REVOKE ALL ON foundation.file_upload_attempts, foundation.file_quarantine_objects FROM PUBLIC, fixlevelup_runtime;

GRANT SELECT(id,intent_id,owner_request_session_id,idempotency_key,generation,upload_lease_id,
        upload_lease_expires_at,object_key,storage_endpoint,storage_bucket,storage_region,charged_bytes,
        state,created_at,dispatched_at,verified_bytes,verified_sha256,probe_generation,probe_held_slots,
        probe_lease_id,probe_lease_expires_at,observed_at,observation,observed_bytes,observed_sha256),
    INSERT(id,intent_id,owner_request_session_id,idempotency_key,generation,upload_lease_id,
        upload_lease_expires_at,object_key,storage_endpoint,storage_bucket,storage_region,charged_bytes),
    UPDATE(state,verified_bytes,verified_sha256,probe_generation,probe_held_slots,
        probe_lease_id,probe_lease_expires_at,observation,observed_bytes,observed_sha256)
    ON foundation.file_upload_attempts TO fixlevelup_runtime;
GRANT SELECT(id,intent_id,attempt_id,actual_bytes,sha256,created_at),
    INSERT(id,intent_id,attempt_id,actual_bytes,sha256)
    ON foundation.file_quarantine_objects TO fixlevelup_runtime;

COMMIT;
