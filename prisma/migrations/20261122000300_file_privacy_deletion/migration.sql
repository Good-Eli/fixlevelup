BEGIN;

-- P03-04D: additive control state and immutable exact-key deletion graph.
-- Defaults describe the pre-existing open/unheld shape, not retention policy.
ALTER TABLE foundation.file_privacy_controls
    ADD COLUMN hold_active boolean NOT NULL DEFAULT false,
    ADD COLUMN hold_actor_id uuid,
    ADD COLUMN hold_reason varchar(24),
    ADD COLUMN hold_at timestamptz(6),
    ADD COLUMN delete_state varchar(24) NOT NULL DEFAULT 'OPEN',
    ADD COLUMN delete_event_id uuid,
    ADD COLUMN delete_at timestamptz(6),
    ADD COLUMN delete_policy_id uuid,
    ADD COLUMN delete_writer_epoch bigint,
    ADD COLUMN ledger_seq bigint,
    ADD COLUMN ledger_hash varchar(64),
    ADD COLUMN delete_graph_sha256 varchar(64),
    ADD CONSTRAINT file_privacy_controls_delete_event_id_key UNIQUE (delete_event_id),
    ADD CONSTRAINT file_privacy_controls_hold_check CHECK (
        (NOT hold_active AND hold_actor_id IS NULL AND hold_reason IS NULL AND hold_at IS NULL)
        OR (hold_active AND delete_state = 'OPEN' AND hold_actor_id IS NOT NULL
            AND hold_reason IS NOT NULL AND hold_reason IN ('LEGAL_HOLD','OPERATOR_REVIEW')
            AND hold_at IS NOT NULL AND isfinite(hold_at))),
    ADD CONSTRAINT file_privacy_controls_delete_state_check CHECK (
        delete_state IN ('OPEN','PENDING_LEDGER','LEDGERED','VERIFY_PENDING','CONFIRMED_ABSENT')),
    ADD CONSTRAINT file_privacy_controls_delete_shape_check CHECK (
        (delete_state = 'OPEN' AND access_epoch = 1 AND delete_event_id IS NULL AND delete_at IS NULL
            AND delete_policy_id IS NULL AND delete_writer_epoch IS NULL AND delete_graph_sha256 IS NULL)
        OR (delete_state <> 'OPEN' AND access_epoch > 1 AND delete_event_id IS NOT NULL
            AND delete_at IS NOT NULL AND isfinite(delete_at) AND delete_policy_id IS NOT NULL
            AND delete_writer_epoch IS NOT NULL AND delete_writer_epoch > 0
            AND delete_graph_sha256 IS NOT NULL AND delete_graph_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$')),
    ADD CONSTRAINT file_privacy_controls_ledger_check CHECK (
        (delete_state IN ('OPEN','PENDING_LEDGER') AND ledger_seq IS NULL AND ledger_hash IS NULL)
        OR (delete_state IN ('LEDGERED','VERIFY_PENDING','CONFIRMED_ABSENT') AND ledger_seq IS NOT NULL
            AND ledger_seq > 0 AND ledger_hash IS NOT NULL AND ledger_hash COLLATE "C" ~ '^[0-9a-f]{64}$'));
CREATE UNIQUE INDEX file_privacy_controls_intent_event_key
    ON foundation.file_privacy_controls(intent_id,delete_event_id);

CREATE TABLE foundation.file_delete_items (
    event_id uuid NOT NULL,
    attempt_kind varchar(9) NOT NULL,
    attempt_id uuid NOT NULL,
    intent_id uuid NOT NULL,
    target_endpoint varchar(32) NOT NULL,
    target_bucket varchar(63) NOT NULL,
    target_region varchar(63) NOT NULL,
    object_key varchar(84) NOT NULL,
    write_proof varchar(20) NOT NULL,
    state varchar(24) NOT NULL DEFAULT 'AUTHORIZED',
    claim_generation integer NOT NULL DEFAULT 0,
    claim_id uuid,
    claim_expires_at timestamptz(6),
    verified_at timestamptz(6),
    PRIMARY KEY (event_id,attempt_kind,attempt_id),
    CONSTRAINT file_delete_items_event_target_key UNIQUE (event_id,target_endpoint,target_bucket,target_region,object_key),
    CONSTRAINT file_delete_items_control_fkey FOREIGN KEY (intent_id,event_id)
        REFERENCES foundation.file_privacy_controls(intent_id,delete_event_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT file_delete_items_kind_check CHECK (attempt_kind IN ('RAW','SANITIZED')),
    CONSTRAINT file_delete_items_proof_check CHECK (write_proof IN ('NEVER_DISPATCHED','VERIFIED_SETTLED','UNKNOWN')),
    CONSTRAINT file_delete_items_state_check CHECK (
        state IN ('AUTHORIZED','DELETE_ATTEMPTED','VERIFY_PENDING','CONFIRMED_ABSENT')),
    CONSTRAINT file_delete_items_claim_check CHECK (
        (state = 'AUTHORIZED' AND claim_generation = 0 AND claim_id IS NULL AND claim_expires_at IS NULL AND verified_at IS NULL)
        OR (state = 'DELETE_ATTEMPTED' AND claim_generation > 0 AND claim_id IS NOT NULL
            AND claim_expires_at IS NOT NULL AND isfinite(claim_expires_at) AND verified_at IS NULL)
        OR (state = 'VERIFY_PENDING' AND claim_generation > 0 AND claim_id IS NULL AND claim_expires_at IS NULL AND verified_at IS NULL)
        OR (state = 'CONFIRMED_ABSENT' AND claim_generation > 0 AND claim_id IS NULL AND claim_expires_at IS NULL
            AND verified_at IS NOT NULL AND isfinite(verified_at) AND write_proof IN ('NEVER_DISPATCHED','VERIFIED_SETTLED')))
);

-- The trusted applicative transaction already owns the forward locks. These
-- invoker guards query prior rows without locking backwards; they enforce state
-- shape, not raw F authorization, external ledger proof or object-store facts.
CREATE OR REPLACE FUNCTION foundation.file_privacy_controls_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    processing_changed boolean;
    read_changed boolean;
    hold_changed boolean;
    delete_changed boolean;
    claim_is_new boolean;
    runtime_mode text;
    runtime_epoch bigint;
    decision_at timestamptz;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF (NEW.row_version,NEW.access_epoch,NEW.processing_generation,NEW.read_generation,
            NEW.hold_active,NEW.delete_state) IS DISTINCT FROM (1::bigint,1::bigint,0,0,false,'OPEN')
            OR NEW.processing_lease_id IS NOT NULL OR NEW.processing_expires_at IS NOT NULL
            OR NEW.read_lease_id IS NOT NULL OR NEW.read_expires_at IS NOT NULL THEN
            RAISE EXCEPTION 'A file control must start open and unclaimed at version one'
                USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_initial_state';
        END IF;
        RETURN NEW;
    END IF;

    IF (NEW.intent_id,NEW.row_version,NEW.access_epoch,NEW.hold_at,NEW.delete_at,NEW.delete_writer_epoch)
        IS DISTINCT FROM (OLD.intent_id,OLD.row_version,OLD.access_epoch,OLD.hold_at,OLD.delete_at,OLD.delete_writer_epoch) THEN
        RAISE EXCEPTION 'File control identity, versions and stamps are not writable'
            USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_immutable';
    END IF;

    processing_changed := (NEW.processing_generation,NEW.processing_lease_id,NEW.processing_expires_at)
        IS DISTINCT FROM (OLD.processing_generation,OLD.processing_lease_id,OLD.processing_expires_at);
    read_changed := (NEW.read_generation,NEW.read_lease_id,NEW.read_expires_at)
        IS DISTINCT FROM (OLD.read_generation,OLD.read_lease_id,OLD.read_expires_at);
    hold_changed := (NEW.hold_active,NEW.hold_actor_id,NEW.hold_reason)
        IS DISTINCT FROM (OLD.hold_active,OLD.hold_actor_id,OLD.hold_reason);
    delete_changed := (NEW.delete_state,NEW.delete_event_id,NEW.delete_policy_id,NEW.delete_graph_sha256,NEW.ledger_seq,NEW.ledger_hash)
        IS DISTINCT FROM (OLD.delete_state,OLD.delete_event_id,OLD.delete_policy_id,OLD.delete_graph_sha256,OLD.ledger_seq,OLD.ledger_hash);
    IF processing_changed::integer + read_changed::integer + hold_changed::integer + delete_changed::integer <> 1 THEN
        RAISE EXCEPTION 'Exactly one file control transition is required'
            USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_claim_transition';
    END IF;

    SELECT mode,epoch INTO runtime_mode,runtime_epoch FROM foundation.file_runtime_epochs WHERE singleton;
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
    ELSIF read_changed THEN
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
    ELSIF hold_changed THEN
        IF runtime_mode IS DISTINCT FROM 'ACTIVE' OR OLD.delete_state <> 'OPEN'
            OR NEW.hold_active IS NULL OR NEW.hold_active = OLD.hold_active THEN
            RAISE EXCEPTION 'Hold changes require an open decision in the active runtime'
                USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_hold_transition';
        END IF;
        NEW.hold_at := CASE WHEN NEW.hold_active THEN decision_at ELSE NULL END;
    ELSE
        IF OLD.delete_state = 'OPEN' THEN
            IF runtime_mode IS DISTINCT FROM 'ACTIVE' OR OLD.hold_active
                OR NEW.delete_state IS DISTINCT FROM 'PENDING_LEDGER' THEN
                RAISE EXCEPTION 'Deletion can only freeze an unheld intent in the active runtime'
                    USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_delete_transition';
            END IF;
            NEW.delete_at := decision_at;
            -- Preserve the original ledger payload epoch across an executor handoff.
            NEW.delete_writer_epoch := runtime_epoch;
            NEW.access_epoch := OLD.access_epoch + 1;
        ELSE
            IF (NEW.delete_event_id,NEW.delete_policy_id,NEW.delete_graph_sha256)
                IS DISTINCT FROM (OLD.delete_event_id,OLD.delete_policy_id,OLD.delete_graph_sha256)
                OR (OLD.delete_state <> 'PENDING_LEDGER'
                    AND (NEW.ledger_seq,NEW.ledger_hash) IS DISTINCT FROM (OLD.ledger_seq,OLD.ledger_hash)) THEN
                RAISE EXCEPTION 'The frozen deletion decision and ledger evidence are immutable'
                    USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_delete_immutable';
            END IF;
            IF OLD.delete_state = 'PENDING_LEDGER' AND NEW.delete_state = 'LEDGERED'
                AND runtime_mode IN ('ACTIVE','FENCED') THEN
                -- Trusted source drain while FENCED records ledger evidence only.
                NULL;
            ELSIF OLD.delete_state = 'LEDGERED' AND NEW.delete_state = 'VERIFY_PENDING' AND runtime_mode = 'ACTIVE' THEN
                NULL;
            ELSIF OLD.delete_state = 'VERIFY_PENDING' AND NEW.delete_state = 'CONFIRMED_ABSENT' AND runtime_mode = 'ACTIVE'
                AND EXISTS (SELECT 1 FROM foundation.file_delete_items WHERE event_id = OLD.delete_event_id)
                AND NOT EXISTS (SELECT 1 FROM foundation.file_delete_items
                    WHERE event_id = OLD.delete_event_id AND state <> 'CONFIRMED_ABSENT') THEN
                NULL;
            ELSE
                RAISE EXCEPTION 'Invalid deletion phase transition'
                    USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_delete_transition';
            END IF;
        END IF;
    END IF;

    IF claim_is_new THEN
        IF runtime_mode IS DISTINCT FROM 'ACTIVE' THEN
            RAISE EXCEPTION 'New file claims require an active runtime'
                USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_active_runtime';
        END IF;
        IF OLD.delete_state <> 'OPEN' THEN
            RAISE EXCEPTION 'New file claims require an open intent'
                USING ERRCODE='23514', CONSTRAINT='file_privacy_controls_open_claim';
        END IF;
    END IF;
    -- Never force-release processing or read claims at a deletion decision. The
    -- exact local holder may still release its own claim after a freeze/fence.
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END $$;

CREATE FUNCTION foundation.file_delete_items_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    expected_proof text;
    decision_at timestamptz;
    parent_state text;
BEGIN
    SELECT c.delete_state INTO parent_state
    FROM foundation.file_privacy_controls AS c
    CROSS JOIN foundation.file_runtime_epochs AS r
    WHERE c.intent_id = NEW.intent_id AND c.delete_event_id = NEW.event_id AND r.singleton AND r.mode = 'ACTIVE';
    decision_at := clock_timestamp();
    IF TG_OP = 'INSERT' THEN
        IF parent_state IS DISTINCT FROM 'PENDING_LEDGER' OR NEW.state IS DISTINCT FROM 'AUTHORIZED'
            OR NEW.claim_generation IS DISTINCT FROM 0 OR NEW.claim_id IS NOT NULL OR NEW.claim_expires_at IS NOT NULL
            OR NEW.verified_at IS NOT NULL THEN
            RAISE EXCEPTION 'Delete items must start authorized in an active pending decision'
                USING ERRCODE='23514', CONSTRAINT='file_delete_items_initial_state';
        END IF;
        IF NEW.attempt_kind = 'RAW' THEN
            SELECT CASE WHEN a.dispatched_at IS NULL THEN 'NEVER_DISPATCHED'
                        WHEN a.state = 'VERIFIED' THEN 'VERIFIED_SETTLED' ELSE 'UNKNOWN' END
            INTO expected_proof FROM foundation.file_upload_attempts AS a
            WHERE (a.id,a.intent_id,a.storage_endpoint,a.storage_bucket,a.storage_region,a.object_key)
              = (NEW.attempt_id,NEW.intent_id,NEW.target_endpoint,NEW.target_bucket,NEW.target_region,NEW.object_key);
        ELSIF NEW.attempt_kind = 'SANITIZED' THEN
            SELECT CASE WHEN a.dispatched_at IS NULL THEN 'NEVER_DISPATCHED'
                        WHEN a.state = 'VERIFIED' THEN 'VERIFIED_SETTLED' ELSE 'UNKNOWN' END
            INTO expected_proof FROM foundation.file_sanitized_attempts AS a
            WHERE (a.id,a.intent_id,a.storage_endpoint,a.storage_bucket,a.storage_region,a.object_key)
              = (NEW.attempt_id,NEW.intent_id,NEW.target_endpoint,NEW.target_bucket,NEW.target_region,NEW.object_key);
        END IF;
        IF expected_proof IS NULL OR NEW.write_proof IS DISTINCT FROM expected_proof THEN
            RAISE EXCEPTION 'Delete item must match the exact registered attempt and its recorded write phase'
                USING ERRCODE='23514', CONSTRAINT='file_delete_items_exact_attempt';
        END IF;
        RETURN NEW;
    END IF;

    IF (NEW.event_id,NEW.attempt_kind,NEW.attempt_id,NEW.intent_id,NEW.target_endpoint,NEW.target_bucket,
        NEW.target_region,NEW.object_key,NEW.write_proof,NEW.verified_at)
        IS DISTINCT FROM
       (OLD.event_id,OLD.attempt_kind,OLD.attempt_id,OLD.intent_id,OLD.target_endpoint,OLD.target_bucket,
        OLD.target_region,OLD.object_key,OLD.write_proof,OLD.verified_at) THEN
        RAISE EXCEPTION 'Delete item identity, target and write proof are immutable'
            USING ERRCODE='23514', CONSTRAINT='file_delete_items_immutable';
    END IF;
    IF parent_state IS DISTINCT FROM 'VERIFY_PENDING' THEN
        RAISE EXCEPTION 'Delete item transitions require an active ledgered decision being verified'
            USING ERRCODE='23514', CONSTRAINT='file_delete_items_parent_phase';
    END IF;

    IF NEW.state = 'DELETE_ATTEMPTED' THEN
        IF NOT (OLD.state IN ('AUTHORIZED','VERIFY_PENDING')
                OR (OLD.state = 'DELETE_ATTEMPTED' AND OLD.claim_expires_at <= decision_at))
            OR NEW.claim_generation::bigint IS DISTINCT FROM OLD.claim_generation::bigint + 1
            OR NEW.claim_id IS NULL OR NEW.claim_id IS NOT DISTINCT FROM OLD.claim_id
            OR NEW.claim_expires_at IS NULL OR NOT isfinite(NEW.claim_expires_at) OR NEW.claim_expires_at <= decision_at THEN
            RAISE EXCEPTION 'Delete retry must acquire a new generation on the exact same item'
                USING ERRCODE='23514', CONSTRAINT='file_delete_items_claim_transition';
        END IF;
        RETURN NEW;
    ELSIF NEW.state IN ('VERIFY_PENDING','CONFIRMED_ABSENT') THEN
        IF OLD.state <> 'DELETE_ATTEMPTED' OR OLD.claim_expires_at <= decision_at
            OR NEW.claim_generation IS DISTINCT FROM OLD.claim_generation
            OR NEW.claim_id IS NOT NULL OR NEW.claim_expires_at IS NOT NULL
            OR (NEW.state = 'CONFIRMED_ABSENT' AND OLD.write_proof = 'UNKNOWN') THEN
            RAISE EXCEPTION 'Delete result requires the live claim and authoritative absence for confirmation'
                USING ERRCODE='23514', CONSTRAINT='file_delete_items_result_transition';
        END IF;
        IF NEW.state = 'CONFIRMED_ABSENT' THEN
            NEW.verified_at := decision_at;
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'Invalid delete item state transition'
        USING ERRCODE='23514', CONSTRAINT='file_delete_items_state_transition';
END $$;
CREATE TRIGGER file_delete_items_guard BEFORE INSERT OR UPDATE ON foundation.file_delete_items
    FOR EACH ROW EXECUTE FUNCTION foundation.file_delete_items_guard();
CREATE TRIGGER file_delete_items_reject_removal BEFORE DELETE OR TRUNCATE ON foundation.file_delete_items
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.file_processing_history_reject_removal();

-- Items and freeze commit as one unit. Each present item was checked against
-- the exact registered key; this deferred check also detects omitted attempts.
CREATE FUNCTION foundation.file_delete_graph_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM foundation.file_delete_items WHERE event_id = NEW.delete_event_id)
        OR EXISTS (SELECT 1 FROM foundation.file_upload_attempts AS a WHERE a.intent_id = NEW.intent_id
            AND NOT EXISTS (SELECT 1 FROM foundation.file_delete_items AS i
                WHERE i.event_id = NEW.delete_event_id AND i.intent_id = a.intent_id
                  AND i.attempt_kind = 'RAW' AND i.attempt_id = a.id))
        OR EXISTS (SELECT 1 FROM foundation.file_sanitized_attempts AS a WHERE a.intent_id = NEW.intent_id
            AND NOT EXISTS (SELECT 1 FROM foundation.file_delete_items AS i
                WHERE i.event_id = NEW.delete_event_id AND i.intent_id = a.intent_id
                  AND i.attempt_kind = 'SANITIZED' AND i.attempt_id = a.id)) THEN
        RAISE EXCEPTION 'A frozen deletion graph must include every registered attempt'
            USING ERRCODE='23514', CONSTRAINT='file_delete_graph_complete';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER file_delete_graph_complete AFTER UPDATE ON foundation.file_privacy_controls
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (OLD.delete_state = 'OPEN' AND NEW.delete_state = 'PENDING_LEDGER')
    EXECUTE FUNCTION foundation.file_delete_graph_guard();

-- Defense in depth: deny an already visible freeze/closed runtime without
-- taking backwards row locks. Serialization against a concurrent freeze is
-- owned by the ordered application locks. Technical retire/probes stay legal.
CREATE FUNCTION foundation.file_write_freeze_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM foundation.file_runtime_epochs WHERE singleton AND mode <> 'ACTIVE')
        OR EXISTS (SELECT 1 FROM foundation.file_privacy_controls WHERE intent_id = NEW.intent_id AND delete_state <> 'OPEN') THEN
        RAISE EXCEPTION 'An active runtime and an unfrozen intent are required for file writes'
            USING ERRCODE='23514', CONSTRAINT='file_write_unfrozen_intent';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER file_00_write_freeze_insert BEFORE INSERT ON foundation.file_upload_attempts
    FOR EACH ROW EXECUTE FUNCTION foundation.file_write_freeze_guard();
CREATE TRIGGER file_00_write_freeze_advance BEFORE UPDATE ON foundation.file_upload_attempts
    FOR EACH ROW WHEN (NEW.state IN ('IN_FLIGHT','VERIFIED') AND NEW.state IS DISTINCT FROM OLD.state)
    EXECUTE FUNCTION foundation.file_write_freeze_guard();
CREATE TRIGGER file_00_write_freeze_insert BEFORE INSERT ON foundation.file_sanitized_attempts
    FOR EACH ROW EXECUTE FUNCTION foundation.file_write_freeze_guard();
CREATE TRIGGER file_00_write_freeze_advance BEFORE UPDATE ON foundation.file_sanitized_attempts
    FOR EACH ROW WHEN (NEW.state IN ('IN_FLIGHT','VERIFIED') AND NEW.state IS DISTINCT FROM OLD.state)
    EXECUTE FUNCTION foundation.file_write_freeze_guard();
CREATE TRIGGER file_00_write_freeze_insert BEFORE INSERT ON foundation.file_quarantine_objects
    FOR EACH ROW EXECUTE FUNCTION foundation.file_write_freeze_guard();
CREATE TRIGGER file_00_write_freeze_insert BEFORE INSERT ON foundation.file_publications
    FOR EACH ROW EXECUTE FUNCTION foundation.file_write_freeze_guard();

REVOKE ALL ON FUNCTION foundation.file_privacy_controls_guard(), foundation.file_delete_items_guard(),
    foundation.file_delete_graph_guard(), foundation.file_write_freeze_guard() FROM PUBLIC, fixlevelup_runtime;
REVOKE ALL ON foundation.file_delete_items FROM PUBLIC, fixlevelup_runtime;

GRANT SELECT(hold_active,hold_actor_id,hold_reason,hold_at,delete_state,delete_event_id,delete_at,
        delete_policy_id,delete_writer_epoch,ledger_seq,ledger_hash,delete_graph_sha256),
    UPDATE(hold_active,hold_actor_id,hold_reason,delete_state,delete_event_id,delete_policy_id,ledger_seq,ledger_hash,delete_graph_sha256)
    ON foundation.file_privacy_controls TO fixlevelup_runtime;
GRANT SELECT(event_id,attempt_kind,attempt_id,intent_id,target_endpoint,target_bucket,target_region,object_key,
        write_proof,state,claim_generation,claim_id,claim_expires_at,verified_at),
    INSERT(event_id,attempt_kind,attempt_id,intent_id,target_endpoint,target_bucket,target_region,object_key,write_proof),
    UPDATE(state,claim_generation,claim_id,claim_expires_at)
    ON foundation.file_delete_items TO fixlevelup_runtime;

COMMIT;
