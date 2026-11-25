BEGIN;
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET LOCAL search_path = pg_catalog;

-- P05-02 (023, schema profile S2): form session foundation.
-- Additive only over 022: opaque browser groups, form session group
-- memberships and bounded throttle counters. The P03 request_sessions (013)
-- stay the only anchor and the only F-token proof: no second anchor id or
-- secret is introduced here, so reserveFileUpload (014) and consent_records
-- (013) keep working with the same F token. No customers, requests, submit,
-- phone or receipts. No routes, no runtime seeding, no secrets and no PII in
-- this migration.
--
-- As in 022: tables are created without an explicit OWNER (the migrator role
-- owns the objects), everything is REVOKEd from PUBLIC and fixlevelup_runtime
-- first, then the runtime role receives exact column grants only.

-- ---------------------------------------------------------------------------
-- 1. Opaque browser groups (not an F-session and not an identity).
-- ---------------------------------------------------------------------------
-- A server-side hash of an opaque browser-grouping secret plus a trusted expiry
-- window. No PII and no revoke: expiry is decided by comparing the stored
-- timestamps with the database clock, so the row always stays. UPDATE and
-- DELETE are refused by the guard below (ERRCODE 23514, as the history tables
-- in 013/022); the §2 trigger pins every P03 anchor expiry to the group
-- expiry.
CREATE TABLE foundation.form_browser_groups (
    id uuid PRIMARY KEY,
    secret_hash varchar(64) NOT NULL,
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz(6) NOT NULL,
    CONSTRAINT form_browser_groups_secret_hash_check CHECK (secret_hash COLLATE "C" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT form_browser_groups_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT form_browser_groups_secret_hash_key UNIQUE (secret_hash)
);
-- Groups are immutable history: no UPDATE, no DELETE, ever; and even on a
-- direct INSERT by the owner created_at is pinned to the database clock.
CREATE FUNCTION foundation.form_browser_groups_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.created_at := clock_timestamp();
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'Browser groups are immutable' USING ERRCODE='23514';
END $$;
CREATE TRIGGER form_browser_groups_guard BEFORE INSERT OR UPDATE OR DELETE ON foundation.form_browser_groups
    FOR EACH ROW EXECUTE FUNCTION foundation.form_browser_groups_guard();

-- ---------------------------------------------------------------------------
-- 2. Form session group memberships (S2: request_sessions stays the anchor).
-- ---------------------------------------------------------------------------
-- The thin 1:1 mapping of a request_sessions.id issued through the F protocol
-- to its browser group: session_id is both the primary key and the P03 anchor
-- reference. There is no second anchor id, no second secret hash and no own
-- expiry, revoke or intake pair here — the anchor secret, expiry and provenance
-- keep living in request_sessions (013), so the same F token keeps authorizing
-- reserveFileUpload (014) and consent_records (013). Rows are immutable
-- history: no UPDATE and no DELETE, ever.
CREATE TABLE foundation.form_session_group_memberships (
    session_id uuid PRIMARY KEY,
    group_id uuid NOT NULL,
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT form_session_group_memberships_group_id_fkey FOREIGN KEY (group_id)
        REFERENCES foundation.form_browser_groups(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT form_session_group_memberships_session_id_fkey FOREIGN KEY (session_id)
        REFERENCES foundation.request_sessions(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);
-- Membership lookups per group (live counting is done by the application
-- against the database clock itself; now() cannot appear in an index
-- predicate).
CREATE INDEX form_session_group_memberships_group_id_idx ON foundation.form_session_group_memberships(group_id);

-- A membership must join an existing browser group to an existing, live
-- (unrevoked and unexpired) P03 request session, and the anchor expiry may
-- never exceed its browser group expiry. These cross-table rules cannot be
-- table CHECKs, so they are proven at insert time; UPDATE and DELETE are
-- refused outright. No row lock is needed: the group expiry is itself
-- immutable (§1 guard). On INSERT created_at is pinned to the database clock
-- even on a direct INSERT by the owner.
CREATE FUNCTION foundation.form_session_group_memberships_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    group_expires_at timestamptz;
    session_expires_at timestamptz;
    session_revoked_at timestamptz;
BEGIN
    IF TG_OP = 'UPDATE' OR TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Form session group memberships are immutable' USING ERRCODE='23514';
    END IF;
    NEW.created_at := clock_timestamp();
    SELECT g.expires_at INTO group_expires_at
        FROM foundation.form_browser_groups g WHERE g.id = NEW.group_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Form session membership requires an existing browser group' USING ERRCODE='23514';
    END IF;
    SELECT s.expires_at, s.revoked_at INTO session_expires_at, session_revoked_at
        FROM foundation.request_sessions s WHERE s.id = NEW.session_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Form session membership requires an existing request session' USING ERRCODE='23514';
    END IF;
    IF session_revoked_at IS NOT NULL OR session_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'Form session membership requires a live request session' USING ERRCODE='23514';
    END IF;
    IF session_expires_at > group_expires_at THEN
        RAISE EXCEPTION 'Anchor expiry exceeds its browser group' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER form_session_group_memberships_guard BEFORE INSERT OR UPDATE OR DELETE ON foundation.form_session_group_memberships
    FOR EACH ROW EXECUTE FUNCTION foundation.form_session_group_memberships_guard();

-- ---------------------------------------------------------------------------
-- 3. Bounded throttle counters.
-- ---------------------------------------------------------------------------
-- Fixed-window counters for the form session issuance paths. A bucket is a
-- keyed counter, not a policy and not PII: kind/key_hash locate the subject,
-- window_started_at + window_seconds bound the window and hit_count counts the
-- accepted writes. A new window is a new row: DELETE is refused, the identity
-- columns are immutable and hit_count can only grow or stay (never be reset by
-- rewriting the row).
CREATE TABLE foundation.form_throttle_buckets (
    id uuid PRIMARY KEY,
    kind varchar(16) NOT NULL,
    key_hash varchar(64) NOT NULL,
    window_started_at timestamptz(6) NOT NULL,
    window_seconds integer NOT NULL,
    hit_count integer NOT NULL,
    CONSTRAINT form_throttle_buckets_kind_check CHECK (kind COLLATE "C" IN ('SOURCE','GLOBAL','ANCHOR')),
    CONSTRAINT form_throttle_buckets_key_hash_check CHECK (key_hash COLLATE "C" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT form_throttle_buckets_window_seconds_check CHECK (window_seconds BETWEEN 1 AND 86400),
    -- A window row is born with its first accepted hit: an empty bucket with 0
    -- hits is never inserted, so hit_count starts at 1 and never resets.
    CONSTRAINT form_throttle_buckets_hit_count_check CHECK (hit_count BETWEEN 1 AND 1000000),
    CONSTRAINT form_throttle_buckets_kind_key_hash_window_started_at_key
        UNIQUE (kind,key_hash,window_started_at)
);
CREATE FUNCTION foundation.form_throttle_buckets_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Throttle buckets are history; a new window is a new row' USING ERRCODE='23514';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.key_hash IS DISTINCT FROM OLD.key_hash
        OR NEW.window_started_at IS DISTINCT FROM OLD.window_started_at
        OR NEW.window_seconds IS DISTINCT FROM OLD.window_seconds THEN
        RAISE EXCEPTION 'Throttle bucket identity and window are immutable' USING ERRCODE='23514';
    END IF;
    IF NEW.hit_count < OLD.hit_count THEN
        RAISE EXCEPTION 'Throttle bucket hit count cannot decrease' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER form_throttle_buckets_guard BEFORE UPDATE OR DELETE ON foundation.form_throttle_buckets
    FOR EACH ROW EXECUTE FUNCTION foundation.form_throttle_buckets_guard();

-- ---------------------------------------------------------------------------
-- 4. TRUNCATE refusal (row triggers do not see TRUNCATE).
-- ---------------------------------------------------------------------------
CREATE FUNCTION foundation.form_history_reject_truncate() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'P05-02 form session history refuses TRUNCATE (%)', TG_TABLE_NAME USING ERRCODE='23514';
END $$;
CREATE TRIGGER form_browser_groups_reject_truncate BEFORE TRUNCATE ON foundation.form_browser_groups
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.form_history_reject_truncate();
CREATE TRIGGER form_session_group_memberships_reject_truncate BEFORE TRUNCATE ON foundation.form_session_group_memberships
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.form_history_reject_truncate();
CREATE TRIGGER form_throttle_buckets_reject_truncate BEFORE TRUNCATE ON foundation.form_throttle_buckets
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.form_history_reject_truncate();

-- ---------------------------------------------------------------------------
-- 5. Privileges: exact column grants, no PUBLIC access, no DELETE anywhere.
-- ---------------------------------------------------------------------------
REVOKE ALL ON foundation.form_browser_groups, foundation.form_session_group_memberships,
    foundation.form_throttle_buckets FROM PUBLIC, fixlevelup_runtime;
REVOKE ALL ON FUNCTION foundation.form_browser_groups_guard(),
    foundation.form_session_group_memberships_guard(),
    foundation.form_throttle_buckets_guard(), foundation.form_history_reject_truncate()
    FROM PUBLIC, fixlevelup_runtime;

-- Browser groups: read and create with a trusted expiry; created_at is always
-- forced from the database clock by the guard. No UPDATE and no DELETE exist.
GRANT SELECT(id,secret_hash,created_at,expires_at),
    INSERT(id,secret_hash,expires_at)
    ON foundation.form_browser_groups TO fixlevelup_runtime;
-- Form session group memberships: append the 1:1 mapping only. The anchor
-- secret, expiry and revoke keep living in request_sessions; created_at is
-- forced from the database clock by the guard.
GRANT SELECT(session_id,group_id,created_at),
    INSERT(session_id,group_id)
    ON foundation.form_session_group_memberships TO fixlevelup_runtime;
-- Throttle buckets: append a window row, read it and count up inside it.
GRANT SELECT(id,kind,key_hash,window_started_at,window_seconds,hit_count),
    INSERT(id,kind,key_hash,window_started_at,window_seconds,hit_count),
    UPDATE(hit_count)
    ON foundation.form_throttle_buckets TO fixlevelup_runtime;

COMMIT;
