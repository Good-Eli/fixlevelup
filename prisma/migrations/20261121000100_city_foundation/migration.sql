BEGIN;

-- P03-01 city foundation. Additive DDL only: no seed, no real city, no default
-- timezone/contact/hours, no reviewer, no operator facts. The owner fills the
-- first real city later through approved settings commands; a synthetic city is
-- created only inside tests as the migration owner.
--
-- Scope note: this migration creates the stable city identity, its immutable
-- reviewed snapshots and the immutable published business settings revisions.
-- Zones, districts, memberships, city-scoped addresses/prices and any city write
-- API are later sub-steps. Nothing here fixes an actual city, reviewer role or
-- real operator data, and no rule requires an ACTIVE city to exist.
--
-- Deliberate non-goals:
--   * no CHECK/unique rule "at most one ACTIVE city" (v1 SINGLE_CITY readiness is
--     a resolver/config gate, not a schema limit that a second city would break);
--   * no timezone/contact/hours columns in business_settings_versions, so there is
--     exactly one source for those values (service_city_versions) and no second
--     editable copy or duplicated/legal default to drift from it.

-- Validation helpers. Both are pure functions of their argument (no table or
-- catalog access except the tz database view in the timezone helper), so the
-- office-hours rule is a real CHECK and stays dump/restore safe.
--
-- office_hours is exactly seven ISO weekday slots, Monday first (index 0 = ISO 1,
-- index 6 = ISO 7). Each slot is an array of [startMinute, endMinute] integer
-- pairs with 0 <= start < end <= 1440, sorted and non-overlapping (touching ends
-- are allowed). An empty slot array is an explicitly closed day and is valid stored
-- configuration; an all-closed week is likewise accepted and still lets the city
-- context resolve. It only means "office closed": it must never be presented as
-- accepting requests, and intake readiness stays a resolver/config decision.
--
-- Written as a linear plpgsql loop on purpose: every jsonb_typeof guard runs before
-- jsonb_array_length/-> on the same value, so malformed JSON yields false instead of
-- error 22023, and no per-day quadratic rescan of previous intervals is needed.
CREATE FUNCTION foundation.city_office_hours_is_valid(schedule jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE
    day jsonb;
    slot jsonb;
    prev_end integer;
    start_minute integer;
    end_minute integer;
BEGIN
    IF schedule IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(schedule) <> 'array' THEN RETURN false; END IF;
    IF jsonb_array_length(schedule) <> 7 THEN RETURN false; END IF;
    FOR day_index IN 0..6 LOOP
        day := schedule -> day_index;
        IF jsonb_typeof(day) <> 'array' THEN RETURN false; END IF;
        prev_end := NULL;
        FOR slot IN SELECT value FROM jsonb_array_elements(day) LOOP
            IF jsonb_typeof(slot) <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(slot) <> 2 THEN RETURN false; END IF;
            IF jsonb_typeof(slot->0) <> 'number' OR jsonb_typeof(slot->1) <> 'number' THEN RETURN false; END IF;
            -- Plain integer minutes only: "1.5" is refused as text before any cast
            -- could raise, and 0..1440 bounds are checked on the integers below.
            IF (slot->>0) !~ '^[0-9]{1,4}$' OR (slot->>1) !~ '^[0-9]{1,4}$' THEN RETURN false; END IF;
            start_minute := (slot->>0)::integer;
            end_minute := (slot->>1)::integer;
            IF start_minute < 0 OR start_minute >= end_minute OR end_minute > 1440 THEN RETURN false; END IF;
            IF prev_end IS NOT NULL AND start_minute < prev_end THEN RETURN false; END IF;
            prev_end := end_minute;
        END LOOP;
    END LOOP;
    RETURN true;
END $$;

-- A city timezone must be a real named IANA zone with area/id semantics. Accepted:
-- exactly 'UTC', or any existing name with at least one '/' that the installed tz
-- database knows - including the legitimate Etc/* names such as 'Etc/UTC',
-- 'Etc/GMT-3' and 'Etc/GMT+7' (those are real IANA names, not raw numeric offsets).
-- Rejected: raw offsets and abbreviation-style names ('+03:00', 'UTC+3', 'MSK',
-- 'EST5EDT'), the non-canonical 'posix/' and 'right/' trees, 'SystemV/*', and any
-- padding whitespace. Membership is checked against pg_timezone_names at write
-- time, so a snapshot keeps the exact name it was reviewed with even after a tzdata
-- update instead of being reinterpreted.
CREATE FUNCTION foundation.city_timezone_is_valid(candidate text) RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog AS $$
    SELECT candidate = 'UTC' OR (
        candidate ~ '^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+)+$'
        AND candidate !~ '^(posix|right|SystemV)/'
        AND EXISTS (SELECT FROM pg_timezone_names z WHERE z.name = candidate));
$$;

-- Stable city identity, not a tenant. row_version is bumped by the database (see
-- city_guard_update below); callers never supply the next value themselves.
CREATE TABLE foundation.service_cities (
    id uuid PRIMARY KEY,
    code varchar(32) NOT NULL,
    lifecycle varchar(16) NOT NULL DEFAULT 'DRAFT',
    row_version integer NOT NULL DEFAULT 1,
    current_version_id uuid,
    -- An ACTIVE city must point at the reviewed snapshot it currently serves.
    CONSTRAINT service_cities_lifecycle_check CHECK (lifecycle IN ('DRAFT','ACTIVE','INACTIVE')),
    CONSTRAINT service_cities_code_check CHECK (code ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$' AND length(code) BETWEEN 2 AND 32),
    CONSTRAINT service_cities_row_version_check CHECK (row_version >= 1),
    CONSTRAINT service_cities_active_pointer_check CHECK (lifecycle <> 'ACTIVE' OR current_version_id IS NOT NULL)
);
CREATE UNIQUE INDEX service_cities_code_key ON foundation.service_cities(code);

-- Immutable reviewed snapshot of one city's local settings. Every row is already
-- a published revision (no DRAFT state is modelled), so UPDATE/DELETE/TRUNCATE are
-- refused for everyone including the table owner; a change is a new version row.
CREATE TABLE foundation.service_city_versions (
    id uuid PRIMARY KEY,
    city_id uuid NOT NULL,
    version integer NOT NULL,
    display_name text NOT NULL,
    address_display text,
    timezone text NOT NULL,
    public_contact text NOT NULL,
    office_hours jsonb NOT NULL,
    reviewed_by uuid NOT NULL,
    published_at timestamptz(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT service_city_versions_city_id_fkey FOREIGN KEY (city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT service_city_versions_reviewed_by_fkey FOREIGN KEY (reviewed_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT service_city_versions_version_check CHECK (version >= 1),
    -- Non-blank means at least one non-whitespace character: btrim() alone would
    -- accept a "prepared" value consisting only of tabs/newlines.
    CONSTRAINT service_city_versions_display_name_check CHECK (display_name ~ '[^[:space:]]'),
    CONSTRAINT service_city_versions_address_display_check
        CHECK (address_display IS NULL OR address_display ~ '[^[:space:]]'),
    -- One approved public contact/display for the city; private channel or staff
    -- contact data does not belong in this snapshot.
    CONSTRAINT service_city_versions_public_contact_check CHECK (public_contact ~ '[^[:space:]]'),
    CONSTRAINT service_city_versions_office_hours_check CHECK (foundation.city_office_hours_is_valid(office_hours))
);
CREATE UNIQUE INDEX service_city_versions_city_version_key ON foundation.service_city_versions(city_id,version);
-- Target of the current-pointer FK: it proves the pointer belongs to this city and
-- therefore cannot name another city's history.
CREATE UNIQUE INDEX service_city_versions_city_id_key ON foundation.service_city_versions(city_id,id);

-- Published company settings revisions. City timezone/contact/hours are
-- deliberately absent: they live only in service_city_versions. MULTI_CITY is
-- reserved vocabulary, not an enabled mode - the resolver enables SINGLE_CITY only
-- and must treat MULTI_CITY as unsupported configuration, not as multi-city
-- behaviour. There is no DRAFT state and no default row: every row is published.
CREATE TABLE foundation.business_settings_versions (
    id uuid PRIMARY KEY,
    version integer NOT NULL,
    launch_mode varchar(16) NOT NULL,
    primary_city_id uuid NOT NULL,
    reviewed_by uuid NOT NULL,
    published_at timestamptz(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT business_settings_versions_primary_city_id_fkey FOREIGN KEY (primary_city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT business_settings_versions_reviewed_by_fkey FOREIGN KEY (reviewed_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT business_settings_versions_version_check CHECK (version >= 1),
    CONSTRAINT business_settings_versions_launch_mode_check CHECK (launch_mode IN ('SINGLE_CITY','MULTI_CITY'))
);
CREATE UNIQUE INDEX business_settings_versions_version_key ON foundation.business_settings_versions(version);

-- The current pointer must be a version of the same city: composite FK on
-- (id, current_version_id) forbids a foreign city's history. MATCH SIMPLE keeps the
-- nullable pointer legal for DRAFT/INACTIVE cities; ACTIVE is covered by the CHECK.
ALTER TABLE foundation.service_cities ADD CONSTRAINT service_cities_id_current_version_id_fkey
    FOREIGN KEY (id,current_version_id) REFERENCES foundation.service_city_versions(city_id,id)
    ON DELETE RESTRICT ON UPDATE RESTRICT;

-- IANA timezone is validated against the catalog, so it cannot be a CHECK (a CHECK
-- may not read pg_timezone_names). Trigger-time validation also pins the reviewed
-- name instead of re-interpreting old snapshots after a tzdata update.
CREATE FUNCTION foundation.city_versions_validate() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF NOT foundation.city_timezone_is_valid(NEW.timezone) THEN
        RAISE EXCEPTION 'City version timezone must be a named IANA area/id' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER city_versions_validate BEFORE INSERT OR UPDATE ON foundation.service_city_versions
    FOR EACH ROW EXECUTE FUNCTION foundation.city_versions_validate();

-- Reviewed snapshots and published revisions are append-only for ordinary DML,
-- including the owning role: a correction is a new version row, never an in-place
-- rewrite of what was reviewed. Owner-level DDL (DISABLE TRIGGER) remains the only
-- way around this and is not granted to the application.
CREATE FUNCTION foundation.city_settings_reject_revision_change() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'Published revision is immutable (%)', TG_TABLE_NAME USING ERRCODE='23514';
END $$;
CREATE TRIGGER city_versions_immutable BEFORE UPDATE OR DELETE ON foundation.service_city_versions
    FOR EACH ROW EXECUTE FUNCTION foundation.city_settings_reject_revision_change();
CREATE TRIGGER city_versions_no_truncate BEFORE TRUNCATE ON foundation.service_city_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.city_settings_reject_revision_change();
CREATE TRIGGER business_settings_immutable BEFORE UPDATE OR DELETE ON foundation.business_settings_versions
    FOR EACH ROW EXECUTE FUNCTION foundation.city_settings_reject_revision_change();
CREATE TRIGGER business_settings_no_truncate BEFORE TRUNCATE ON foundation.business_settings_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.city_settings_reject_revision_change();

-- id and code are the stable identity a stored city reference depends on; neither
-- may be rewritten. The database owns row_version: it is always OLD+1, so a caller
-- cannot keep it constant and defeat the optimistic lock. Concurrent updates use
-- UPDATE ... WHERE id=$1 AND row_version=$expected and retry on zero rows.
CREATE FUNCTION foundation.city_guard_update() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.code IS DISTINCT FROM OLD.code THEN
        RAISE EXCEPTION 'Service city id and code are stable' USING ERRCODE='23514';
    END IF;
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END $$;
CREATE TRIGGER city_guard_update BEFORE UPDATE ON foundation.service_cities
    FOR EACH ROW EXECUTE FUNCTION foundation.city_guard_update();

-- Trigger functions are not callable by the runtime role. All are invoker
-- privileges with a fixed search_path and static qualified SQL.
REVOKE ALL ON FUNCTION foundation.city_office_hours_is_valid(jsonb), foundation.city_timezone_is_valid(text),
    foundation.city_versions_validate(), foundation.city_settings_reject_revision_change(),
    foundation.city_guard_update() FROM PUBLIC;
REVOKE ALL ON foundation.service_cities, foundation.service_city_versions,
    foundation.business_settings_versions FROM PUBLIC;

-- Resolver reads only. Nothing is granted to PUBLIC, no INSERT/UPDATE/DELETE/
-- TRUNCATE is granted, and no existing grant is widened: publishing cities and
-- settings stays an owner/reviewed migration-role operation until the city write
-- API arrives with its own capabilities. Display name, contact and office hours are
-- not granted yet because no resolver reads them at this sub-step.
--
-- Note for the future write path: the office-hours CHECK and the timezone trigger
-- call foundation.city_office_hours_is_valid / foundation.city_timezone_is_valid, so
-- whichever role is granted INSERT on service_city_versions must also be granted
-- EXECUTE on those two validator functions in the same reviewed migration.
GRANT SELECT (id,lifecycle,current_version_id) ON foundation.service_cities TO fixlevelup_runtime;
GRANT SELECT (city_id,id,timezone) ON foundation.service_city_versions TO fixlevelup_runtime;
GRANT SELECT (version,launch_mode,primary_city_id) ON foundation.business_settings_versions TO fixlevelup_runtime;

COMMIT;
