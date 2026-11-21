BEGIN;

-- P03-02 service area geography, data layer only. Additive DDL: no seed, no default
-- city or employee, no destructive statement, no new runtime privilege.
--
-- Deliberate non-goals: no automatic grants, administrator membership or technician
-- trip permission (the P03-02 rights matrix is agreed separately and the audited
-- write path is a later sub-step); no address inference - a FULL/PARTIAL district
-- mapping is an advisory candidate for a manual assessment, never proof that a
-- concrete address is in the zone, and no address is stored or derived here; no
-- GIS/polygons, no second zones table, no tenant column.
--
-- Revision lifecycle: draft (published_at IS NULL) is editable, including its
-- district coverage; published is immutable for everyone including the owner. A
-- revision is always INSERTed as a draft and publication is one UPDATE that keeps
-- the reviewed content unchanged. service_areas.current_version_id may only name a
-- published revision of the same city and area.

-- Real administrative district of one city. Optional reference data (a city may
-- have none); archived instead of deleted because request snapshots keep the
-- district label they were reviewed with.
CREATE TABLE foundation.administrative_districts (
    id uuid PRIMARY KEY,
    city_id uuid NOT NULL,
    code varchar(32) NOT NULL,
    name text NOT NULL,
    archived_at timestamptz(6),
    row_version integer NOT NULL DEFAULT 1,
    CONSTRAINT administrative_districts_city_id_fkey FOREIGN KEY (city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT administrative_districts_code_check CHECK (code ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$' AND length(code) BETWEEN 2 AND 32),
    CONSTRAINT administrative_districts_name_check CHECK (name ~ '[^[:space:]]'),
    CONSTRAINT administrative_districts_row_version_check CHECK (row_version >= 1)
);
CREATE UNIQUE INDEX administrative_districts_city_code_key ON foundation.administrative_districts(city_id,code);
CREATE UNIQUE INDEX administrative_districts_city_id_key ON foundation.administrative_districts(city_id,id);

-- Stable service area identity inside one city: a company trip zone, not a district
-- and not a tenant. code and id never change; a rename or new coverage is a new
-- revision, never an in-place rewrite of reviewed history.
CREATE TABLE foundation.service_areas (
    id uuid PRIMARY KEY,
    city_id uuid NOT NULL,
    code varchar(32) NOT NULL,
    current_version_id uuid,
    archived_at timestamptz(6),
    row_version integer NOT NULL DEFAULT 1,
    CONSTRAINT service_areas_city_id_fkey FOREIGN KEY (city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT service_areas_code_check CHECK (code ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$' AND length(code) BETWEEN 2 AND 32),
    CONSTRAINT service_areas_row_version_check CHECK (row_version >= 1)
);
CREATE UNIQUE INDEX service_areas_city_code_key ON foundation.service_areas(city_id,code);
CREATE UNIQUE INDEX service_areas_city_id_key ON foundation.service_areas(city_id,id);

-- Revision of one service area: immutable name/coverage description/manual address
-- criteria and its author, so an old published revision keeps explaining the zone
-- exactly as reviewed after a newer revision becomes current.
CREATE TABLE foundation.service_area_versions (
    id uuid PRIMARY KEY,
    city_id uuid NOT NULL,
    area_id uuid NOT NULL,
    version integer NOT NULL,
    name text NOT NULL,
    coverage_description text,
    address_criteria text,
    created_by uuid NOT NULL,
    published_at timestamptz(6),
    published_by uuid,
    row_version integer NOT NULL DEFAULT 1,
    CONSTRAINT service_area_versions_city_id_area_id_fkey FOREIGN KEY (city_id,area_id)
        REFERENCES foundation.service_areas(city_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT service_area_versions_created_by_fkey FOREIGN KEY (created_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT service_area_versions_published_by_fkey FOREIGN KEY (published_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT service_area_versions_version_check CHECK (version >= 1),
    CONSTRAINT service_area_versions_row_version_check CHECK (row_version >= 1),
    CONSTRAINT service_area_versions_name_check CHECK (name ~ '[^[:space:]]'),
    CONSTRAINT service_area_versions_coverage_description_check
        CHECK (coverage_description IS NULL OR coverage_description ~ '[^[:space:]]'),
    CONSTRAINT service_area_versions_address_criteria_check
        CHECK (address_criteria IS NULL OR address_criteria ~ '[^[:space:]]'),
    -- Draft and published are the only states: no half-published revision.
    CONSTRAINT service_area_versions_publication_pair_check
        CHECK ((published_at IS NULL) = (published_by IS NULL))
);
CREATE UNIQUE INDEX service_area_versions_city_area_version_key ON foundation.service_area_versions(city_id,area_id,version);
CREATE UNIQUE INDEX service_area_versions_city_id_key ON foundation.service_area_versions(city_id,id);
-- Pointer FK target: pins a revision to one area and one city.
CREATE UNIQUE INDEX service_area_versions_area_city_id_key ON foundation.service_area_versions(area_id,city_id,id);

-- Manual M:N coverage of one area revision by real districts. Both composite FKs are
-- city-scoped, so a foreign revision or a foreign district cannot be mapped. M:N in
-- both directions: a zone covers several districts, a district belongs to several
-- zones. FULL/PARTIAL is advisory only and does not qualify an address.
CREATE TABLE foundation.service_area_district_coverage (
    city_id uuid NOT NULL,
    area_version_id uuid NOT NULL,
    district_id uuid NOT NULL,
    relation varchar(16) NOT NULL,
    description text,
    CONSTRAINT service_area_district_coverage_pkey PRIMARY KEY (area_version_id,district_id),
    CONSTRAINT service_area_district_coverage_city_id_area_version_id_fkey FOREIGN KEY (city_id,area_version_id)
        REFERENCES foundation.service_area_versions(city_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT service_area_district_coverage_city_id_district_id_fkey FOREIGN KEY (city_id,district_id)
        REFERENCES foundation.administrative_districts(city_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT service_area_district_coverage_relation_check CHECK (relation IN ('FULL','PARTIAL')),
    CONSTRAINT service_area_district_coverage_description_check
        CHECK (description IS NULL OR description ~ '[^[:space:]]')
);
CREATE INDEX service_area_district_coverage_district_idx ON foundation.service_area_district_coverage(city_id,district_id);

-- The pointer must be same city + same area + published. MATCH SIMPLE keeps a NULL
-- pointer legal for a new area; the trigger below adds the published qualification.
ALTER TABLE foundation.service_areas ADD CONSTRAINT service_areas_id_city_id_current_version_id_fkey
    FOREIGN KEY (id,city_id,current_version_id) REFERENCES foundation.service_area_versions(area_id,city_id,id)
    ON DELETE RESTRICT ON UPDATE RESTRICT;

-- Identity is stable and the database owns row_version (always OLD+1), so a caller
-- cannot keep it constant and defeat the optimistic lock. A non-null pointer must be
-- a published revision of this city and area: the composite FK rejects foreign
-- history, this guard adds the published check.
CREATE FUNCTION foundation.service_areas_guard_pointer() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    version_published timestamptz;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.city_id IS DISTINCT FROM OLD.city_id
            OR NEW.code IS DISTINCT FROM OLD.code THEN
            RAISE EXCEPTION 'Service area id, city and code are stable' USING ERRCODE='23514';
        END IF;
        NEW.row_version := OLD.row_version + 1;
    END IF;
    IF NEW.current_version_id IS NOT NULL THEN
        SELECT v.published_at INTO version_published
        FROM foundation.service_area_versions v
        WHERE v.id = NEW.current_version_id AND v.area_id = NEW.id AND v.city_id = NEW.city_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Current service area version must belong to the same city and area' USING ERRCODE='23503';
        END IF;
        IF version_published IS NULL THEN
            RAISE EXCEPTION 'Current service area version must be published' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER service_areas_guard_pointer BEFORE INSERT OR UPDATE ON foundation.service_areas
    FOR EACH ROW EXECUTE FUNCTION foundation.service_areas_guard_pointer();

CREATE FUNCTION foundation.administrative_districts_guard_update() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.city_id IS DISTINCT FROM OLD.city_id
        OR NEW.code IS DISTINCT FROM OLD.code THEN
        RAISE EXCEPTION 'Administrative district id, city and code are stable' USING ERRCODE='23514';
    END IF;
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END $$;
CREATE TRIGGER administrative_districts_guard_update BEFORE UPDATE ON foundation.administrative_districts
    FOR EACH ROW EXECUTE FUNCTION foundation.administrative_districts_guard_update();

-- Draft lifecycle: create as draft, edit or publish a draft, published is
-- append-only. Publication is a state transition that may not change the reviewed
-- content; the publishing UPDATE holds the row lock that serializes it against the
-- coverage guard below.
CREATE FUNCTION foundation.service_area_versions_guard_change() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.published_at IS NOT NULL OR NEW.published_by IS NOT NULL THEN
            RAISE EXCEPTION 'Service area version must be created as a draft' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Service area version history is append-only' USING ERRCODE='23514';
    END IF;
    IF OLD.published_at IS NOT NULL THEN
        RAISE EXCEPTION 'Published service area version is immutable' USING ERRCODE='23514';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.city_id IS DISTINCT FROM OLD.city_id
        OR NEW.area_id IS DISTINCT FROM OLD.area_id OR NEW.version IS DISTINCT FROM OLD.version
        OR NEW.created_by IS DISTINCT FROM OLD.created_by THEN
        RAISE EXCEPTION 'Service area version identity is stable' USING ERRCODE='23514';
    END IF;
    IF NEW.published_at IS NOT NULL AND (NEW.name IS DISTINCT FROM OLD.name
        OR NEW.coverage_description IS DISTINCT FROM OLD.coverage_description
        OR NEW.address_criteria IS DISTINCT FROM OLD.address_criteria) THEN
        RAISE EXCEPTION 'Publishing must not change the reviewed draft content' USING ERRCODE='23514';
    END IF;
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END $$;
CREATE TRIGGER service_area_versions_guard_change BEFORE INSERT OR UPDATE OR DELETE ON foundation.service_area_versions
    FOR EACH ROW EXECUTE FUNCTION foundation.service_area_versions_guard_change();

-- Coverage guard. Every child change first takes FOR UPDATE on its parent revision
-- and then refuses if that revision is published. Publication is an UPDATE of the
-- same row, so both orders serialize: a child change that commits first bumps the
-- parent draft row_version (publisher's WHERE row_version=$expected then misses),
-- and a child change that arrives after publication sees published_at and fails.
-- This is what makes "no late INSERT into published history" true under concurrency.
CREATE FUNCTION foundation.service_area_district_coverage_guard_change() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    target_version uuid;
    version_city uuid;
    version_published timestamptz;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_version := OLD.area_version_id;
    ELSE
        target_version := NEW.area_version_id;
    END IF;
    SELECT v.city_id, v.published_at INTO version_city, version_published
    FROM foundation.service_area_versions v WHERE v.id = target_version FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'District coverage must reference an existing service area version' USING ERRCODE='23503';
    END IF;
    IF TG_OP <> 'DELETE' AND NEW.city_id IS DISTINCT FROM version_city THEN
        RAISE EXCEPTION 'District coverage city must match its service area version city' USING ERRCODE='23503';
    END IF;
    IF version_published IS NOT NULL THEN
        RAISE EXCEPTION 'District coverage is immutable once its service area version is published' USING ERRCODE='23514';
    END IF;
    IF TG_OP = 'UPDATE' AND (NEW.city_id IS DISTINCT FROM OLD.city_id
        OR NEW.area_version_id IS DISTINCT FROM OLD.area_version_id
        OR NEW.district_id IS DISTINCT FROM OLD.district_id) THEN
        RAISE EXCEPTION 'District coverage identity is stable; correct it through the draft revision' USING ERRCODE='23514';
    END IF;
    UPDATE foundation.service_area_versions SET row_version = row_version WHERE id = target_version;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER service_area_district_coverage_guard_change BEFORE INSERT OR UPDATE OR DELETE
    ON foundation.service_area_district_coverage
    FOR EACH ROW EXECUTE FUNCTION foundation.service_area_district_coverage_guard_change();

-- TRUNCATE bypasses row triggers, so history refuses it at statement level too.
-- Owner-level DDL (DISABLE TRIGGER) is the only way around this and is not granted.
CREATE FUNCTION foundation.service_area_history_reject_truncate() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'Service area history is append-only (%)', TG_TABLE_NAME USING ERRCODE='23514';
END $$;
CREATE TRIGGER service_area_versions_no_truncate BEFORE TRUNCATE ON foundation.service_area_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.service_area_history_reject_truncate();
CREATE TRIGGER service_area_district_coverage_no_truncate BEFORE TRUNCATE ON foundation.service_area_district_coverage
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.service_area_history_reject_truncate();

-- Guard functions are invoker privileges with a fixed search_path and static
-- qualified SQL, and none is callable by the runtime role.
REVOKE ALL ON FUNCTION foundation.service_areas_guard_pointer(),
    foundation.administrative_districts_guard_update(),
    foundation.service_area_versions_guard_change(),
    foundation.service_area_district_coverage_guard_change(),
    foundation.service_area_history_reject_truncate() FROM PUBLIC;
REVOKE ALL ON foundation.administrative_districts, foundation.service_areas,
    foundation.service_area_versions, foundation.service_area_district_coverage FROM PUBLIC;

-- No privilege is granted here, not even SELECT: reading published coverage and the
-- audited draft/publish write path are separate reviewed sub-steps. The runtime role
-- gets no access and no capability from this migration, and nothing is granted to
-- PUBLIC.

COMMIT;
