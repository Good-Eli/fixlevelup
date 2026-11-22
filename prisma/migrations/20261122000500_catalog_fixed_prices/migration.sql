BEGIN;
SET LOCAL search_path = pg_catalog;

-- Trusted, server-supplied PostgreSQL 18.7 extension. The migration role owns
-- foundation and has CREATE in the database (including the provisioned shadow).
CREATE EXTENSION btree_gist WITH SCHEMA foundation VERSION '1.8';

CREATE TABLE foundation.catalog_directory_entries (
    id uuid PRIMARY KEY,
    kind varchar(16) NOT NULL,
    code varchar(64) NOT NULL,
    category_id uuid,
    brand_id uuid,
    category_kind varchar(16) NOT NULL DEFAULT 'CATEGORY',
    brand_kind varchar(16) NOT NULL DEFAULT 'BRAND',
    row_version integer NOT NULL DEFAULT 1,
    current_version_id uuid,
    archived_at timestamptz(6),
    CONSTRAINT catalog_directory_entries_kind_check CHECK (kind IN ('CATEGORY','BRAND','MODEL','FAULT')),
    CONSTRAINT catalog_directory_entries_code_check CHECK (code COLLATE "C" ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$' AND length(code) >= 2),
    CONSTRAINT catalog_directory_entries_category_kind_check CHECK (category_kind = 'CATEGORY'),
    CONSTRAINT catalog_directory_entries_brand_kind_check CHECK (brand_kind = 'BRAND'),
    CONSTRAINT catalog_directory_entries_parents_check CHECK (CASE kind
        WHEN 'MODEL' THEN category_id IS NOT NULL AND brand_id IS NOT NULL
        WHEN 'FAULT' THEN category_id IS NOT NULL AND brand_id IS NULL
        ELSE category_id IS NULL AND brand_id IS NULL END),
    CONSTRAINT catalog_directory_entries_row_version_check CHECK (row_version >= 1),
    CONSTRAINT catalog_directory_entries_archive_check CHECK (archived_at IS NULL OR isfinite(archived_at)),
    CONSTRAINT catalog_directory_entries_kind_code_key UNIQUE (kind,code),
    CONSTRAINT catalog_directory_entries_id_kind_key UNIQUE (id,kind),
    CONSTRAINT catalog_directory_entries_category_identity_key UNIQUE (id,kind,category_id),
    CONSTRAINT catalog_directory_entries_category_fkey FOREIGN KEY (category_id,category_kind)
        REFERENCES foundation.catalog_directory_entries(id,kind) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT catalog_directory_entries_brand_fkey FOREIGN KEY (brand_id,brand_kind)
        REFERENCES foundation.catalog_directory_entries(id,kind) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE foundation.catalog_directory_versions (
    id uuid PRIMARY KEY,
    entry_id uuid NOT NULL,
    version integer NOT NULL,
    title text NOT NULL,
    description text,
    reviewed_by uuid NOT NULL,
    published_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT catalog_directory_versions_version_check CHECK (version >= 1),
    CONSTRAINT catalog_directory_versions_title_check CHECK (length(title) BETWEEN 1 AND 160 AND title ~ '[^[:space:]]'),
    CONSTRAINT catalog_directory_versions_description_check CHECK (description IS NULL OR length(description) <= 1000),
    CONSTRAINT catalog_directory_versions_entry_version_key UNIQUE (entry_id,version),
    CONSTRAINT catalog_directory_versions_entry_id_key UNIQUE (entry_id,id),
    CONSTRAINT catalog_directory_versions_entry_fkey FOREIGN KEY (entry_id)
        REFERENCES foundation.catalog_directory_entries(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT catalog_directory_versions_reviewer_fkey FOREIGN KEY (reviewed_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);
ALTER TABLE foundation.catalog_directory_entries ADD CONSTRAINT catalog_directory_entries_current_version_fkey
    FOREIGN KEY (id,current_version_id) REFERENCES foundation.catalog_directory_versions(entry_id,id)
    ON DELETE RESTRICT ON UPDATE RESTRICT;

CREATE TABLE foundation.catalog_items (
    id uuid PRIMARY KEY,
    kind varchar(16) NOT NULL,
    code varchar(64) NOT NULL,
    category_id uuid,
    category_kind varchar(16) NOT NULL DEFAULT 'CATEGORY',
    unit varchar(24) NOT NULL,
    row_version integer NOT NULL DEFAULT 1,
    current_version_id uuid,
    archived_at timestamptz(6),
    CONSTRAINT catalog_items_kind_check CHECK (kind IN ('WORK','PART','MATERIAL','TRAVEL','DIAGNOSTICS')),
    CONSTRAINT catalog_items_code_check CHECK (code COLLATE "C" ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$' AND length(code) >= 2),
    CONSTRAINT catalog_items_unit_check CHECK (unit COLLATE "C" ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'),
    CONSTRAINT catalog_items_category_kind_check CHECK (category_kind = 'CATEGORY'),
    CONSTRAINT catalog_items_category_required_check CHECK (kind <> 'WORK' OR category_id IS NOT NULL),
    CONSTRAINT catalog_items_row_version_check CHECK (row_version >= 1),
    CONSTRAINT catalog_items_archive_check CHECK (archived_at IS NULL OR isfinite(archived_at)),
    CONSTRAINT catalog_items_code_key UNIQUE (code),
    CONSTRAINT catalog_items_id_kind_key UNIQUE (id,kind),
    CONSTRAINT catalog_items_category_identity_key UNIQUE (id,kind,category_id),
    CONSTRAINT catalog_items_category_fkey FOREIGN KEY (category_id,category_kind)
        REFERENCES foundation.catalog_directory_entries(id,kind) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE foundation.catalog_item_versions (
    id uuid PRIMARY KEY,
    item_id uuid NOT NULL,
    kind varchar(16) NOT NULL,
    version integer NOT NULL,
    title text NOT NULL,
    description text,
    duration_minutes integer,
    technician_visible boolean NOT NULL,
    public_visible boolean NOT NULL,
    reviewed_by uuid NOT NULL,
    published_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT catalog_item_versions_version_check CHECK (version >= 1),
    CONSTRAINT catalog_item_versions_title_check CHECK (length(title) BETWEEN 1 AND 160 AND title ~ '[^[:space:]]'),
    CONSTRAINT catalog_item_versions_description_check CHECK (description IS NULL OR length(description) <= 1000),
    CONSTRAINT catalog_item_versions_duration_check CHECK (CASE WHEN kind IN ('WORK','DIAGNOSTICS')
        THEN duration_minutes IS NOT NULL AND duration_minutes BETWEEN 1 AND 1440
        ELSE duration_minutes IS NULL END),
    CONSTRAINT catalog_item_versions_item_version_key UNIQUE (item_id,version),
    CONSTRAINT catalog_item_versions_item_id_key UNIQUE (item_id,id),
    CONSTRAINT catalog_item_versions_item_fkey FOREIGN KEY (item_id,kind)
        REFERENCES foundation.catalog_items(id,kind) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT catalog_item_versions_reviewer_fkey FOREIGN KEY (reviewed_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);
ALTER TABLE foundation.catalog_items ADD CONSTRAINT catalog_items_current_version_fkey
    FOREIGN KEY (id,current_version_id) REFERENCES foundation.catalog_item_versions(item_id,id)
    ON DELETE RESTRICT ON UPDATE RESTRICT;

CREATE TABLE foundation.catalog_fault_service_mappings (
    id uuid PRIMARY KEY,
    category_id uuid NOT NULL,
    fault_id uuid NOT NULL,
    fault_kind varchar(16) NOT NULL DEFAULT 'FAULT',
    item_id uuid NOT NULL,
    item_kind varchar(16) NOT NULL DEFAULT 'WORK',
    row_version integer NOT NULL DEFAULT 1,
    published_at timestamptz(6),
    published_by uuid,
    archived_at timestamptz(6),
    CONSTRAINT catalog_fault_service_mappings_fault_kind_check CHECK (fault_kind = 'FAULT'),
    CONSTRAINT catalog_fault_service_mappings_item_kind_check CHECK (item_kind = 'WORK'),
    CONSTRAINT catalog_fault_service_mappings_row_version_check CHECK (row_version >= 1),
    CONSTRAINT catalog_fault_service_mappings_publication_check CHECK (
        (published_at IS NULL AND published_by IS NULL)
        OR (published_at IS NOT NULL AND isfinite(published_at) AND published_by IS NOT NULL)),
    CONSTRAINT catalog_fault_service_mappings_archive_check CHECK (archived_at IS NULL OR isfinite(archived_at)),
    CONSTRAINT catalog_fault_service_mappings_pair_key UNIQUE (fault_id,item_id),
    CONSTRAINT catalog_fault_service_mappings_fault_fkey FOREIGN KEY (fault_id,fault_kind,category_id)
        REFERENCES foundation.catalog_directory_entries(id,kind,category_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT catalog_fault_service_mappings_item_fkey FOREIGN KEY (item_id,item_kind,category_id)
        REFERENCES foundation.catalog_items(id,kind,category_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT catalog_fault_service_mappings_publisher_fkey FOREIGN KEY (published_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE foundation.catalog_price_series (
    id uuid PRIMARY KEY,
    city_id uuid NOT NULL,
    item_id uuid NOT NULL,
    row_version integer NOT NULL DEFAULT 1,
    CONSTRAINT catalog_price_series_row_version_check CHECK (row_version >= 1),
    CONSTRAINT catalog_price_series_city_item_key UNIQUE (city_id,item_id),
    CONSTRAINT catalog_price_series_identity_key UNIQUE (id,city_id,item_id),
    CONSTRAINT catalog_price_series_city_fkey FOREIGN KEY (city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT catalog_price_series_item_fkey FOREIGN KEY (item_id)
        REFERENCES foundation.catalog_items(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE foundation.catalog_price_versions (
    id uuid PRIMARY KEY,
    series_id uuid NOT NULL,
    city_id uuid NOT NULL,
    city_version_id uuid NOT NULL,
    item_id uuid NOT NULL,
    item_version_id uuid NOT NULL,
    version integer NOT NULL,
    amount_minor bigint NOT NULL,
    currency varchar(3) NOT NULL,
    zero_basis text,
    source_ref text NOT NULL,
    reviewed_by uuid NOT NULL,
    published_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    valid_from timestamptz(6) NOT NULL,
    valid_until timestamptz(6),
    CONSTRAINT catalog_price_versions_version_check CHECK (version >= 1),
    CONSTRAINT catalog_price_versions_amount_check CHECK (amount_minor >= 0),
    CONSTRAINT catalog_price_versions_currency_check CHECK (currency COLLATE "C" ~ '^[A-Z]{3}$'),
    CONSTRAINT catalog_price_versions_zero_basis_check CHECK (CASE WHEN amount_minor = 0
        THEN zero_basis IS NOT NULL AND length(zero_basis) <= 200 AND zero_basis ~ '[^[:space:]]'
        ELSE zero_basis IS NULL END),
    CONSTRAINT catalog_price_versions_source_ref_check CHECK (length(source_ref) <= 200 AND source_ref ~ '[^[:space:]]'),
    CONSTRAINT catalog_price_versions_valid_from_check CHECK (
        isfinite(valid_from) AND valid_from = date_trunc('milliseconds',valid_from,'UTC')),
    CONSTRAINT catalog_price_versions_valid_until_check CHECK (valid_until IS NULL OR (
        isfinite(valid_until) AND valid_until = date_trunc('milliseconds',valid_until,'UTC') AND valid_until > valid_from)),
    CONSTRAINT catalog_price_versions_city_id_key UNIQUE (city_id,id),
    CONSTRAINT catalog_price_versions_series_version_key UNIQUE (series_id,version),
    CONSTRAINT catalog_price_versions_identity_key UNIQUE (id,series_id,city_id,item_id),
    CONSTRAINT catalog_price_versions_series_fkey FOREIGN KEY (series_id,city_id,item_id)
        REFERENCES foundation.catalog_price_series(id,city_id,item_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT catalog_price_versions_city_version_fkey FOREIGN KEY (city_id,city_version_id)
        REFERENCES foundation.service_city_versions(city_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT catalog_price_versions_item_version_fkey FOREIGN KEY (item_id,item_version_id)
        REFERENCES foundation.catalog_item_versions(item_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT catalog_price_versions_reviewer_fkey FOREIGN KEY (reviewed_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE foundation.catalog_price_periods (
    price_version_id uuid PRIMARY KEY,
    series_id uuid NOT NULL,
    city_id uuid NOT NULL,
    item_id uuid NOT NULL,
    valid_from timestamptz(6) NOT NULL,
    scheduled_until timestamptz(6),
    closed_effective_until timestamptz(6),
    CONSTRAINT catalog_price_periods_valid_from_check CHECK (
        isfinite(valid_from) AND valid_from = date_trunc('milliseconds',valid_from,'UTC')),
    CONSTRAINT catalog_price_periods_scheduled_until_check CHECK (scheduled_until IS NULL OR (
        isfinite(scheduled_until) AND scheduled_until = date_trunc('milliseconds',scheduled_until,'UTC')
        AND scheduled_until > valid_from)),
    CONSTRAINT catalog_price_periods_closed_until_check CHECK (closed_effective_until IS NULL OR (
        isfinite(closed_effective_until) AND closed_effective_until = date_trunc('milliseconds',closed_effective_until,'UTC')
        AND closed_effective_until > valid_from AND (scheduled_until IS NULL OR closed_effective_until < scheduled_until))),
    CONSTRAINT catalog_price_periods_version_fkey FOREIGN KEY (price_version_id,series_id,city_id,item_id)
        REFERENCES foundation.catalog_price_versions(id,series_id,city_id,item_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT catalog_price_periods_no_overlap EXCLUDE USING gist (
        city_id foundation.gist_uuid_ops WITH =,
        item_id foundation.gist_uuid_ops WITH =,
        tstzrange(valid_from,coalesce(closed_effective_until,scheduled_until),'[)') WITH &&
    )
);
ALTER TABLE foundation.catalog_price_versions ADD CONSTRAINT catalog_price_versions_period_fkey
    FOREIGN KEY (id) REFERENCES foundation.catalog_price_periods(price_version_id)
    ON DELETE NO ACTION ON UPDATE NO ACTION DEFERRABLE INITIALLY DEFERRED;

-- Ports take this fence in a separate statement before any reads/locks. Also
-- serialize direct DML writers before they can check parents or lock catalog rows.
CREATE FUNCTION foundation.catalog_lock_write() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'Catalog writes require READ COMMITTED' USING ERRCODE = '40001';
    END IF;
    PERFORM pg_advisory_xact_lock(77304,1);
    RETURN NULL;
END $$;

CREATE FUNCTION foundation.catalog_reject_history_change() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'Catalog history cannot be rewritten (%)', TG_TABLE_NAME USING ERRCODE = '23514';
END $$;

CREATE FUNCTION foundation.catalog_guard_identity() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    previous_version integer;
    candidate_version integer;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.row_version IS DISTINCT FROM 1 OR NEW.current_version_id IS NOT NULL OR NEW.archived_at IS NOT NULL THEN
            RAISE EXCEPTION 'Catalog identity starts as a draft at version 1' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.archived_at IS NOT NULL OR ROW(NEW.id,NEW.kind,NEW.code,NEW.category_id,NEW.category_kind,NEW.row_version)
        IS DISTINCT FROM ROW(OLD.id,OLD.kind,OLD.code,OLD.category_id,OLD.category_kind,OLD.row_version) THEN
        RAISE EXCEPTION 'Archived catalog identities and stable fields cannot change' USING ERRCODE = '23514';
    END IF;
    IF TG_TABLE_NAME = 'catalog_directory_entries' THEN
        IF ROW(NEW.brand_id,NEW.brand_kind) IS DISTINCT FROM ROW(OLD.brand_id,OLD.brand_kind) THEN
            RAISE EXCEPTION 'Catalog directory parent identities cannot change' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.unit IS DISTINCT FROM OLD.unit THEN
        RAISE EXCEPTION 'Catalog item unit cannot change' USING ERRCODE = '23514';
    END IF;

    IF NEW.archived_at IS NOT NULL THEN
        IF NEW.current_version_id IS DISTINCT FROM OLD.current_version_id THEN
            RAISE EXCEPTION 'Archive preserves the published pointer' USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NEW.current_version_id IS NULL OR NEW.current_version_id IS NOT DISTINCT FROM OLD.current_version_id THEN
            RAISE EXCEPTION 'Catalog publish requires a new current version' USING ERRCODE = '23514';
        END IF;
        IF TG_TABLE_NAME = 'catalog_directory_entries' THEN
            SELECT version INTO previous_version FROM foundation.catalog_directory_versions WHERE id = OLD.current_version_id;
            SELECT version INTO candidate_version FROM foundation.catalog_directory_versions
                WHERE id = NEW.current_version_id AND entry_id = OLD.id;
            IF NEW.brand_id IS NOT NULL AND NOT EXISTS (SELECT FROM foundation.catalog_directory_entries
                WHERE id = NEW.brand_id AND archived_at IS NULL AND current_version_id IS NOT NULL) THEN
                RAISE EXCEPTION 'Catalog publish requires a live published brand' USING ERRCODE = '23514';
            END IF;
        ELSE
            SELECT version INTO previous_version FROM foundation.catalog_item_versions WHERE id = OLD.current_version_id;
            SELECT version INTO candidate_version FROM foundation.catalog_item_versions
                WHERE id = NEW.current_version_id AND item_id = OLD.id;
        END IF;
        IF candidate_version IS NULL THEN
            RAISE EXCEPTION 'Current version must belong to this catalog identity' USING ERRCODE = '23503';
        END IF;
        IF candidate_version IS DISTINCT FROM coalesce(previous_version,0) + 1 THEN
            RAISE EXCEPTION 'Current catalog version must advance by one' USING ERRCODE = '23514';
        END IF;
        IF NEW.category_id IS NOT NULL AND NOT EXISTS (SELECT FROM foundation.catalog_directory_entries
            WHERE id = NEW.category_id AND archived_at IS NULL AND current_version_id IS NOT NULL) THEN
            RAISE EXCEPTION 'Catalog publish requires a live published category' USING ERRCODE = '23514';
        END IF;
    END IF;
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END $$;

-- A reviewed metadata row is part of the canonical published chain, not a
-- detached draft. Check at transaction end so INSERT may precede pointer UPDATE.
CREATE FUNCTION foundation.catalog_guard_revision_chain() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    reached_version integer;
BEGIN
    IF TG_TABLE_NAME = 'catalog_directory_versions' THEN
        SELECT v.version INTO reached_version
        FROM foundation.catalog_directory_entries e
        JOIN foundation.catalog_directory_versions v ON v.id = e.current_version_id
        WHERE e.id = NEW.entry_id;
    ELSE
        SELECT v.version INTO reached_version
        FROM foundation.catalog_items i
        JOIN foundation.catalog_item_versions v ON v.id = i.current_version_id
        WHERE i.id = NEW.item_id;
    END IF;
    IF reached_version IS NULL OR reached_version < NEW.version THEN
        RAISE EXCEPTION 'Reviewed catalog revision must join its published chain' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END $$;

CREATE FUNCTION foundation.catalog_guard_mapping() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.row_version IS DISTINCT FROM 1 OR NEW.archived_at IS NOT NULL OR NEW.published_at IS NOT NULL OR NEW.published_by IS NOT NULL THEN
            RAISE EXCEPTION 'Catalog mapping starts as a draft at version 1' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.archived_at IS NOT NULL OR ROW(NEW.id,NEW.category_id,NEW.fault_id,NEW.fault_kind,NEW.item_id,NEW.item_kind,NEW.row_version)
        IS DISTINCT FROM ROW(OLD.id,OLD.category_id,OLD.fault_id,OLD.fault_kind,OLD.item_id,OLD.item_kind,OLD.row_version) THEN
        RAISE EXCEPTION 'Archived catalog mappings and stable fields cannot change' USING ERRCODE = '23514';
    END IF;
    IF NEW.archived_at IS NOT NULL THEN
        IF ROW(NEW.published_at,NEW.published_by) IS DISTINCT FROM ROW(OLD.published_at,OLD.published_by) THEN
            RAISE EXCEPTION 'Archive preserves the first mapping publication' USING ERRCODE = '23514';
        END IF;
    ELSE
        IF OLD.published_at IS NOT NULL OR NEW.published_at IS NULL OR NEW.published_by IS NULL THEN
            RAISE EXCEPTION 'Mapping can be published only once as a pair' USING ERRCODE = '23514';
        END IF;
        IF NOT EXISTS (SELECT FROM foundation.catalog_directory_entries c
            JOIN foundation.catalog_directory_entries f ON f.id = NEW.fault_id
            JOIN foundation.catalog_items i ON i.id = NEW.item_id
            WHERE c.id = NEW.category_id AND c.archived_at IS NULL AND c.current_version_id IS NOT NULL
                AND f.archived_at IS NULL AND f.current_version_id IS NOT NULL
                AND i.archived_at IS NULL AND i.current_version_id IS NOT NULL) THEN
            RAISE EXCEPTION 'Mapping publish requires live published category, fault and item' USING ERRCODE = '23514';
        END IF;
    END IF;
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END $$;

CREATE FUNCTION foundation.catalog_guard_price_series() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.row_version IS DISTINCT FROM 1 THEN
            RAISE EXCEPTION 'Price series starts at version 1' USING ERRCODE = '23514';
        END IF;
    ELSIF ROW(NEW.id,NEW.city_id,NEW.item_id) IS DISTINCT FROM ROW(OLD.id,OLD.city_id,OLD.item_id)
        OR NEW.row_version IS DISTINCT FROM OLD.row_version + 1 THEN
        RAISE EXCEPTION 'Only a single row_version increment is allowed on a price series' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;

-- Current-at-publish review basis. An inactive/prepared city may publish prices
-- if it has a reviewed current city version. The existing city UPDATE column
-- grant permits this FOR SHARE without adding privileges to any existing table.
CREATE FUNCTION foundation.catalog_guard_price_basis() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF NOT EXISTS (SELECT FROM foundation.service_cities
        WHERE id = NEW.city_id AND current_version_id = NEW.city_version_id FOR SHARE) THEN
        RAISE EXCEPTION 'Price publish requires the current city version' USING ERRCODE = '23503';
    END IF;
    IF NOT EXISTS (SELECT FROM foundation.catalog_items i
        LEFT JOIN foundation.catalog_directory_entries c ON c.id = i.category_id
        WHERE i.id = NEW.item_id AND i.current_version_id = NEW.item_version_id AND i.archived_at IS NULL
            AND (i.category_id IS NULL OR (c.current_version_id IS NOT NULL AND c.archived_at IS NULL))) THEN
        RAISE EXCEPTION 'Price publish requires the current eligible item version' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION foundation.catalog_guard_price_period() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    db_now timestamptz;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.closed_effective_until IS NOT NULL OR NOT EXISTS (
            SELECT FROM foundation.catalog_price_versions v
            WHERE (v.id,v.series_id,v.city_id,v.item_id) = (NEW.price_version_id,NEW.series_id,NEW.city_id,NEW.item_id)
                AND v.valid_from = NEW.valid_from AND v.valid_until IS NOT DISTINCT FROM NEW.scheduled_until
        ) THEN
            RAISE EXCEPTION 'Price period must start open and project the exact reviewed period'
                USING ERRCODE = '23514', CONSTRAINT = 'catalog_price_periods_projection_guard';
        END IF;
        db_now := date_trunc('milliseconds',clock_timestamp());
        IF NEW.valid_from <= db_now THEN
            RAISE EXCEPTION 'Price period start must be in the future'
                USING ERRCODE = '23514', CONSTRAINT = 'catalog_price_periods_future_start_guard';
        END IF;
    ELSE
        IF ROW(NEW.price_version_id,NEW.series_id,NEW.city_id,NEW.item_id,NEW.valid_from,NEW.scheduled_until)
            IS DISTINCT FROM ROW(OLD.price_version_id,OLD.series_id,OLD.city_id,OLD.item_id,OLD.valid_from,OLD.scheduled_until) THEN
            RAISE EXCEPTION 'Price period identity and schedule are immutable'
                USING ERRCODE = '23514', CONSTRAINT = 'catalog_price_periods_projection_guard';
        END IF;
        db_now := date_trunc('milliseconds',clock_timestamp());
        IF OLD.closed_effective_until IS NOT NULL OR NEW.closed_effective_until IS NULL
            OR OLD.valid_from > db_now OR (OLD.scheduled_until IS NOT NULL AND OLD.scheduled_until <= db_now)
            OR NEW.closed_effective_until <= db_now
            OR (OLD.scheduled_until IS NOT NULL AND NEW.closed_effective_until >= OLD.scheduled_until) THEN
            RAISE EXCEPTION 'Only an effective open price period can be closed once at a future instant before its scheduled end'
                USING ERRCODE = '23514', CONSTRAINT = 'catalog_price_periods_close_guard';
        END IF;
    END IF;
    RETURN NEW;
END $$;

-- Final check under the same transaction fence. A wait on evidence or another
-- constraint can consume the remaining time between before-row guard and COMMIT.
CREATE FUNCTION foundation.catalog_guard_price_final_clock() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    boundary timestamptz;
BEGIN
    boundary := CASE WHEN TG_OP = 'INSERT' THEN NEW.valid_from ELSE NEW.closed_effective_until END;
    IF boundary <= date_trunc('milliseconds',clock_timestamp()) THEN
        RAISE EXCEPTION 'Price boundary elapsed before transaction end'
            USING ERRCODE = '23514', CONSTRAINT = 'catalog_price_periods_final_clock_guard';
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER catalog_directory_entries_write_fence BEFORE INSERT OR UPDATE ON foundation.catalog_directory_entries
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER catalog_directory_versions_write_fence BEFORE INSERT ON foundation.catalog_directory_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER catalog_items_write_fence BEFORE INSERT OR UPDATE ON foundation.catalog_items
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER catalog_item_versions_write_fence BEFORE INSERT ON foundation.catalog_item_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER catalog_fault_service_mappings_write_fence BEFORE INSERT OR UPDATE ON foundation.catalog_fault_service_mappings
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER catalog_price_series_write_fence BEFORE INSERT OR UPDATE ON foundation.catalog_price_series
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER catalog_price_versions_write_fence BEFORE INSERT ON foundation.catalog_price_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER catalog_price_periods_write_fence BEFORE INSERT OR UPDATE ON foundation.catalog_price_periods
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();

CREATE TRIGGER catalog_directory_entries_guard BEFORE INSERT OR UPDATE ON foundation.catalog_directory_entries
    FOR EACH ROW EXECUTE FUNCTION foundation.catalog_guard_identity();
CREATE TRIGGER catalog_items_guard BEFORE INSERT OR UPDATE ON foundation.catalog_items
    FOR EACH ROW EXECUTE FUNCTION foundation.catalog_guard_identity();
CREATE TRIGGER catalog_fault_service_mappings_guard BEFORE INSERT OR UPDATE ON foundation.catalog_fault_service_mappings
    FOR EACH ROW EXECUTE FUNCTION foundation.catalog_guard_mapping();
CREATE TRIGGER catalog_price_series_guard BEFORE INSERT OR UPDATE ON foundation.catalog_price_series
    FOR EACH ROW EXECUTE FUNCTION foundation.catalog_guard_price_series();
CREATE TRIGGER catalog_price_versions_basis_guard BEFORE INSERT ON foundation.catalog_price_versions
    FOR EACH ROW EXECUTE FUNCTION foundation.catalog_guard_price_basis();
CREATE TRIGGER catalog_price_periods_guard BEFORE INSERT OR UPDATE ON foundation.catalog_price_periods
    FOR EACH ROW EXECUTE FUNCTION foundation.catalog_guard_price_period();

CREATE CONSTRAINT TRIGGER catalog_directory_versions_chain_guard AFTER INSERT ON foundation.catalog_directory_versions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.catalog_guard_revision_chain();
CREATE CONSTRAINT TRIGGER catalog_item_versions_chain_guard AFTER INSERT ON foundation.catalog_item_versions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.catalog_guard_revision_chain();
CREATE CONSTRAINT TRIGGER catalog_price_periods_final_clock_guard AFTER INSERT OR UPDATE ON foundation.catalog_price_periods
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.catalog_guard_price_final_clock();

CREATE TRIGGER catalog_directory_entries_no_remove BEFORE DELETE OR TRUNCATE ON foundation.catalog_directory_entries
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER catalog_directory_versions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.catalog_directory_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER catalog_items_no_remove BEFORE DELETE OR TRUNCATE ON foundation.catalog_items
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER catalog_item_versions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.catalog_item_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER catalog_fault_service_mappings_no_remove BEFORE DELETE OR TRUNCATE ON foundation.catalog_fault_service_mappings
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER catalog_price_series_no_remove BEFORE DELETE OR TRUNCATE ON foundation.catalog_price_series
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER catalog_price_versions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.catalog_price_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER catalog_price_periods_no_remove BEFORE DELETE OR TRUNCATE ON foundation.catalog_price_periods
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();

REVOKE ALL ON FUNCTION foundation.catalog_lock_write(), foundation.catalog_reject_history_change(),
    foundation.catalog_guard_identity(), foundation.catalog_guard_revision_chain(), foundation.catalog_guard_mapping(),
    foundation.catalog_guard_price_series(), foundation.catalog_guard_price_basis(), foundation.catalog_guard_price_period(),
    foundation.catalog_guard_price_final_clock() FROM PUBLIC,fixlevelup_runtime;
REVOKE ALL ON foundation.catalog_directory_entries, foundation.catalog_directory_versions, foundation.catalog_items,
    foundation.catalog_item_versions, foundation.catalog_fault_service_mappings, foundation.catalog_price_series,
    foundation.catalog_price_versions, foundation.catalog_price_periods FROM PUBLIC,fixlevelup_runtime;

GRANT SELECT, INSERT(id,kind,code,category_id,brand_id), UPDATE(current_version_id,archived_at)
    ON foundation.catalog_directory_entries TO fixlevelup_runtime;
GRANT SELECT, INSERT(id,entry_id,version,title,description,reviewed_by)
    ON foundation.catalog_directory_versions TO fixlevelup_runtime;
GRANT SELECT, INSERT(id,kind,code,category_id,unit), UPDATE(current_version_id,archived_at)
    ON foundation.catalog_items TO fixlevelup_runtime;
GRANT SELECT, INSERT(id,item_id,kind,version,title,description,duration_minutes,technician_visible,public_visible,reviewed_by)
    ON foundation.catalog_item_versions TO fixlevelup_runtime;
GRANT SELECT, INSERT(id,category_id,fault_id,item_id), UPDATE(published_at,published_by,archived_at)
    ON foundation.catalog_fault_service_mappings TO fixlevelup_runtime;
GRANT SELECT, INSERT(id,city_id,item_id), UPDATE(row_version) ON foundation.catalog_price_series TO fixlevelup_runtime;
GRANT SELECT, INSERT(id,series_id,city_id,city_version_id,item_id,item_version_id,version,amount_minor,currency,
    zero_basis,source_ref,reviewed_by,valid_from,valid_until) ON foundation.catalog_price_versions TO fixlevelup_runtime;
GRANT SELECT, INSERT(price_version_id,series_id,city_id,item_id,valid_from,scheduled_until), UPDATE(closed_effective_until)
    ON foundation.catalog_price_periods TO fixlevelup_runtime;

COMMIT;
