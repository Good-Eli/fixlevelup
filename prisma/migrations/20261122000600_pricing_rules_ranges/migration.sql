BEGIN;
SET LOCAL search_path = pg_catalog;

-- btree_gist 1.8 and the catalog transaction fence are installed by 019.
CREATE FUNCTION foundation.pricing_policy_units_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    member record;
    members integer := 0;
BEGIN
    IF jsonb_typeof(value) <> 'object' THEN
        RETURN false;
    END IF;
    -- Validate the stored JSONB structure, not the source JSON token stream.
    FOR member IN SELECT key, val FROM jsonb_each(value) AS e(key,val) LOOP
        members := members + 1;
        IF members > 32 OR length(member.key) > 24
            OR member.key COLLATE "C" !~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'
            OR jsonb_typeof(member.val) <> 'number'
            OR member.val::text COLLATE "C" !~ '^[0-6]$' THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN members > 0;
END $$;

CREATE TABLE foundation.price_rules (
    id uuid PRIMARY KEY,
    code varchar(64) NOT NULL,
    kind varchar(16) NOT NULL,
    row_version integer NOT NULL DEFAULT 1,
    archived_at timestamptz(6),
    CONSTRAINT price_rules_code_check CHECK (code COLLATE "C" ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$' AND length(code) >= 2),
    CONSTRAINT price_rules_kind_check CHECK (kind IN ('EVENING','NIGHT','EXPRESS','SURCHARGE','DISCOUNT')),
    CONSTRAINT price_rules_row_version_check CHECK (row_version >= 1),
    CONSTRAINT price_rules_archive_check CHECK (archived_at IS NULL OR isfinite(archived_at)),
    CONSTRAINT price_rules_code_key UNIQUE (code),
    CONSTRAINT price_rules_id_kind_key UNIQUE (id,kind)
);

CREATE TABLE foundation.price_rule_series (
    id uuid PRIMARY KEY,
    city_id uuid NOT NULL,
    rule_id uuid NOT NULL,
    row_version integer NOT NULL DEFAULT 1,
    CONSTRAINT price_rule_series_row_version_check CHECK (row_version >= 1),
    CONSTRAINT price_rule_series_city_rule_key UNIQUE (city_id,rule_id),
    CONSTRAINT price_rule_series_identity_key UNIQUE (id,city_id,rule_id),
    CONSTRAINT price_rule_series_city_fkey FOREIGN KEY (city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT price_rule_series_rule_fkey FOREIGN KEY (rule_id)
        REFERENCES foundation.price_rules(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE foundation.price_rule_versions (
    id uuid PRIMARY KEY,
    series_id uuid NOT NULL,
    city_id uuid NOT NULL,
    city_version_id uuid NOT NULL,
    version integer NOT NULL,
    source_ref text NOT NULL,
    reviewed_by uuid NOT NULL,
    published_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    valid_from timestamptz(6) NOT NULL,
    valid_until timestamptz(6),
    rule_id uuid NOT NULL,
    kind varchar(16) NOT NULL,
    title text NOT NULL,
    method varchar(16) NOT NULL,
    base varchar(16) NOT NULL,
    currency varchar(3) NOT NULL,
    fixed_minor bigint,
    rate_bps integer,
    min_base bigint,
    max_base bigint,
    min_delta bigint,
    max_delta bigint,
    start_minute integer,
    end_minute integer,
    wraps_midnight boolean,
    scope_count integer NOT NULL,
    CONSTRAINT price_rule_versions_version_check CHECK (version >= 1),
    CONSTRAINT price_rule_versions_source_ref_check CHECK (length(source_ref) <= 200 AND source_ref ~ '[^[:space:]]'),
    CONSTRAINT price_rule_versions_valid_from_check CHECK (
        isfinite(valid_from) AND valid_from = date_trunc('milliseconds',valid_from,'UTC')),
    CONSTRAINT price_rule_versions_valid_until_check CHECK (valid_until IS NULL OR (
        isfinite(valid_until) AND valid_until = date_trunc('milliseconds',valid_until,'UTC') AND valid_until > valid_from)),
    CONSTRAINT price_rule_versions_title_check CHECK (length(title) BETWEEN 1 AND 160 AND title ~ '[^[:space:]]'),
    CONSTRAINT price_rule_versions_method_check CHECK (CASE method
        WHEN 'FIXED' THEN fixed_minor IS NOT NULL AND fixed_minor >= 0 AND rate_bps IS NULL
        WHEN 'RATE' THEN fixed_minor IS NULL AND rate_bps IS NOT NULL AND rate_bps BETWEEN 1 AND 10000
        ELSE false END),
    CONSTRAINT price_rule_versions_base_check CHECK (base IN ('WORKS','WORKS_AND_PARTS','ORDER_BASE')),
    CONSTRAINT price_rule_versions_currency_check CHECK (currency COLLATE "C" ~ '^[A-Z]{3}$'),
    CONSTRAINT price_rule_versions_base_bounds_check CHECK (
        (min_base IS NULL OR min_base >= 0) AND (max_base IS NULL OR max_base >= 0)
        AND (min_base IS NULL OR max_base IS NULL OR min_base <= max_base)),
    CONSTRAINT price_rule_versions_delta_bounds_check CHECK (
        (min_delta IS NULL OR min_delta >= 0) AND (max_delta IS NULL OR max_delta >= 0)
        AND (min_delta IS NULL OR max_delta IS NULL OR min_delta <= max_delta)),
    CONSTRAINT price_rule_versions_window_check CHECK (CASE WHEN kind IN ('EVENING','NIGHT') THEN
        start_minute IS NOT NULL AND end_minute IS NOT NULL AND wraps_midnight IS NOT NULL
        AND start_minute BETWEEN 0 AND 1439 AND end_minute BETWEEN 0 AND 1439
        AND start_minute <> end_minute AND wraps_midnight = (start_minute > end_minute)
        ELSE start_minute IS NULL AND end_minute IS NULL AND wraps_midnight IS NULL END),
    CONSTRAINT price_rule_versions_scope_count_check CHECK (scope_count BETWEEN 0 AND 32),
    CONSTRAINT price_rule_versions_series_version_key UNIQUE (series_id,version),
    CONSTRAINT price_rule_versions_identity_key UNIQUE (id,series_id,city_id),
    CONSTRAINT price_rule_versions_series_fkey FOREIGN KEY (series_id,city_id,rule_id)
        REFERENCES foundation.price_rule_series(id,city_id,rule_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT price_rule_versions_rule_fkey FOREIGN KEY (rule_id,kind)
        REFERENCES foundation.price_rules(id,kind) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT price_rule_versions_city_version_fkey FOREIGN KEY (city_id,city_version_id)
        REFERENCES foundation.service_city_versions(city_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT price_rule_versions_reviewer_fkey FOREIGN KEY (reviewed_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE foundation.price_rule_scopes (
    rule_version_id uuid NOT NULL,
    category_id uuid NOT NULL,
    category_kind varchar(16) NOT NULL DEFAULT 'CATEGORY',
    PRIMARY KEY (rule_version_id,category_id),
    CONSTRAINT price_rule_scopes_category_kind_check CHECK (category_kind = 'CATEGORY'),
    CONSTRAINT price_rule_scopes_version_fkey FOREIGN KEY (rule_version_id)
        REFERENCES foundation.price_rule_versions(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT price_rule_scopes_category_fkey FOREIGN KEY (category_id,category_kind)
        REFERENCES foundation.catalog_directory_entries(id,kind) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE foundation.pricing_policy_series (
    id uuid PRIMARY KEY,
    city_id uuid NOT NULL,
    row_version integer NOT NULL DEFAULT 1,
    CONSTRAINT pricing_policy_series_row_version_check CHECK (row_version >= 1),
    CONSTRAINT pricing_policy_series_city_key UNIQUE (city_id),
    CONSTRAINT pricing_policy_series_identity_key UNIQUE (id,city_id),
    CONSTRAINT pricing_policy_series_city_fkey FOREIGN KEY (city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE foundation.pricing_policy_versions (
    id uuid PRIMARY KEY,
    series_id uuid NOT NULL,
    city_id uuid NOT NULL,
    city_version_id uuid NOT NULL,
    version integer NOT NULL,
    source_ref text NOT NULL,
    reviewed_by uuid NOT NULL,
    published_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    valid_from timestamptz(6) NOT NULL,
    valid_until timestamptz(6),
    currency varchar(3) NOT NULL,
    tax_display text NOT NULL,
    rounding_mode varchar(16) NOT NULL,
    units jsonb NOT NULL,
    max_manual_delta_minor bigint NOT NULL,
    priority_count integer NOT NULL,
    compatibility_count integer NOT NULL,
    CONSTRAINT pricing_policy_versions_version_check CHECK (version >= 1),
    CONSTRAINT pricing_policy_versions_source_ref_check CHECK (length(source_ref) <= 200 AND source_ref ~ '[^[:space:]]'),
    CONSTRAINT pricing_policy_versions_valid_from_check CHECK (
        isfinite(valid_from) AND valid_from = date_trunc('milliseconds',valid_from,'UTC')),
    CONSTRAINT pricing_policy_versions_valid_until_check CHECK (valid_until IS NULL OR (
        isfinite(valid_until) AND valid_until = date_trunc('milliseconds',valid_until,'UTC') AND valid_until > valid_from)),
    CONSTRAINT pricing_policy_versions_currency_check CHECK (currency COLLATE "C" ~ '^[A-Z]{3}$'),
    CONSTRAINT pricing_policy_versions_tax_display_check CHECK (length(tax_display) <= 200 AND tax_display ~ '[^[:space:]]'),
    CONSTRAINT pricing_policy_versions_rounding_mode_check CHECK (rounding_mode IN ('HALF_UP','DOWN')),
    CONSTRAINT pricing_policy_versions_units_check CHECK (foundation.pricing_policy_units_valid(units)),
    CONSTRAINT pricing_policy_versions_max_manual_delta_check CHECK (max_manual_delta_minor >= 0),
    CONSTRAINT pricing_policy_versions_priority_count_check CHECK (priority_count BETWEEN 0 AND 64),
    CONSTRAINT pricing_policy_versions_compatibility_count_check CHECK (compatibility_count BETWEEN 0 AND 128),
    CONSTRAINT pricing_policy_versions_series_version_key UNIQUE (series_id,version),
    CONSTRAINT pricing_policy_versions_identity_key UNIQUE (id,series_id,city_id),
    CONSTRAINT pricing_policy_versions_series_fkey FOREIGN KEY (series_id,city_id)
        REFERENCES foundation.pricing_policy_series(id,city_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT pricing_policy_versions_city_version_fkey FOREIGN KEY (city_id,city_version_id)
        REFERENCES foundation.service_city_versions(city_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT pricing_policy_versions_reviewer_fkey FOREIGN KEY (reviewed_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE foundation.price_rule_priorities (
    policy_version_id uuid NOT NULL,
    rule_id uuid NOT NULL,
    priority integer NOT NULL,
    PRIMARY KEY (policy_version_id,rule_id),
    CONSTRAINT price_rule_priorities_priority_check CHECK (priority BETWEEN 0 AND 1000000),
    CONSTRAINT price_rule_priorities_version_fkey FOREIGN KEY (policy_version_id)
        REFERENCES foundation.pricing_policy_versions(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT price_rule_priorities_rule_fkey FOREIGN KEY (rule_id)
        REFERENCES foundation.price_rules(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE foundation.price_rule_compatibilities (
    policy_version_id uuid NOT NULL,
    left_rule_id uuid NOT NULL,
    right_rule_id uuid NOT NULL,
    PRIMARY KEY (policy_version_id,left_rule_id,right_rule_id),
    CONSTRAINT price_rule_compatibilities_order_check CHECK (left_rule_id < right_rule_id),
    CONSTRAINT price_rule_compatibilities_version_fkey FOREIGN KEY (policy_version_id)
        REFERENCES foundation.pricing_policy_versions(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT price_rule_compatibilities_left_rule_fkey FOREIGN KEY (left_rule_id)
        REFERENCES foundation.price_rules(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT price_rule_compatibilities_right_rule_fkey FOREIGN KEY (right_rule_id)
        REFERENCES foundation.price_rules(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE foundation.public_price_estimate_series (
    id uuid PRIMARY KEY,
    city_id uuid NOT NULL,
    category_id uuid NOT NULL,
    category_kind varchar(16) NOT NULL DEFAULT 'CATEGORY',
    code varchar(64) NOT NULL,
    row_version integer NOT NULL DEFAULT 1,
    archived_at timestamptz(6),
    CONSTRAINT public_price_estimate_series_category_kind_check CHECK (category_kind = 'CATEGORY'),
    CONSTRAINT public_price_estimate_series_code_check CHECK (
        code COLLATE "C" ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$' AND length(code) >= 2),
    CONSTRAINT public_price_estimate_series_row_version_check CHECK (row_version >= 1),
    CONSTRAINT public_price_estimate_series_archive_check CHECK (archived_at IS NULL OR isfinite(archived_at)),
    CONSTRAINT public_price_estimate_series_city_category_code_key UNIQUE (city_id,category_id,code),
    CONSTRAINT public_price_estimate_series_identity_key UNIQUE (id,city_id),
    CONSTRAINT public_price_estimate_series_city_fkey FOREIGN KEY (city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT public_price_estimate_series_category_fkey FOREIGN KEY (category_id,category_kind)
        REFERENCES foundation.catalog_directory_entries(id,kind) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE foundation.public_price_estimates (
    id uuid PRIMARY KEY,
    series_id uuid NOT NULL,
    city_id uuid NOT NULL,
    city_version_id uuid NOT NULL,
    version integer NOT NULL,
    source_ref text NOT NULL,
    reviewed_by uuid NOT NULL,
    published_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    valid_from timestamptz(6) NOT NULL,
    valid_until timestamptz(6),
    title text NOT NULL,
    currency varchar(3) NOT NULL,
    min_minor bigint NOT NULL,
    max_minor bigint NOT NULL,
    conditions text,
    disclaimer text NOT NULL,
    CONSTRAINT public_price_estimates_version_check CHECK (version >= 1),
    CONSTRAINT public_price_estimates_source_ref_check CHECK (length(source_ref) <= 200 AND source_ref ~ '[^[:space:]]'),
    CONSTRAINT public_price_estimates_valid_from_check CHECK (
        isfinite(valid_from) AND valid_from = date_trunc('milliseconds',valid_from,'UTC')),
    CONSTRAINT public_price_estimates_valid_until_check CHECK (valid_until IS NULL OR (
        isfinite(valid_until) AND valid_until = date_trunc('milliseconds',valid_until,'UTC') AND valid_until > valid_from)),
    CONSTRAINT public_price_estimates_title_check CHECK (length(title) BETWEEN 1 AND 160 AND title ~ '[^[:space:]]'),
    CONSTRAINT public_price_estimates_currency_check CHECK (currency COLLATE "C" ~ '^[A-Z]{3}$'),
    CONSTRAINT public_price_estimates_range_check CHECK (min_minor >= 0 AND max_minor >= min_minor),
    CONSTRAINT public_price_estimates_conditions_check CHECK (conditions IS NULL OR length(conditions) <= 1000),
    CONSTRAINT public_price_estimates_disclaimer_check CHECK (length(disclaimer) <= 500 AND disclaimer ~ '[^[:space:]]'),
    CONSTRAINT public_price_estimates_series_version_key UNIQUE (series_id,version),
    CONSTRAINT public_price_estimates_identity_key UNIQUE (id,series_id,city_id),
    CONSTRAINT public_price_estimates_series_fkey FOREIGN KEY (series_id,city_id)
        REFERENCES foundation.public_price_estimate_series(id,city_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT public_price_estimates_city_version_fkey FOREIGN KEY (city_id,city_version_id)
        REFERENCES foundation.service_city_versions(city_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT public_price_estimates_reviewer_fkey FOREIGN KEY (reviewed_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);

CREATE TABLE foundation.price_rule_periods (
    version_id uuid PRIMARY KEY,
    series_id uuid NOT NULL,
    city_id uuid NOT NULL,
    valid_from timestamptz(6) NOT NULL,
    scheduled_until timestamptz(6),
    closed_effective_until timestamptz(6),
    CONSTRAINT price_rule_periods_valid_from_check CHECK (
        isfinite(valid_from) AND valid_from = date_trunc('milliseconds',valid_from,'UTC')),
    CONSTRAINT price_rule_periods_scheduled_until_check CHECK (scheduled_until IS NULL OR (
        isfinite(scheduled_until) AND scheduled_until = date_trunc('milliseconds',scheduled_until,'UTC')
        AND scheduled_until > valid_from)),
    CONSTRAINT price_rule_periods_closed_until_check CHECK (closed_effective_until IS NULL OR (
        isfinite(closed_effective_until) AND closed_effective_until = date_trunc('milliseconds',closed_effective_until,'UTC')
        AND closed_effective_until > valid_from AND (scheduled_until IS NULL OR closed_effective_until < scheduled_until))),
    CONSTRAINT price_rule_periods_version_fkey FOREIGN KEY (version_id,series_id,city_id)
        REFERENCES foundation.price_rule_versions(id,series_id,city_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT price_rule_periods_no_overlap EXCLUDE USING gist (
        city_id foundation.gist_uuid_ops WITH =,
        series_id foundation.gist_uuid_ops WITH =,
        tstzrange(valid_from,coalesce(closed_effective_until,scheduled_until),'[)') WITH &&
    )
);
ALTER TABLE foundation.price_rule_versions ADD CONSTRAINT price_rule_versions_period_fkey
    FOREIGN KEY (id) REFERENCES foundation.price_rule_periods(version_id)
    ON DELETE NO ACTION ON UPDATE NO ACTION DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE foundation.pricing_policy_periods (
    version_id uuid PRIMARY KEY,
    series_id uuid NOT NULL,
    city_id uuid NOT NULL,
    valid_from timestamptz(6) NOT NULL,
    scheduled_until timestamptz(6),
    closed_effective_until timestamptz(6),
    CONSTRAINT pricing_policy_periods_valid_from_check CHECK (
        isfinite(valid_from) AND valid_from = date_trunc('milliseconds',valid_from,'UTC')),
    CONSTRAINT pricing_policy_periods_scheduled_until_check CHECK (scheduled_until IS NULL OR (
        isfinite(scheduled_until) AND scheduled_until = date_trunc('milliseconds',scheduled_until,'UTC')
        AND scheduled_until > valid_from)),
    CONSTRAINT pricing_policy_periods_closed_until_check CHECK (closed_effective_until IS NULL OR (
        isfinite(closed_effective_until) AND closed_effective_until = date_trunc('milliseconds',closed_effective_until,'UTC')
        AND closed_effective_until > valid_from AND (scheduled_until IS NULL OR closed_effective_until < scheduled_until))),
    CONSTRAINT pricing_policy_periods_version_fkey FOREIGN KEY (version_id,series_id,city_id)
        REFERENCES foundation.pricing_policy_versions(id,series_id,city_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT pricing_policy_periods_no_overlap EXCLUDE USING gist (
        city_id foundation.gist_uuid_ops WITH =,
        series_id foundation.gist_uuid_ops WITH =,
        tstzrange(valid_from,coalesce(closed_effective_until,scheduled_until),'[)') WITH &&
    )
);
ALTER TABLE foundation.pricing_policy_versions ADD CONSTRAINT pricing_policy_versions_period_fkey
    FOREIGN KEY (id) REFERENCES foundation.pricing_policy_periods(version_id)
    ON DELETE NO ACTION ON UPDATE NO ACTION DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE foundation.public_price_estimate_periods (
    version_id uuid PRIMARY KEY,
    series_id uuid NOT NULL,
    city_id uuid NOT NULL,
    valid_from timestamptz(6) NOT NULL,
    scheduled_until timestamptz(6),
    closed_effective_until timestamptz(6),
    CONSTRAINT public_price_estimate_periods_valid_from_check CHECK (
        isfinite(valid_from) AND valid_from = date_trunc('milliseconds',valid_from,'UTC')),
    CONSTRAINT public_price_estimate_periods_scheduled_until_check CHECK (scheduled_until IS NULL OR (
        isfinite(scheduled_until) AND scheduled_until = date_trunc('milliseconds',scheduled_until,'UTC')
        AND scheduled_until > valid_from)),
    CONSTRAINT public_price_estimate_periods_closed_until_check CHECK (closed_effective_until IS NULL OR (
        isfinite(closed_effective_until) AND closed_effective_until = date_trunc('milliseconds',closed_effective_until,'UTC')
        AND closed_effective_until > valid_from AND (scheduled_until IS NULL OR closed_effective_until < scheduled_until))),
    CONSTRAINT public_price_estimate_periods_version_fkey FOREIGN KEY (version_id,series_id,city_id)
        REFERENCES foundation.public_price_estimates(id,series_id,city_id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT public_price_estimate_periods_no_overlap EXCLUDE USING gist (
        city_id foundation.gist_uuid_ops WITH =,
        series_id foundation.gist_uuid_ops WITH =,
        tstzrange(valid_from,coalesce(closed_effective_until,scheduled_until),'[)') WITH &&
    )
);
ALTER TABLE foundation.public_price_estimates ADD CONSTRAINT public_price_estimates_period_fkey
    FOREIGN KEY (id) REFERENCES foundation.public_price_estimate_periods(version_id)
    ON DELETE NO ACTION ON UPDATE NO ACTION DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION foundation.pricing_guard_identity() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.row_version IS DISTINCT FROM 1 OR NEW.archived_at IS NOT NULL THEN
            RAISE EXCEPTION 'Pricing identity starts unarchived at row version 1'
                USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_identity_guard';
        END IF;
        IF TG_TABLE_NAME = 'public_price_estimate_series' THEN
            IF EXISTS (SELECT FROM foundation.catalog_directory_entries
                WHERE (id,kind) = (NEW.category_id,NEW.category_kind)
                    AND (archived_at IS NOT NULL OR current_version_id IS NULL)) THEN
                RAISE EXCEPTION 'Estimate identity requires a live published category'
                    USING ERRCODE = '23514', CONSTRAINT = 'public_price_estimate_series_category_basis_guard';
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.archived_at IS NOT NULL OR ROW(NEW.id,NEW.code) IS DISTINCT FROM ROW(OLD.id,OLD.code) THEN
        RAISE EXCEPTION 'Archived pricing identities and stable fields cannot change'
            USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_identity_guard';
    END IF;
    IF TG_TABLE_NAME = 'price_rules' THEN
        IF NEW.kind IS DISTINCT FROM OLD.kind OR NEW.archived_at IS NULL THEN
            RAISE EXCEPTION 'Only terminal archive is allowed for a price rule'
                USING ERRCODE = '23514', CONSTRAINT = 'price_rules_identity_guard';
        END IF;
    ELSIF ROW(NEW.city_id,NEW.category_id,NEW.category_kind) IS DISTINCT FROM ROW(OLD.city_id,OLD.category_id,OLD.category_kind) THEN
        RAISE EXCEPTION 'Estimate city and category are immutable'
            USING ERRCODE = '23514', CONSTRAINT = 'public_price_estimate_series_identity_guard';
    END IF;

    IF NEW.archived_at IS NOT NULL THEN
        IF NEW.row_version IS DISTINCT FROM OLD.row_version THEN
            RAISE EXCEPTION 'Archive advances the pricing identity row version automatically'
                USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_identity_guard';
        END IF;
        NEW.row_version := OLD.row_version + 1;
    ELSIF NEW.row_version IS DISTINCT FROM OLD.row_version + 1 THEN
        RAISE EXCEPTION 'Only a single row version advance is allowed'
            USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_identity_guard';
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION foundation.pricing_guard_series() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.row_version IS DISTINCT FROM 1 THEN
            RAISE EXCEPTION 'Pricing series starts at row version 1'
                USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_sequence_guard';
        END IF;
        IF TG_TABLE_NAME = 'price_rule_series' THEN
            IF EXISTS (SELECT FROM foundation.price_rules WHERE id = NEW.rule_id AND archived_at IS NOT NULL) THEN
                RAISE EXCEPTION 'Archived rules cannot start a new series'
                    USING ERRCODE = '23514', CONSTRAINT = 'price_rule_series_rule_basis_guard';
            END IF;
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.id,NEW.city_id) IS DISTINCT FROM ROW(OLD.id,OLD.city_id)
        OR NEW.row_version IS DISTINCT FROM OLD.row_version + 1 THEN
        RAISE EXCEPTION 'Only a single row version advance is allowed on a pricing series'
            USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_sequence_guard';
    END IF;
    IF TG_TABLE_NAME = 'price_rule_series' THEN
        IF NEW.rule_id IS DISTINCT FROM OLD.rule_id THEN
            RAISE EXCEPTION 'A pricing series cannot switch rules'
                USING ERRCODE = '23514', CONSTRAINT = 'price_rule_series_sequence_guard';
        END IF;
    END IF;
    RETURN NEW;
END $$;

-- Like 019, the fence precedes the city row lock even for direct INSERT. A
-- prepared city need not be ACTIVE, but must have the exact current review.
CREATE FUNCTION foundation.pricing_guard_publish_basis() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF NOT EXISTS (SELECT FROM foundation.service_cities
        WHERE id = NEW.city_id AND current_version_id = NEW.city_version_id FOR SHARE) THEN
        RAISE EXCEPTION 'Pricing publication requires the current city version'
            USING ERRCODE = '23503', CONSTRAINT = TG_TABLE_NAME || '_city_basis_guard';
    END IF;
    IF TG_TABLE_NAME = 'price_rule_versions' THEN
        IF EXISTS (SELECT FROM foundation.price_rules WHERE id = NEW.rule_id AND archived_at IS NOT NULL) THEN
            RAISE EXCEPTION 'Archived rules cannot publish a new version'
                USING ERRCODE = '23514', CONSTRAINT = 'price_rule_versions_rule_basis_guard';
        END IF;
    ELSIF TG_TABLE_NAME = 'public_price_estimates' THEN
        IF EXISTS (SELECT FROM foundation.public_price_estimate_series
            WHERE (id,city_id) = (NEW.series_id,NEW.city_id) AND archived_at IS NOT NULL) THEN
            RAISE EXCEPTION 'Archived estimate series cannot publish a new version'
                USING ERRCODE = '23514', CONSTRAINT = 'public_price_estimates_series_basis_guard';
        END IF;
        IF EXISTS (SELECT FROM foundation.public_price_estimate_series s
            JOIN foundation.catalog_directory_entries c ON (c.id,c.kind) = (s.category_id,s.category_kind)
            WHERE (s.id,s.city_id) = (NEW.series_id,NEW.city_id)
                AND (c.archived_at IS NOT NULL OR c.current_version_id IS NULL)) THEN
            RAISE EXCEPTION 'Estimate publication requires a live published category'
                USING ERRCODE = '23514', CONSTRAINT = 'public_price_estimates_category_basis_guard';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION foundation.pricing_guard_child_basis() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF TG_TABLE_NAME = 'price_rule_scopes' THEN
        IF EXISTS (SELECT FROM foundation.catalog_directory_entries
            WHERE (id,kind) = (NEW.category_id,NEW.category_kind)
                AND (archived_at IS NOT NULL OR current_version_id IS NULL)) THEN
            RAISE EXCEPTION 'Rule scope requires a live published category'
                USING ERRCODE = '23514', CONSTRAINT = 'price_rule_scopes_category_basis_guard';
        END IF;
    ELSIF TG_TABLE_NAME = 'price_rule_priorities' THEN
        IF EXISTS (SELECT FROM foundation.price_rules WHERE id = NEW.rule_id AND archived_at IS NOT NULL) THEN
            RAISE EXCEPTION 'A new priority cannot reference an archived rule'
                USING ERRCODE = '23514', CONSTRAINT = 'price_rule_priorities_rule_basis_guard';
        END IF;
    ELSE
        IF EXISTS (SELECT FROM foundation.price_rules
            WHERE id IN (NEW.left_rule_id,NEW.right_rule_id) AND archived_at IS NOT NULL) THEN
            RAISE EXCEPTION 'A new compatibility cannot reference an archived rule'
                USING ERRCODE = '23514', CONSTRAINT = 'price_rule_compatibilities_rule_basis_guard';
        END IF;
    END IF;
    RETURN NEW;
END $$;

-- Parent INSERT ensures a complete publication even when no children were
-- attempted. Child INSERT also checks the count, preventing a later attachment
-- to a previously committed version. Both run under the shared catalog fence.
CREATE FUNCTION foundation.pricing_guard_child_counts() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    owner_id uuid;
    expected_count integer;
    actual_count integer;
BEGIN
    IF TG_TABLE_NAME IN ('price_rule_versions','price_rule_scopes') THEN
        IF TG_TABLE_NAME = 'price_rule_versions' THEN
            owner_id := NEW.id;
        ELSE
            owner_id := NEW.rule_version_id;
        END IF;
        SELECT scope_count INTO expected_count FROM foundation.price_rule_versions WHERE id = owner_id;
        SELECT count(*) INTO actual_count FROM (
            SELECT 1 FROM foundation.price_rule_scopes WHERE rule_version_id = owner_id LIMIT 33
        ) AS children;
        IF expected_count IS DISTINCT FROM actual_count THEN
            RAISE EXCEPTION 'Reviewed rule scope count must match its children'
                USING ERRCODE = '23514', CONSTRAINT = 'price_rule_scopes_count_guard';
        END IF;
        RETURN NULL;
    END IF;

    IF TG_TABLE_NAME = 'pricing_policy_versions' THEN
        owner_id := NEW.id;
    ELSE
        owner_id := NEW.policy_version_id;
    END IF;
    SELECT priority_count INTO expected_count FROM foundation.pricing_policy_versions WHERE id = owner_id;
    SELECT count(*) INTO actual_count FROM (
        SELECT 1 FROM foundation.price_rule_priorities WHERE policy_version_id = owner_id LIMIT 65
    ) AS children;
    IF expected_count IS DISTINCT FROM actual_count THEN
        RAISE EXCEPTION 'Reviewed policy priority count must match its children'
            USING ERRCODE = '23514', CONSTRAINT = 'price_rule_priorities_count_guard';
    END IF;
    SELECT compatibility_count INTO expected_count FROM foundation.pricing_policy_versions WHERE id = owner_id;
    SELECT count(*) INTO actual_count FROM (
        SELECT 1 FROM foundation.price_rule_compatibilities WHERE policy_version_id = owner_id LIMIT 129
    ) AS children;
    IF expected_count IS DISTINCT FROM actual_count THEN
        RAISE EXCEPTION 'Reviewed policy compatibility count must match its children'
            USING ERRCODE = '23514', CONSTRAINT = 'price_rule_compatibilities_count_guard';
    END IF;
    RETURN NULL;
END $$;

CREATE FUNCTION foundation.pricing_guard_period() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    db_now timestamptz;
    projects_review boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF TG_TABLE_NAME = 'price_rule_periods' THEN
            SELECT EXISTS (SELECT FROM foundation.price_rule_versions v
                WHERE (v.id,v.series_id,v.city_id) = (NEW.version_id,NEW.series_id,NEW.city_id)
                    AND v.valid_from = NEW.valid_from AND v.valid_until IS NOT DISTINCT FROM NEW.scheduled_until)
                INTO projects_review;
        ELSIF TG_TABLE_NAME = 'pricing_policy_periods' THEN
            SELECT EXISTS (SELECT FROM foundation.pricing_policy_versions v
                WHERE (v.id,v.series_id,v.city_id) = (NEW.version_id,NEW.series_id,NEW.city_id)
                    AND v.valid_from = NEW.valid_from AND v.valid_until IS NOT DISTINCT FROM NEW.scheduled_until)
                INTO projects_review;
        ELSE
            SELECT EXISTS (SELECT FROM foundation.public_price_estimates v
                WHERE (v.id,v.series_id,v.city_id) = (NEW.version_id,NEW.series_id,NEW.city_id)
                    AND v.valid_from = NEW.valid_from AND v.valid_until IS NOT DISTINCT FROM NEW.scheduled_until)
                INTO projects_review;
        END IF;
        IF NEW.closed_effective_until IS NOT NULL OR NOT projects_review THEN
            RAISE EXCEPTION 'Pricing period must start open and project the exact reviewed bounds'
                USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_projection_guard';
        END IF;
        db_now := date_trunc('milliseconds',clock_timestamp(),'UTC');
        IF NEW.valid_from <= db_now THEN
            RAISE EXCEPTION 'Pricing period start must be in the future'
                USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_future_start_guard';
        END IF;
    ELSE
        IF ROW(NEW.version_id,NEW.series_id,NEW.city_id,NEW.valid_from,NEW.scheduled_until)
            IS DISTINCT FROM ROW(OLD.version_id,OLD.series_id,OLD.city_id,OLD.valid_from,OLD.scheduled_until) THEN
            RAISE EXCEPTION 'Pricing period identity and schedule are immutable'
                USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_projection_guard';
        END IF;
        db_now := date_trunc('milliseconds',clock_timestamp(),'UTC');
        IF OLD.closed_effective_until IS NOT NULL OR NEW.closed_effective_until IS NULL
            OR OLD.valid_from > db_now OR (OLD.scheduled_until IS NOT NULL AND OLD.scheduled_until <= db_now)
            OR NEW.closed_effective_until <= db_now
            OR (OLD.scheduled_until IS NOT NULL AND NEW.closed_effective_until >= OLD.scheduled_until) THEN
            RAISE EXCEPTION 'Only an effective open pricing period can be closed once before its scheduled end'
                USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_close_guard';
        END IF;
    END IF;
    RETURN NEW;
END $$;

-- Recheck at deferred-constraint processing: a wait anywhere after the first
-- clock check may consume the remaining time to publish or close a period.
CREATE FUNCTION foundation.pricing_guard_final_clock() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    boundary timestamptz;
BEGIN
    boundary := CASE WHEN TG_OP = 'INSERT' THEN NEW.valid_from ELSE NEW.closed_effective_until END;
    IF boundary <= date_trunc('milliseconds',clock_timestamp(),'UTC') THEN
        RAISE EXCEPTION 'Pricing boundary elapsed before transaction end'
            USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_final_clock_guard';
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER price_rules_write_fence BEFORE INSERT OR UPDATE ON foundation.price_rules
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER price_rule_series_write_fence BEFORE INSERT OR UPDATE ON foundation.price_rule_series
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER price_rule_versions_write_fence BEFORE INSERT ON foundation.price_rule_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER price_rule_scopes_write_fence BEFORE INSERT ON foundation.price_rule_scopes
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER pricing_policy_series_write_fence BEFORE INSERT OR UPDATE ON foundation.pricing_policy_series
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER pricing_policy_versions_write_fence BEFORE INSERT ON foundation.pricing_policy_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER price_rule_priorities_write_fence BEFORE INSERT ON foundation.price_rule_priorities
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER price_rule_compatibilities_write_fence BEFORE INSERT ON foundation.price_rule_compatibilities
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER public_price_estimate_series_write_fence BEFORE INSERT OR UPDATE ON foundation.public_price_estimate_series
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER public_price_estimates_write_fence BEFORE INSERT ON foundation.public_price_estimates
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER price_rule_periods_write_fence BEFORE INSERT OR UPDATE ON foundation.price_rule_periods
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER pricing_policy_periods_write_fence BEFORE INSERT OR UPDATE ON foundation.pricing_policy_periods
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER public_price_estimate_periods_write_fence BEFORE INSERT OR UPDATE ON foundation.public_price_estimate_periods
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();

CREATE TRIGGER price_rules_identity_guard BEFORE INSERT OR UPDATE ON foundation.price_rules
    FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_identity();
CREATE TRIGGER public_price_estimate_series_identity_guard BEFORE INSERT OR UPDATE ON foundation.public_price_estimate_series
    FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_identity();
CREATE TRIGGER price_rule_series_sequence_guard BEFORE INSERT OR UPDATE ON foundation.price_rule_series
    FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_series();
CREATE TRIGGER pricing_policy_series_sequence_guard BEFORE INSERT OR UPDATE ON foundation.pricing_policy_series
    FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_series();
CREATE TRIGGER price_rule_versions_basis_guard BEFORE INSERT ON foundation.price_rule_versions
    FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_publish_basis();
CREATE TRIGGER pricing_policy_versions_basis_guard BEFORE INSERT ON foundation.pricing_policy_versions
    FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_publish_basis();
CREATE TRIGGER public_price_estimates_basis_guard BEFORE INSERT ON foundation.public_price_estimates
    FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_publish_basis();
CREATE TRIGGER price_rule_scopes_category_basis_guard BEFORE INSERT ON foundation.price_rule_scopes
    FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_child_basis();
CREATE TRIGGER price_rule_priorities_rule_basis_guard BEFORE INSERT ON foundation.price_rule_priorities
    FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_child_basis();
CREATE TRIGGER price_rule_compatibilities_rule_basis_guard BEFORE INSERT ON foundation.price_rule_compatibilities
    FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_child_basis();
CREATE TRIGGER price_rule_periods_guard BEFORE INSERT OR UPDATE ON foundation.price_rule_periods
    FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_period();
CREATE TRIGGER pricing_policy_periods_guard BEFORE INSERT OR UPDATE ON foundation.pricing_policy_periods
    FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_period();
CREATE TRIGGER public_price_estimate_periods_guard BEFORE INSERT OR UPDATE ON foundation.public_price_estimate_periods
    FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_period();

CREATE CONSTRAINT TRIGGER price_rule_versions_counts_guard AFTER INSERT ON foundation.price_rule_versions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_child_counts();
CREATE CONSTRAINT TRIGGER price_rule_scopes_count_guard AFTER INSERT ON foundation.price_rule_scopes
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_child_counts();
CREATE CONSTRAINT TRIGGER pricing_policy_versions_counts_guard AFTER INSERT ON foundation.pricing_policy_versions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_child_counts();
CREATE CONSTRAINT TRIGGER price_rule_priorities_count_guard AFTER INSERT ON foundation.price_rule_priorities
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_child_counts();
CREATE CONSTRAINT TRIGGER price_rule_compatibilities_count_guard AFTER INSERT ON foundation.price_rule_compatibilities
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_child_counts();
CREATE CONSTRAINT TRIGGER price_rule_periods_final_clock_guard AFTER INSERT OR UPDATE ON foundation.price_rule_periods
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_final_clock();
CREATE CONSTRAINT TRIGGER pricing_policy_periods_final_clock_guard AFTER INSERT OR UPDATE ON foundation.pricing_policy_periods
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_final_clock();
CREATE CONSTRAINT TRIGGER public_price_estimate_periods_final_clock_guard AFTER INSERT OR UPDATE ON foundation.public_price_estimate_periods
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.pricing_guard_final_clock();

CREATE TRIGGER price_rules_no_remove BEFORE DELETE OR TRUNCATE ON foundation.price_rules
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER price_rule_series_no_remove BEFORE DELETE OR TRUNCATE ON foundation.price_rule_series
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER price_rule_versions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.price_rule_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER price_rule_scopes_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.price_rule_scopes
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER pricing_policy_series_no_remove BEFORE DELETE OR TRUNCATE ON foundation.pricing_policy_series
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER pricing_policy_versions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.pricing_policy_versions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER price_rule_priorities_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.price_rule_priorities
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER price_rule_compatibilities_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.price_rule_compatibilities
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER public_price_estimate_series_no_remove BEFORE DELETE OR TRUNCATE ON foundation.public_price_estimate_series
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER public_price_estimates_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.public_price_estimates
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER price_rule_periods_no_remove BEFORE DELETE OR TRUNCATE ON foundation.price_rule_periods
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER pricing_policy_periods_no_remove BEFORE DELETE OR TRUNCATE ON foundation.pricing_policy_periods
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER public_price_estimate_periods_no_remove BEFORE DELETE OR TRUNCATE ON foundation.public_price_estimate_periods
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();

REVOKE ALL ON FUNCTION foundation.pricing_policy_units_valid(jsonb), foundation.pricing_guard_identity(),
    foundation.pricing_guard_series(), foundation.pricing_guard_publish_basis(), foundation.pricing_guard_child_basis(),
    foundation.pricing_guard_child_counts(), foundation.pricing_guard_period(), foundation.pricing_guard_final_clock()
    FROM PUBLIC,fixlevelup_runtime;
-- Only the CHECK expression calls a helper as runtime; trigger functions need
-- no runtime EXECUTE grant (trigger binding is authorized at creation).
GRANT EXECUTE ON FUNCTION foundation.pricing_policy_units_valid(jsonb) TO fixlevelup_runtime;
REVOKE ALL ON foundation.price_rules, foundation.price_rule_series, foundation.price_rule_versions,
    foundation.price_rule_scopes, foundation.pricing_policy_series, foundation.pricing_policy_versions,
    foundation.price_rule_priorities, foundation.price_rule_compatibilities, foundation.public_price_estimate_series,
    foundation.public_price_estimates, foundation.price_rule_periods, foundation.pricing_policy_periods,
    foundation.public_price_estimate_periods FROM PUBLIC,fixlevelup_runtime;

GRANT SELECT, INSERT(id,code,kind), UPDATE(archived_at) ON foundation.price_rules TO fixlevelup_runtime;
GRANT SELECT, INSERT(id,city_id,rule_id), UPDATE(row_version) ON foundation.price_rule_series TO fixlevelup_runtime;
GRANT SELECT, INSERT(id,series_id,city_id,city_version_id,version,source_ref,reviewed_by,valid_from,valid_until,
    rule_id,kind,title,method,base,currency,fixed_minor,rate_bps,min_base,max_base,min_delta,max_delta,start_minute,
    end_minute,wraps_midnight,scope_count) ON foundation.price_rule_versions TO fixlevelup_runtime;
GRANT SELECT, INSERT(rule_version_id,category_id) ON foundation.price_rule_scopes TO fixlevelup_runtime;
GRANT SELECT, INSERT(id,city_id), UPDATE(row_version) ON foundation.pricing_policy_series TO fixlevelup_runtime;
GRANT SELECT, INSERT(id,series_id,city_id,city_version_id,version,source_ref,reviewed_by,valid_from,valid_until,
    currency,tax_display,rounding_mode,units,max_manual_delta_minor,priority_count,compatibility_count)
    ON foundation.pricing_policy_versions TO fixlevelup_runtime;
GRANT SELECT, INSERT(policy_version_id,rule_id,priority) ON foundation.price_rule_priorities TO fixlevelup_runtime;
GRANT SELECT, INSERT(policy_version_id,left_rule_id,right_rule_id) ON foundation.price_rule_compatibilities TO fixlevelup_runtime;
GRANT SELECT, INSERT(id,city_id,category_id,code), UPDATE(row_version,archived_at)
    ON foundation.public_price_estimate_series TO fixlevelup_runtime;
GRANT SELECT, INSERT(id,series_id,city_id,city_version_id,version,source_ref,reviewed_by,valid_from,valid_until,
    title,currency,min_minor,max_minor,conditions,disclaimer) ON foundation.public_price_estimates TO fixlevelup_runtime;
GRANT SELECT, INSERT(version_id,series_id,city_id,valid_from,scheduled_until), UPDATE(closed_effective_until)
    ON foundation.price_rule_periods, foundation.pricing_policy_periods, foundation.public_price_estimate_periods TO fixlevelup_runtime;

COMMIT;
