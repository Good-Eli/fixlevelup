BEGIN;
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;
SET LOCAL search_path = pg_catalog;

-- P04-03 (021): inert capability registry only. Serialize with existing policy
-- writers, and fail fast on a relation-lock inversion during cutover.
SELECT pg_advisory_xact_lock(hashtextextended('fixlevelup:admin-invariant',0));
LOCK TABLE foundation.permissions IN SHARE ROW EXCLUSIVE MODE NOWAIT;
LOCK TABLE foundation.role_permissions IN ACCESS EXCLUSIVE MODE NOWAIT;

DO $$
BEGIN
    IF EXISTS (SELECT FROM foundation.permissions WHERE code IN (
        'catalog.read','catalog.manage','pricing.rules.read','pricing.rules.manage','pricing.read','pricing.manage',
        'content.externalreviews.read','content.externalreviews.manage','content.externalreviews.publish')) THEN
        RAISE EXCEPTION 'P04 management catalog must be empty before migration 021' USING ERRCODE = '23514';
    END IF;
END $$;

INSERT INTO foundation.permissions(code,module,description,protected,active)
SELECT code,split_part(code,'.',1),description,false,true
FROM (VALUES
    ('catalog.read','Просмотр каталога и истории'),
    ('catalog.manage','Управление каталогом'),
    ('pricing.rules.read','Просмотр определений ценовых правил'),
    ('pricing.rules.manage','Управление определениями ценовых правил'),
    ('pricing.read','Просмотр городских цен и истории'),
    ('pricing.manage','Управление городскими ценами'),
    ('content.externalreviews.read','Просмотр ручных записей Avito и истории'),
    ('content.externalreviews.manage','Создание и архивирование ручных записей Avito'),
    ('content.externalreviews.publish','Публикация ручных записей Avito')
) AS catalog(code,description);

ALTER TABLE foundation.role_permissions DROP CONSTRAINT role_permissions_scope_check;
ALTER TABLE foundation.role_permissions ADD CONSTRAINT role_permissions_scope_check CHECK (
    CASE
        WHEN permission_code LIKE 'staff.self.%' THEN scope_type = 'SELF'
        WHEN permission_code IN ('geography.read','geography.manage','geography.publish',
            'staff.geography.read','staff.geography.manage',
            'references.callbackinterval.read','references.callbackinterval.manage',
            'content.read','content.manage','content.publish','pricing.read','pricing.manage') THEN scope_type IN ('CITY','GLOBAL')
        ELSE scope_type = 'GLOBAL'
    END);

-- The existing statement trigger takes the RBAC lock. This row guard only
-- checks the stored target; the web channel and exact delegator authority are
-- checked by the application under the same lock, not inferred from SQL role.
CREATE FUNCTION foundation.p04_guard_role_grant() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    target_admin boolean;
    target_delegated boolean;
BEGIN
    IF NOT NEW.enabled OR NEW.permission_code NOT IN (
        'catalog.read','catalog.manage','pricing.rules.read','pricing.rules.manage','pricing.read','pricing.manage',
        'content.externalreviews.read','content.externalreviews.manage','content.externalreviews.publish') THEN
        RETURN NEW;
    END IF;

    SELECT r.status = 'ACTIVE' AND r.role_type = 'SYSTEM' AND r.code = 'ADMIN',
           r.status = 'ACTIVE' AND (r.role_type = 'CUSTOM' OR (r.role_type = 'SYSTEM' AND r.code = 'MANAGER'))
        INTO target_admin,target_delegated FROM foundation.roles r WHERE r.id = NEW.role_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'P04 management grant needs an existing role' USING ERRCODE = '23503';
    END IF;
    IF NOT EXISTS (SELECT FROM foundation.permissions p WHERE p.code = NEW.permission_code
        AND p.active AND NOT p.protected AND p.module = split_part(p.code,'.',1)) THEN
        RAISE EXCEPTION 'P04 management grant needs the exact active ordinary catalog code' USING ERRCODE = '23514';
    END IF;
    IF (CASE WHEN NEW.permission_code IN ('pricing.read','pricing.manage')
        THEN (target_admin AND NEW.scope_type IN ('CITY','GLOBAL')) OR (target_delegated AND NEW.scope_type = 'CITY')
        ELSE target_admin AND NEW.scope_type = 'GLOBAL' END) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'P04 management grant is not permitted for this role and scope' USING ERRCODE = '23514';
END $$;
CREATE TRIGGER p04_guard_role_grant BEFORE INSERT OR UPDATE ON foundation.role_permissions
    FOR EACH ROW EXECUTE FUNCTION foundation.p04_guard_role_grant();

CREATE TABLE foundation.p04_bootstrap_permissions (
    assignment_id uuid NOT NULL,
    permission_code varchar(64) NOT NULL,
    row_version integer NOT NULL DEFAULT 1,
    revoked_at timestamptz(6),
    revoked_by uuid,
    CONSTRAINT p04_bootstrap_permissions_pkey PRIMARY KEY (assignment_id,permission_code),
    CONSTRAINT p04_bootstrap_permissions_assignment_id_fkey FOREIGN KEY (assignment_id)
        REFERENCES foundation.staff_role_assignments(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT p04_bootstrap_permissions_permission_code_fkey FOREIGN KEY (permission_code)
        REFERENCES foundation.permissions(code) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT p04_bootstrap_permissions_revoked_by_fkey FOREIGN KEY (revoked_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT p04_bootstrap_permissions_code_check CHECK (permission_code IN (
        'catalog.read','catalog.manage','pricing.rules.read','pricing.rules.manage','pricing.read','pricing.manage',
        'content.externalreviews.read','content.externalreviews.manage','content.externalreviews.publish')),
    CONSTRAINT p04_bootstrap_permissions_revoke_check CHECK ((revoked_at IS NULL AND revoked_by IS NULL)
        OR (revoked_at IS NOT NULL AND isfinite(revoked_at) AND revoked_by IS NOT NULL)),
    CONSTRAINT p04_bootstrap_permissions_row_version_check CHECK (
        row_version = CASE WHEN revoked_at IS NULL THEN 1 ELSE 2 END)
);

CREATE FUNCTION foundation.p04_bootstrap_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF current_user <> 'fixlevelup_migrator' OR current_database() COLLATE "C"
        !~ '^fixlevelup_(configuration_test|p04_browser_test)_[a-f0-9]{24}$' THEN
        RAISE EXCEPTION 'P04 bootstrap writes require the isolated synthetic migrator' USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.assignment_id IS NULL OR NEW.assignment_id IS DISTINCT FROM foundation.p03_original_bootstrap_assignment()
            OR NEW.revoked_at IS NOT NULL OR NEW.revoked_by IS NOT NULL OR NEW.row_version IS DISTINCT FROM 1
            OR NOT EXISTS (SELECT FROM foundation.permissions p WHERE p.code = NEW.permission_code
                AND p.active AND NOT p.protected AND p.module = split_part(p.code,'.',1)) THEN
            RAISE EXCEPTION 'P04 bootstrap grant requires the original verified assignment and an ordinary active code'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR NEW.revoked_by IS NULL
        OR ROW(NEW.assignment_id,NEW.permission_code,NEW.row_version)
            IS DISTINCT FROM ROW(OLD.assignment_id,OLD.permission_code,OLD.row_version) THEN
        RAISE EXCEPTION 'P04 bootstrap grant may only be revoked once' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (
        SELECT FROM foundation.staff s
        JOIN foundation.staff_web_credentials c ON c.staff_id = s.id
        JOIN foundation.staff_role_assignments a ON a.staff_id = s.id AND a.revoked_at IS NULL
        JOIN foundation.roles r ON r.id = a.role_id
        WHERE s.id = NEW.revoked_by AND s.employment_state = 'ACTIVE' AND s.role = 'ADMIN'
          AND r.role_type = 'SYSTEM' AND r.code = 'ADMIN' AND r.status = 'ACTIVE'
    ) THEN
        RAISE EXCEPTION 'P04 bootstrap revocation needs an active SYSTEM ADMIN' USING ERRCODE = '23514';
    END IF;
    NEW.revoked_at := clock_timestamp();
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END $$;
CREATE TRIGGER p04_bootstrap_write BEFORE INSERT OR UPDATE ON foundation.p04_bootstrap_permissions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.rbac_lock_write();
CREATE TRIGGER p04_bootstrap_guard BEFORE INSERT OR UPDATE ON foundation.p04_bootstrap_permissions
    FOR EACH ROW EXECUTE FUNCTION foundation.p04_bootstrap_guard();
CREATE TRIGGER p04_bootstrap_no_remove BEFORE DELETE OR TRUNCATE ON foundation.p04_bootstrap_permissions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();

-- No migration, startup or recovery call site: this is a synthetic fixture
-- entry point, not a production provisioning mechanism. An existing revoked
-- row keeps the only conflict key forever; reassignment cannot become founder.
CREATE FUNCTION foundation.issue_p04_synthetic_permissions() RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    founder_assignment uuid;
BEGIN
    IF current_user <> 'fixlevelup_migrator' OR current_database() COLLATE "C"
        !~ '^fixlevelup_(configuration_test|p04_browser_test)_[a-f0-9]{24}$' THEN
        RAISE EXCEPTION 'P04 bootstrap issuance requires the isolated synthetic migrator' USING ERRCODE = '42501';
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'P04 bootstrap issuance requires READ COMMITTED' USING ERRCODE = '40001';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('fixlevelup:admin-invariant',0));
    founder_assignment := foundation.p03_original_bootstrap_assignment();
    IF founder_assignment IS NULL THEN
        RETURN;
    END IF;

    INSERT INTO foundation.p04_bootstrap_permissions(assignment_id,permission_code)
    SELECT founder_assignment,code FROM unnest(ARRAY[
        'catalog.read','catalog.manage','pricing.rules.read','pricing.rules.manage','pricing.read','pricing.manage',
        'content.externalreviews.read','content.externalreviews.manage','content.externalreviews.publish']) AS codes(code)
    ON CONFLICT (assignment_id,permission_code) DO NOTHING;
END $$;

CREATE TABLE foundation.p04_command_receipts (
    actor_id uuid NOT NULL,
    operation varchar(64) NOT NULL,
    key uuid NOT NULL,
    request_sha256 varchar(64) NOT NULL,
    city_id uuid,
    subject_id uuid NOT NULL,
    target_version_id uuid,
    entity_id uuid NOT NULL,
    entity_version integer NOT NULL,
    revision_id uuid,
    revision_version integer,
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT p04_command_receipts_pkey PRIMARY KEY (actor_id,operation,key),
    CONSTRAINT p04_command_receipts_actor_id_fkey FOREIGN KEY (actor_id)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT p04_command_receipts_city_id_fkey FOREIGN KEY (city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT p04_command_receipts_operation_check CHECK (operation COLLATE "C" IN (
        'categoryCreate','categoryPublish','categoryArchive','brandCreate','brandPublish','brandArchive',
        'modelCreate','modelPublish','modelArchive','faultCreate','faultPublish','faultArchive',
        'itemCreate','itemPublish','itemArchive','mappingCreate','mappingPublish','mappingArchive',
        'ruleCreate','ruleArchive','fixedPublish','fixedClose','fixedReplace',
        'ruleVersionPublish','ruleVersionClose','ruleVersionReplace','policyPublish','policyClose','policyReplace',
        'estimateCreate','estimateArchive','estimatePublish','estimateClose','estimateReplace',
        'avitoCreate','avitoPublish','avitoArchive')),
    CONSTRAINT p04_command_receipts_request_sha256_check CHECK (request_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT p04_command_receipts_entity_version_check CHECK (entity_version > 0),
    CONSTRAINT p04_command_receipts_city_check CHECK ((city_id IS NOT NULL) = (operation IN (
        'fixedPublish','fixedClose','fixedReplace','ruleVersionPublish','ruleVersionClose','ruleVersionReplace',
        'policyPublish','policyClose','policyReplace','estimateCreate','estimateArchive','estimatePublish','estimateClose','estimateReplace'))),
    -- The subject is mandatory for every command. Only city/staff have one
    -- portable FK target: the other IDs are resolved by the exact route and data port.
    CONSTRAINT p04_command_receipts_subject_check CHECK (CASE
        WHEN operation IN ('policyPublish','policyClose','policyReplace') THEN subject_id IS NOT DISTINCT FROM city_id
        WHEN operation IN ('categoryCreate','brandCreate','modelCreate','faultCreate','itemCreate','mappingCreate','ruleCreate',
            'estimateCreate','avitoCreate') THEN subject_id = entity_id
        ELSE true END),
    CONSTRAINT p04_command_receipts_target_version_check CHECK ((target_version_id IS NOT NULL) = (operation IN (
        'fixedClose','fixedReplace','ruleVersionClose','ruleVersionReplace','policyClose','policyReplace','estimateClose','estimateReplace'))),
    CONSTRAINT p04_command_receipts_revision_check CHECK (CASE WHEN operation IN (
        'categoryPublish','brandPublish','modelPublish','faultPublish','itemPublish','fixedPublish','fixedReplace',
        'ruleVersionPublish','ruleVersionReplace','policyPublish','policyReplace','estimatePublish','estimateReplace','avitoPublish')
        THEN revision_id IS NOT NULL AND revision_version IS NOT NULL AND revision_version > 0
        ELSE revision_id IS NULL AND revision_version IS NULL END)
);
CREATE TRIGGER p04_command_receipts_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.p04_command_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();

CREATE TYPE foundation.external_review_kind AS ENUM ('PROFILE','REVIEW');

CREATE TABLE foundation.external_reviews (
    id uuid PRIMARY KEY,
    code varchar(64) NOT NULL,
    kind foundation.external_review_kind NOT NULL,
    profile_id uuid,
    profile_kind foundation.external_review_kind NOT NULL DEFAULT 'PROFILE',
    current_version_id uuid,
    row_version integer NOT NULL DEFAULT 1,
    archived_at timestamptz(6),
    CONSTRAINT external_reviews_code_check CHECK (code COLLATE "C" ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$' AND length(code) >= 2),
    CONSTRAINT external_reviews_profile_kind_check CHECK (profile_kind = 'PROFILE'),
    CONSTRAINT external_reviews_profile_check CHECK ((kind = 'REVIEW') = (profile_id IS NOT NULL)),
    CONSTRAINT external_reviews_row_version_check CHECK (row_version >= 1),
    CONSTRAINT external_reviews_archive_check CHECK (archived_at IS NULL OR isfinite(archived_at)),
    CONSTRAINT external_reviews_kind_code_key UNIQUE (kind,code),
    CONSTRAINT external_reviews_id_kind_key UNIQUE (id,kind),
    CONSTRAINT external_reviews_profile_fkey FOREIGN KEY (profile_id,profile_kind)
        REFERENCES foundation.external_reviews(id,kind) ON DELETE RESTRICT ON UPDATE RESTRICT
);

-- The linkage columns allow a normal, typed FK to the exact immutable PROFILE
-- revision. The write guard below binds that FK owner to the REVIEW's parent.
CREATE TABLE foundation.external_review_revisions (
    id uuid PRIMARY KEY,
    entry_id uuid NOT NULL,
    kind foundation.external_review_kind NOT NULL,
    version integer NOT NULL,
    title text NOT NULL,
    source_url text NOT NULL,
    source_date date,
    excerpt text,
    rating integer,
    permission_ref text NOT NULL,
    profile_revision_id uuid,
    reviewed_by uuid NOT NULL,
    published_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    profile_id uuid,
    profile_kind foundation.external_review_kind NOT NULL DEFAULT 'PROFILE',
    CONSTRAINT external_review_revisions_version_check CHECK (version >= 1),
    CONSTRAINT external_review_revisions_profile_kind_check CHECK (profile_kind = 'PROFILE'),
    -- Plain reviewed strings: no markup delimiters, control or format code
    -- points. PostgreSQL UTF-8 cannot store surrogate or zero code points.
    CONSTRAINT external_review_revisions_title_check CHECK (length(title) BETWEEN 1 AND 160
        AND title COLLATE "C" !~ U&'[<>\0001-\001F\007F-\009F\00AD\0600-\0605\061C\06DD\070F\0890-\0891\08E2\180E\200B-\200F\202A-\202E\2060-\2064\2066-\206F\FEFF\FFF9-\FFFB\+0110BD\+0110CD\+013430-\+01343F\+01BCA0-\+01BCA3\+01D173-\+01D17A\+0E0001\+0E0020-\+0E007F]'
        AND title = btrim(title,U&' \00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000')),
    CONSTRAINT external_review_revisions_source_url_check CHECK (length(source_url) <= 2048
        AND source_url COLLATE "C" ~ '^https://(www\.)?avito\.ru/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$'),
    CONSTRAINT external_review_revisions_source_date_check CHECK (source_date IS NULL OR source_date BETWEEN DATE '0001-01-01' AND DATE '9999-12-31'),
    CONSTRAINT external_review_revisions_excerpt_check CHECK (excerpt IS NULL OR (length(excerpt) BETWEEN 1 AND 1500
        AND excerpt COLLATE "C" !~ U&'[<>\0001-\001F\007F-\009F\00AD\0600-\0605\061C\06DD\070F\0890-\0891\08E2\180E\200B-\200F\202A-\202E\2060-\2064\2066-\206F\FEFF\FFF9-\FFFB\+0110BD\+0110CD\+013430-\+01343F\+01BCA0-\+01BCA3\+01D173-\+01D17A\+0E0001\+0E0020-\+0E007F]'
        AND excerpt = btrim(excerpt,U&' \00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000'))),
    CONSTRAINT external_review_revisions_rating_check CHECK (rating IS NULL OR rating BETWEEN 1 AND 5),
    CONSTRAINT external_review_revisions_permission_ref_check CHECK (length(permission_ref) BETWEEN 1 AND 200
        AND permission_ref COLLATE "C" !~ U&'[<>\0001-\001F\007F-\009F\00AD\0600-\0605\061C\06DD\070F\0890-\0891\08E2\180E\200B-\200F\202A-\202E\2060-\2064\2066-\206F\FEFF\FFF9-\FFFB\+0110BD\+0110CD\+013430-\+01343F\+01BCA0-\+01BCA3\+01D173-\+01D17A\+0E0001\+0E0020-\+0E007F]'
        AND permission_ref = btrim(permission_ref,U&' \00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000')),
    CONSTRAINT external_review_revisions_kind_fields_check CHECK (CASE WHEN kind = 'PROFILE'
        THEN source_date IS NULL AND excerpt IS NULL AND rating IS NULL AND profile_id IS NULL AND profile_revision_id IS NULL
        ELSE source_date IS NOT NULL AND excerpt IS NOT NULL AND profile_id IS NOT NULL AND profile_revision_id IS NOT NULL END),
    CONSTRAINT external_review_revisions_published_at_check CHECK (isfinite(published_at)),
    CONSTRAINT external_review_revisions_entry_version_key UNIQUE (entry_id,version),
    CONSTRAINT external_review_revisions_entry_kind_id_key UNIQUE (entry_id,kind,id),
    CONSTRAINT external_review_revisions_entry_fkey FOREIGN KEY (entry_id,kind)
        REFERENCES foundation.external_reviews(id,kind) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT external_review_revisions_profile_fkey FOREIGN KEY (profile_id,profile_kind,profile_revision_id)
        REFERENCES foundation.external_review_revisions(entry_id,kind,id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT external_review_revisions_reviewer_fkey FOREIGN KEY (reviewed_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT
);
ALTER TABLE foundation.external_reviews ADD CONSTRAINT external_reviews_current_version_fkey
    FOREIGN KEY (id,kind,current_version_id) REFERENCES foundation.external_review_revisions(entry_id,kind,id)
    ON DELETE RESTRICT ON UPDATE RESTRICT;

CREATE FUNCTION foundation.external_reviews_guard_identity() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    previous_version integer;
    candidate_version integer;
    basis_id uuid;
    basis_version_id uuid;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.row_version IS DISTINCT FROM 1 OR NEW.current_version_id IS NOT NULL OR NEW.archived_at IS NOT NULL THEN
            RAISE EXCEPTION 'External review identity starts as a draft at version 1' USING ERRCODE = '23514';
        END IF;
        IF NEW.kind = 'REVIEW' AND NOT EXISTS (SELECT FROM foundation.external_reviews p
            WHERE p.id = NEW.profile_id AND p.kind = 'PROFILE' AND p.archived_at IS NULL) THEN
            RAISE EXCEPTION 'External review draft needs a live PROFILE parent' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.archived_at IS NOT NULL OR ROW(NEW.id,NEW.code,NEW.kind,NEW.profile_id,NEW.profile_kind,NEW.row_version)
        IS DISTINCT FROM ROW(OLD.id,OLD.code,OLD.kind,OLD.profile_id,OLD.profile_kind,OLD.row_version) THEN
        RAISE EXCEPTION 'Archived external review identities and stable fields cannot change' USING ERRCODE = '23514';
    END IF;
    IF NEW.archived_at IS NOT NULL THEN
        IF NEW.current_version_id IS DISTINCT FROM OLD.current_version_id THEN
            RAISE EXCEPTION 'Archive preserves the external review publication' USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT v.version INTO previous_version FROM foundation.external_review_revisions v WHERE v.id = OLD.current_version_id;
        SELECT v.version,v.profile_id,v.profile_revision_id INTO candidate_version,basis_id,basis_version_id
          FROM foundation.external_review_revisions v WHERE (v.entry_id,v.kind,v.id) = (OLD.id,OLD.kind,NEW.current_version_id);
        IF candidate_version IS NULL THEN
            RAISE EXCEPTION 'External review publication must point to its own typed revision' USING ERRCODE = '23503';
        END IF;
        IF candidate_version IS DISTINCT FROM coalesce(previous_version,0) + 1 THEN
            RAISE EXCEPTION 'Current external review version must advance by one' USING ERRCODE = '23514';
        END IF;
        IF NEW.kind = 'REVIEW' AND (basis_id IS DISTINCT FROM NEW.profile_id OR NOT EXISTS (
            SELECT FROM foundation.external_reviews p WHERE p.id = NEW.profile_id AND p.kind = 'PROFILE'
                AND p.archived_at IS NULL AND p.current_version_id = basis_version_id)) THEN
            RAISE EXCEPTION 'External review publication needs its live current PROFILE revision' USING ERRCODE = '23514';
        END IF;
    END IF;
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END $$;

CREATE FUNCTION foundation.external_review_revisions_guard_basis() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    exact_profile_id uuid;
    previous_version integer;
BEGIN
    SELECT e.profile_id,v.version INTO exact_profile_id,previous_version
    FROM foundation.external_reviews e
    LEFT JOIN foundation.external_review_revisions v ON v.id = e.current_version_id
    WHERE (e.id,e.kind) = (NEW.entry_id,NEW.kind) AND e.archived_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'External review revision needs a live identity of its own kind' USING ERRCODE = '23514';
    END IF;
    IF NEW.version IS DISTINCT FROM coalesce(previous_version,0) + 1 THEN
        RAISE EXCEPTION 'External review revision must be next in the chain' USING ERRCODE = '23514';
    END IF;
    IF NEW.kind = 'REVIEW' AND (NEW.profile_id IS DISTINCT FROM exact_profile_id OR NOT EXISTS (
        SELECT FROM foundation.external_reviews p WHERE p.id = exact_profile_id AND p.kind = 'PROFILE'
            AND p.archived_at IS NULL AND p.current_version_id = NEW.profile_revision_id)) THEN
        RAISE EXCEPTION 'External review revision needs its live current PROFILE revision' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION foundation.external_review_revisions_guard_chain() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
    reached_version integer;
BEGIN
    SELECT v.version INTO reached_version
    FROM foundation.external_reviews e
    JOIN foundation.external_review_revisions v ON (v.entry_id,v.kind,v.id) = (e.id,e.kind,e.current_version_id)
    WHERE (e.id,e.kind) = (NEW.entry_id,NEW.kind);
    IF reached_version IS NULL OR reached_version < NEW.version THEN
        RAISE EXCEPTION 'External review revision must join its published chain' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER external_reviews_write_fence BEFORE INSERT OR UPDATE ON foundation.external_reviews
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER external_review_revisions_write_fence BEFORE INSERT ON foundation.external_review_revisions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_lock_write();
CREATE TRIGGER external_reviews_guard BEFORE INSERT OR UPDATE ON foundation.external_reviews
    FOR EACH ROW EXECUTE FUNCTION foundation.external_reviews_guard_identity();
CREATE TRIGGER external_review_revisions_basis_guard BEFORE INSERT ON foundation.external_review_revisions
    FOR EACH ROW EXECUTE FUNCTION foundation.external_review_revisions_guard_basis();
CREATE CONSTRAINT TRIGGER external_review_revisions_chain_guard AFTER INSERT ON foundation.external_review_revisions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.external_review_revisions_guard_chain();
CREATE TRIGGER external_reviews_no_remove BEFORE DELETE OR TRUNCATE ON foundation.external_reviews
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();
CREATE TRIGGER external_review_revisions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON foundation.external_review_revisions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.catalog_reject_history_change();

REVOKE ALL ON FUNCTION foundation.p04_guard_role_grant(), foundation.p04_bootstrap_guard(),
    foundation.issue_p04_synthetic_permissions(), foundation.external_reviews_guard_identity(),
    foundation.external_review_revisions_guard_basis(), foundation.external_review_revisions_guard_chain()
    FROM PUBLIC,fixlevelup_runtime;
GRANT EXECUTE ON FUNCTION foundation.issue_p04_synthetic_permissions() TO fixlevelup_migrator;
REVOKE ALL ON TYPE foundation.external_review_kind FROM PUBLIC,fixlevelup_runtime;
GRANT USAGE ON TYPE foundation.external_review_kind TO fixlevelup_runtime;

REVOKE ALL ON foundation.p04_bootstrap_permissions, foundation.p04_command_receipts,
    foundation.external_reviews, foundation.external_review_revisions FROM PUBLIC,fixlevelup_runtime;
GRANT SELECT(assignment_id,permission_code,row_version,revoked_at)
    ON foundation.p04_bootstrap_permissions TO fixlevelup_runtime;
GRANT SELECT(actor_id,operation,key,request_sha256,city_id,subject_id,target_version_id,entity_id,entity_version,revision_id,revision_version),
    INSERT(actor_id,operation,key,request_sha256,city_id,subject_id,target_version_id,entity_id,entity_version,revision_id,revision_version)
    ON foundation.p04_command_receipts TO fixlevelup_runtime;
GRANT SELECT, INSERT(id,code,kind,profile_id), UPDATE(current_version_id,archived_at)
    ON foundation.external_reviews TO fixlevelup_runtime;
GRANT SELECT, INSERT(id,entry_id,kind,version,title,source_url,source_date,excerpt,rating,permission_ref,profile_id,profile_revision_id,reviewed_by)
    ON foundation.external_review_revisions TO fixlevelup_runtime;

COMMIT;
