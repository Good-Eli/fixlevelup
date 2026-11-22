BEGIN;
SET TRANSACTION ISOLATION LEVEL READ COMMITTED;

-- P03-05 (018): inert management catalog, founder-only personal source, and
-- immutable command receipts. Deploy only with old binaries drained. Take the
-- existing RBAC write lock before validating anything; fail instead of waiting
-- for relation locks in reverse order if an old DB command is still using them.
SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('fixlevelup:admin-invariant',0));
LOCK TABLE foundation.permissions IN SHARE ROW EXCLUSIVE MODE NOWAIT;
LOCK TABLE foundation.role_permissions IN ACCESS EXCLUSIVE MODE NOWAIT;

DO $$
BEGIN
    IF EXISTS (SELECT FROM foundation.permissions WHERE code IN (
        'settings.fullread','settings.manage','settings.readiness.read',
        'references.callbackinterval.read','references.callbackinterval.manage',
        'references.paymentmethod.read','references.paymentmethod.manage',
        'references.cancelreason.read','references.cancelreason.manage',
        'references.declinereason.read','references.declinereason.manage',
        'references.requestsource.read','references.requestsource.manage',
        'content.read','content.manage','content.publish','legal.read','legal.manage')) THEN
        RAISE EXCEPTION 'P03 management catalog must be empty before migration 018' USING ERRCODE='23514';
    END IF;
END $$;

-- Never adopt a pre-existing code or add role_permissions. The founder source
-- below is separate: catalog presence, on its own, has no grant effect.
INSERT INTO foundation.permissions(code,module,description,protected,active)
SELECT code,split_part(code,'.',1),description,false,true
FROM (VALUES
    ('settings.fullread','Просмотр полных настроек компании'),
    ('settings.manage','Публикация настроек компании'),
    ('settings.readiness.read','Просмотр состояния настройки'),
    ('references.callbackinterval.read','Просмотр интервалов обратного звонка'),
    ('references.callbackinterval.manage','Управление интервалами обратного звонка'),
    ('references.paymentmethod.read','Просмотр способов оплаты'),
    ('references.paymentmethod.manage','Управление способами оплаты'),
    ('references.cancelreason.read','Просмотр причин отмены'),
    ('references.cancelreason.manage','Управление причинами отмены'),
    ('references.declinereason.read','Просмотр причин отказа'),
    ('references.declinereason.manage','Управление причинами отказа'),
    ('references.requestsource.read','Просмотр источников заявок'),
    ('references.requestsource.manage','Управление источниками заявок'),
    ('content.read','Просмотр контента и истории'),
    ('content.manage','Создание и архивирование блоков контента'),
    ('content.publish','Публикация версий контента'),
    ('legal.read','Просмотр юридических документов и истории'),
    ('legal.manage','Создание и публикация юридических документов')
) AS catalog(code,description);

ALTER TABLE foundation.role_permissions DROP CONSTRAINT role_permissions_scope_check;
ALTER TABLE foundation.role_permissions ADD CONSTRAINT role_permissions_scope_check CHECK (
    CASE
        WHEN permission_code LIKE 'staff.self.%' THEN scope_type = 'SELF'
        WHEN permission_code IN ('geography.read','geography.manage','geography.publish',
            'staff.geography.read','staff.geography.manage',
            'references.callbackinterval.read','references.callbackinterval.manage',
            'content.read','content.manage','content.publish') THEN scope_type IN ('CITY','GLOBAL')
        ELSE scope_type = 'GLOBAL'
    END);

-- Retain the 009/012 triggers and their ACLs. Here the existing 009 statement
-- trigger has already serialized the decision with role/catalog/assignment writers.
-- CUSTOM is a role, not a channel: the application masks P03 for the TG holder
-- of a shared CUSTOM role. This trigger checks only the stored grant's target.
CREATE FUNCTION foundation.p03_guard_role_grant() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    target_admin boolean;
    target_delegated boolean;
BEGIN
    IF NOT NEW.enabled THEN
        -- Disabling an existing matrix-invalid grant is always permitted.
        RETURN NEW;
    END IF;
    IF NEW.permission_code NOT IN (
        'settings.fullread','settings.manage','settings.readiness.read',
        'references.callbackinterval.read','references.callbackinterval.manage',
        'references.paymentmethod.read','references.paymentmethod.manage',
        'references.cancelreason.read','references.cancelreason.manage',
        'references.declinereason.read','references.declinereason.manage',
        'references.requestsource.read','references.requestsource.manage',
        'content.read','content.manage','content.publish','legal.read','legal.manage') THEN
        RETURN NEW;
    END IF;

    SELECT r.status = 'ACTIVE' AND r.role_type = 'SYSTEM' AND r.code = 'ADMIN',
           r.status = 'ACTIVE' AND (r.role_type = 'CUSTOM' OR (r.role_type = 'SYSTEM' AND r.code = 'MANAGER'))
      INTO target_admin, target_delegated
      FROM foundation.roles r WHERE r.id = NEW.role_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'P03 management grant needs an existing role' USING ERRCODE='23503';
    END IF;
    IF NOT EXISTS (SELECT FROM foundation.permissions p WHERE p.code = NEW.permission_code AND p.active AND NOT p.protected) THEN
        RAISE EXCEPTION 'P03 management grant needs an active ordinary catalog code' USING ERRCODE='23514';
    END IF;

    IF (CASE
        WHEN NEW.permission_code IN ('references.callbackinterval.read','references.callbackinterval.manage',
                'content.read','content.manage','content.publish')
            THEN (target_admin AND NEW.scope_type IN ('CITY','GLOBAL')) OR (target_delegated AND NEW.scope_type = 'CITY')
        WHEN NEW.permission_code IN ('settings.fullread','settings.manage','legal.read','legal.manage')
            THEN target_admin AND NEW.scope_type = 'GLOBAL'
        ELSE (target_admin OR target_delegated) AND NEW.scope_type = 'GLOBAL'
    END) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'P03 management grant is not permitted for this role and scope' USING ERRCODE='23514';
END $$;
CREATE TRIGGER p03_guard_role_grant BEFORE INSERT OR UPDATE ON foundation.role_permissions
    FOR EACH ROW EXECUTE FUNCTION foundation.p03_guard_role_grant();

CREATE TABLE foundation.p03_bootstrap_permissions (
    assignment_id uuid NOT NULL,
    permission_code varchar(64) NOT NULL,
    row_version integer NOT NULL DEFAULT 1,
    revoked_at timestamptz(6),
    revoked_by uuid,
    CONSTRAINT p03_bootstrap_permissions_pkey PRIMARY KEY (assignment_id,permission_code),
    CONSTRAINT p03_bootstrap_permissions_assignment_id_fkey FOREIGN KEY (assignment_id)
        REFERENCES foundation.staff_role_assignments(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT p03_bootstrap_permissions_permission_code_fkey FOREIGN KEY (permission_code)
        REFERENCES foundation.permissions(code) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT p03_bootstrap_permissions_revoked_by_fkey FOREIGN KEY (revoked_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT p03_bootstrap_permissions_code_check CHECK (permission_code IN (
        'settings.fullread','settings.manage','settings.readiness.read',
        'references.callbackinterval.read','references.callbackinterval.manage',
        'references.paymentmethod.read','references.paymentmethod.manage',
        'references.cancelreason.read','references.cancelreason.manage',
        'references.declinereason.read','references.declinereason.manage',
        'references.requestsource.read','references.requestsource.manage',
        'content.read','content.manage','content.publish','legal.read','legal.manage')),
    CONSTRAINT p03_bootstrap_permissions_revoke_check CHECK ((revoked_at IS NULL) = (revoked_by IS NULL)),
    CONSTRAINT p03_bootstrap_permissions_row_version_check CHECK (
        row_version = CASE WHEN revoked_at IS NULL THEN 1 ELSE 2 END)
);

-- Called under the RBAC write lock. The singleton marker identifies the founder;
-- having only one assignment in all history (not a UUID or timestamp ordering)
-- proves it is the original one. No eligible founder is a NULL result, never a
-- fallback. This helper is private to the owner; runtime need not read the marker.
CREATE FUNCTION foundation.p03_original_bootstrap_assignment() RETURNS uuid
LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
    SELECT a.id
    FROM foundation.staff_bootstrap_marker b
    JOIN foundation.staff s ON s.id = b.staff_id
    JOIN foundation.staff_web_credentials c ON c.staff_id = s.id
    JOIN foundation.staff_role_assignments a ON a.staff_id = s.id AND a.revoked_at IS NULL
    JOIN foundation.roles r ON r.id = a.role_id
    WHERE b.id = 1 AND s.employment_state = 'ACTIVE' AND s.role = 'ADMIN'
      AND r.role_type = 'SYSTEM' AND r.code = 'ADMIN' AND r.status = 'ACTIVE'
      AND NOT EXISTS (SELECT FROM foundation.staff_role_assignments other
          WHERE other.staff_id = a.staff_id AND other.id <> a.id)
$$;

CREATE FUNCTION foundation.p03_bootstrap_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'P03 bootstrap grant history cannot be deleted' USING ERRCODE='23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.assignment_id IS NULL OR NEW.assignment_id IS DISTINCT FROM foundation.p03_original_bootstrap_assignment()
            OR NEW.revoked_at IS NOT NULL OR NEW.revoked_by IS NOT NULL OR NEW.row_version IS DISTINCT FROM 1 THEN
            RAISE EXCEPTION 'P03 bootstrap grant requires the original verified assignment and an unrevoked source'
                USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR NEW.revoked_by IS NULL
        OR ROW(NEW.assignment_id,NEW.permission_code,NEW.row_version)
            IS DISTINCT FROM ROW(OLD.assignment_id,OLD.permission_code,OLD.row_version) THEN
        RAISE EXCEPTION 'P03 bootstrap grant may only be revoked once' USING ERRCODE='23514';
    END IF;
    -- Structural revoker check, also allowing self-revocation. The authenticated
    -- identity and live roles.permissions.manage + GLOBAL same-code authority are
    -- enforced by the application; a shared database login cannot authenticate staff.
    IF NOT EXISTS (
        SELECT FROM foundation.staff s
        JOIN foundation.staff_web_credentials c ON c.staff_id = s.id
        JOIN foundation.staff_role_assignments a ON a.staff_id = s.id AND a.revoked_at IS NULL
        JOIN foundation.roles r ON r.id = a.role_id
        WHERE s.id = NEW.revoked_by AND s.employment_state = 'ACTIVE' AND s.role = 'ADMIN'
          AND r.role_type = 'SYSTEM' AND r.code = 'ADMIN' AND r.status = 'ACTIVE'
    ) THEN
        RAISE EXCEPTION 'P03 bootstrap revocation needs an active SYSTEM ADMIN' USING ERRCODE='23514';
    END IF;
    NEW.revoked_at := clock_timestamp();
    NEW.row_version := OLD.row_version + 1;
    RETURN NEW;
END $$;
CREATE TRIGGER p03_bootstrap_write BEFORE INSERT OR UPDATE ON foundation.p03_bootstrap_permissions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.rbac_lock_write();
CREATE TRIGGER p03_bootstrap_guard BEFORE INSERT OR UPDATE OR DELETE ON foundation.p03_bootstrap_permissions
    FOR EACH ROW EXECUTE FUNCTION foundation.p03_bootstrap_guard();

CREATE FUNCTION foundation.issue_first_p03_permissions() RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    founder_assignment uuid;
    issued_codes jsonb;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'P03 bootstrap issuance requires READ COMMITTED' USING ERRCODE='40001';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('fixlevelup:admin-invariant',0));
    founder_assignment := foundation.p03_original_bootstrap_assignment();
    IF founder_assignment IS NULL THEN
        RETURN;
    END IF;

    -- No grant inheritance, replacement assignment, or reactivation on replay:
    -- even a revoked source owns its original conflict key for all time.
    WITH issued AS (
        INSERT INTO foundation.p03_bootstrap_permissions(assignment_id,permission_code)
        SELECT founder_assignment,code FROM unnest(ARRAY[
            'settings.fullread','settings.manage','settings.readiness.read',
            'references.callbackinterval.read','references.callbackinterval.manage',
            'references.paymentmethod.read','references.paymentmethod.manage',
            'references.cancelreason.read','references.cancelreason.manage',
            'references.declinereason.read','references.declinereason.manage',
            'references.requestsource.read','references.requestsource.manage',
            'content.read','content.manage','content.publish','legal.read','legal.manage']) AS codes(code)
        ON CONFLICT (assignment_id,permission_code) DO NOTHING
        RETURNING permission_code
    ) SELECT jsonb_agg(permission_code ORDER BY permission_code COLLATE "C") INTO issued_codes FROM issued;
    IF issued_codes IS NOT NULL THEN
        INSERT INTO foundation.audit_logs(id,operation,correlation_id,details)
        VALUES (gen_random_uuid(),'P03_BOOTSTRAP_PERMISSIONS',gen_random_uuid(),
            jsonb_build_object('actor','SYSTEM_MIGRATION_018','assignmentId',founder_assignment,'permissions',issued_codes));
    END IF;
END $$;

CREATE TABLE foundation.p03_command_receipts (
    actor_id uuid NOT NULL,
    operation varchar(64) NOT NULL,
    key uuid NOT NULL,
    request_sha256 varchar(64) NOT NULL,
    entity_id uuid NOT NULL,
    entity_version integer NOT NULL,
    revision_id uuid,
    revision_version integer,
    created_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT p03_command_receipts_pkey PRIMARY KEY (actor_id,operation,key),
    CONSTRAINT p03_command_receipts_actor_id_fkey FOREIGN KEY (actor_id)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT p03_command_receipts_operation_check CHECK (operation IN (
        'companyPublish','referenceCreate','referencePublish','referenceArchive','contentCreate','contentPublish',
        'contentArchive','legalCreate','legalPublish','bootstrapRevoke')),
    CONSTRAINT p03_command_receipts_request_sha256_check CHECK (request_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT p03_command_receipts_entity_version_check CHECK (entity_version > 0),
    CONSTRAINT p03_command_receipts_revision_check CHECK (
        CASE WHEN operation IN ('referencePublish','contentPublish','legalPublish')
            THEN revision_id IS NOT NULL AND revision_version IS NOT NULL AND revision_version > 0
            ELSE revision_id IS NULL AND revision_version IS NULL
        END)
);

CREATE FUNCTION foundation.p03_history_immutable() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'P03 management history is immutable' USING ERRCODE='23514';
END $$;
CREATE TRIGGER p03_receipts_immutable BEFORE UPDATE OR DELETE ON foundation.p03_command_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.p03_history_immutable();
CREATE TRIGGER p03_receipts_no_truncate BEFORE TRUNCATE ON foundation.p03_command_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.p03_history_immutable();
CREATE TRIGGER p03_bootstrap_no_truncate BEFORE TRUNCATE ON foundation.p03_bootstrap_permissions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.p03_history_immutable();

REVOKE ALL ON FUNCTION foundation.p03_guard_role_grant(),foundation.p03_original_bootstrap_assignment(),
    foundation.p03_bootstrap_guard(),foundation.issue_first_p03_permissions(),foundation.p03_history_immutable()
    FROM PUBLIC,fixlevelup_runtime;
GRANT EXECUTE ON FUNCTION foundation.issue_first_p03_permissions() TO fixlevelup_migrator;

REVOKE ALL ON foundation.p03_bootstrap_permissions, foundation.p03_command_receipts FROM PUBLIC,fixlevelup_runtime;
GRANT SELECT(assignment_id,permission_code,row_version,revoked_at), UPDATE(revoked_at,revoked_by)
    ON foundation.p03_bootstrap_permissions TO fixlevelup_runtime;
GRANT SELECT(actor_id,operation,key,request_sha256,entity_id,entity_version,revision_id,revision_version),
    INSERT(actor_id,operation,key,request_sha256,entity_id,entity_version,revision_id,revision_version)
    ON foundation.p03_command_receipts TO fixlevelup_runtime;

-- Fresh empty DB: no-op. The same trusted migrator call is used at the end of
-- the console bootstrap transaction, once the marker/credential/assignment exist.
SELECT foundation.issue_first_p03_permissions();

COMMIT;
