BEGIN;

-- One cutover snapshot. Old binaries must be drained before deployment: when this
-- commits, individual grants are unreadable as well as unwritable by runtime.
LOCK TABLE foundation.staff, foundation.staff_web_credentials, foundation.staff_bootstrap_marker,
    foundation.user_permissions IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
    IF EXISTS (SELECT FROM foundation.staff) AND NOT EXISTS (
        SELECT FROM foundation.staff_bootstrap_marker b JOIN foundation.staff s ON s.id=b.staff_id
        JOIN foundation.staff_web_credentials c ON c.staff_id=s.id
        WHERE b.id=1 AND s.role='ADMIN' AND s.employment_state='ACTIVE') THEN
        RAISE EXCEPTION 'RBAC cutover requires verified active bootstrap administrator with web credential' USING ERRCODE='23514';
    END IF;
END $$;

-- Marker/credential presence alone is insufficient: a malformed legacy login or
-- unsupported verifier cannot authenticate. Validate in place; do not reset any
-- credential or expose its value/row in migration diagnostics.
ALTER TABLE foundation.staff_web_credentials ADD CONSTRAINT staff_web_credentials_supported_check CHECK (
    login COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._@+\-]{0,254}$' AND
    password_hash COLLATE "C" ~ '^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{21}[AQgw]\$[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$'
) NOT VALID;
DO $$
BEGIN
    ALTER TABLE foundation.staff_web_credentials VALIDATE CONSTRAINT staff_web_credentials_supported_check;
EXCEPTION WHEN check_violation THEN
    RAISE EXCEPTION 'RBAC cutover requires supported staff web credentials' USING ERRCODE='23514';
END $$;

ALTER TABLE foundation.staff ADD COLUMN display_name varchar(80), ADD COLUMN profile_version integer NOT NULL DEFAULT 0,
    ADD CONSTRAINT staff_display_name_check CHECK (display_name IS NULL OR length(btrim(display_name))>0),
    ADD CONSTRAINT staff_profile_version_check CHECK (profile_version>=0);
CREATE TABLE foundation.permissions (
    code varchar(64) PRIMARY KEY, module varchar(32) NOT NULL, description varchar(500) NOT NULL,
    protected boolean NOT NULL DEFAULT false, active boolean NOT NULL DEFAULT true,
    CONSTRAINT permissions_metadata_check CHECK (code ~ '^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$' AND length(btrim(module))>0 AND length(btrim(description))>0),
    CONSTRAINT permissions_protected_active_check CHECK (NOT protected OR active)
);
CREATE TABLE foundation.roles (
    id uuid PRIMARY KEY, code varchar(64) NOT NULL, name varchar(80) NOT NULL, description varchar(500) NOT NULL DEFAULT '',
    role_type varchar(16) NOT NULL DEFAULT 'CUSTOM', status varchar(16) NOT NULL DEFAULT 'ACTIVE', version integer NOT NULL DEFAULT 1,
    created_by uuid REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    updated_by uuid REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    created_at timestamptz(6) NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at timestamptz(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT roles_metadata_check CHECK (code ~ '^[A-Z][A-Z0-9_]*$' AND length(btrim(name))>0 AND version>=1),
    CONSTRAINT roles_identity_check CHECK ((role_type='SYSTEM' AND code IN ('ADMIN','MANAGER','TECHNICIAN') AND status='ACTIVE')
        OR (role_type='CUSTOM' AND code NOT IN ('ADMIN','MANAGER','TECHNICIAN') AND status IN ('ACTIVE','ARCHIVED')))
);
CREATE UNIQUE INDEX roles_code_key ON foundation.roles(code);
CREATE TABLE foundation.role_permissions (
    role_id uuid NOT NULL REFERENCES foundation.roles(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    permission_code varchar(64) NOT NULL REFERENCES foundation.permissions(code) ON DELETE RESTRICT ON UPDATE RESTRICT,
    scope_type varchar(16) NOT NULL, enabled boolean NOT NULL DEFAULT true,
    PRIMARY KEY(role_id,permission_code),
    -- CITY is reserved for a future migration with membership and a target FK.
    -- Never store a purported CITY grant before it can actually be enforced.
    CONSTRAINT role_permissions_scope_check CHECK (scope_type IN ('SELF','CITY','GLOBAL') AND
        scope_type=CASE WHEN permission_code LIKE 'staff.self.%' THEN 'SELF' ELSE 'GLOBAL' END)
);
CREATE TABLE foundation.staff_role_assignments (
    id uuid PRIMARY KEY, staff_id uuid NOT NULL REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    role_id uuid NOT NULL REFERENCES foundation.roles(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    assigned_by uuid REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    revoked_by uuid REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    -- The swap statement closes the preceding assignment at this same instant.
    assigned_at timestamptz(6) NOT NULL DEFAULT statement_timestamp(), revoked_at timestamptz(6),
    CONSTRAINT staff_role_assignments_actor_check CHECK (assigned_by IS DISTINCT FROM staff_id AND revoked_by IS DISTINCT FROM staff_id),
    CONSTRAINT staff_role_assignments_period_check CHECK ((revoked_at IS NULL AND revoked_by IS NULL) OR
        (revoked_at >= assigned_at AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL))
);
CREATE UNIQUE INDEX staff_role_assignments_current_key ON foundation.staff_role_assignments(staff_id) WHERE revoked_at IS NULL;
CREATE INDEX staff_role_assignments_role_staff_idx ON foundation.staff_role_assignments(role_id, staff_id);

INSERT INTO foundation.permissions(code,module,description,protected) VALUES
    ('staff.self.read','staff','Просмотр своего профиля',false), ('staff.self.update','staff','Изменение своего профиля',false),
    ('staff.self.deactivate','staff','Самодеактивация',false), ('staff.read','staff','Просмотр сотрудников',false),
    ('staff.create','staff','Создание сотрудников',false), ('staff.update','staff','Редактирование сотрудников',false),
    ('staff.deactivate','staff','Деактивация сотрудников',false), ('staff.role.assign','staff','Назначение ролей сотрудникам',true),
    ('roles.read','roles','Просмотр ролей и возможностей',false), ('roles.create','roles','Создание пользовательских ролей',true),
    ('roles.update','roles','Редактирование пользовательских ролей',true), ('roles.archive','roles','Архивирование пользовательских ролей',true),
    ('roles.permissions.manage','roles','Изменение возможностей роли',true)
ON CONFLICT(code) DO NOTHING;
INSERT INTO foundation.roles(id,code,name,description,role_type) VALUES
    ('00000000-0000-4000-8000-000000000001','TECHNICIAN','Мастер','Собственный профиль','SYSTEM'),
    ('00000000-0000-4000-8000-000000000002','MANAGER','Менеджер','Управление мастерами','SYSTEM'),
    ('00000000-0000-4000-8000-000000000003','ADMIN','Администратор','Управление сотрудниками и доступом','SYSTEM')
ON CONFLICT(code) DO NOTHING;
INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
SELECT r.id,p.code,CASE WHEN p.code LIKE 'staff.self.%' THEN 'SELF' ELSE 'GLOBAL' END
FROM foundation.roles r CROSS JOIN foundation.permissions p
WHERE r.role_type='SYSTEM' AND (r.code='ADMIN' OR p.code LIKE 'staff.self.%' OR
    (r.code='MANAGER' AND p.code IN ('staff.read','staff.create','staff.update','staff.deactivate')))
ON CONFLICT(role_id,permission_code) DO NOTHING;

-- Do not promote old role labels into administrative/manager grants. Only the
-- verified bootstrap principal becomes ADMIN. Bounded, future, revoked and
-- unknown grants remain available to the migration owner for offline review.
-- Aggregate OLD operational rights into up to four shared (not personal) roles.
-- The migration role has no TEMP database privilege. Use a transaction-private
-- staging table owned by foundation's migration owner instead of CREATE TEMP.
CREATE TABLE foundation.rbac_cutover_stage (
    staff_id uuid PRIMARY KEY, legacy_role varchar(16) NOT NULL, old_auth_version integer NOT NULL,
    code varchar(64) NOT NULL
);
INSERT INTO foundation.rbac_cutover_stage(staff_id,legacy_role,old_auth_version,code)
SELECT s.id, s.role, s.auth_version,
    CASE WHEN b.staff_id IS NOT NULL THEN 'ADMIN' WHEN s.role='TECHNICIAN' THEN 'TECHNICIAN'
    ELSE 'LEGACY_OPERATIONS_' || (
        (CASE WHEN bool_or(p.capability='staff.read') THEN 1 ELSE 0 END) +
        (CASE WHEN bool_or(p.capability='staff.manage') THEN 2 ELSE 0 END))::text END
FROM foundation.staff s LEFT JOIN foundation.staff_bootstrap_marker b ON b.staff_id=s.id
LEFT JOIN foundation.user_permissions p ON p.staff_id=s.id AND p.scope='GLOBAL' AND p.revoked_at IS NULL
    AND p.valid_from <= CURRENT_TIMESTAMP AND p.valid_until IS NULL
GROUP BY s.id,s.role,s.auth_version,b.staff_id;
INSERT INTO foundation.roles(id,code,name,description)
SELECT gen_random_uuid(),code,'Операционный профиль P02 ' || right(code,1),'Сохранённые бессрочные полномочия P02; требуется проверка администратором.'
FROM (SELECT DISTINCT code FROM foundation.rbac_cutover_stage WHERE code LIKE 'LEGACY_OPERATIONS_%') profiles
ON CONFLICT(code) DO NOTHING;
INSERT INTO foundation.role_permissions(role_id,permission_code,scope_type)
SELECT r.id,p.code,'GLOBAL' FROM foundation.roles r CROSS JOIN foundation.permissions p
WHERE (r.code IN ('LEGACY_OPERATIONS_1','LEGACY_OPERATIONS_3') AND p.code='staff.read') OR
      (r.code IN ('LEGACY_OPERATIONS_2','LEGACY_OPERATIONS_3') AND p.code IN ('staff.create','staff.deactivate'))
ON CONFLICT(role_id,permission_code) DO NOTHING;
INSERT INTO foundation.staff_role_assignments(id,staff_id,role_id)
SELECT gen_random_uuid(),c.staff_id,r.id FROM foundation.rbac_cutover_stage c JOIN foundation.roles r ON r.code=c.code;
-- Invalidate BOTH existing session channels. Preserve old CRM as CRM (MANAGER)
-- rather than switching old managers/admins to Telegram during the transition.
UPDATE foundation.staff s SET auth_version=auth_version+1, role=CASE WHEN c.code LIKE 'LEGACY_OPERATIONS_%' THEN 'MANAGER' ELSE c.code END
FROM foundation.rbac_cutover_stage c WHERE c.staff_id=s.id;
INSERT INTO foundation.audit_logs(id,operation,correlation_id,details)
SELECT gen_random_uuid(),'RBAC_CUTOVER_ASSIGNMENT',gen_random_uuid(),
    jsonb_build_object('actor','SYSTEM_MIGRATION_009','staffId',s.id,'roleId',r.id,
        'before',jsonb_build_object('channelRole',c.legacy_role,'authVersion',c.old_auth_version),
        'after',jsonb_build_object('roleCode',r.code,'channelRole',s.role,'authVersion',s.auth_version))
FROM foundation.rbac_cutover_stage c JOIN foundation.staff s ON s.id=c.staff_id JOIN foundation.roles r ON r.code=c.code;
DROP TABLE foundation.rbac_cutover_stage;

-- Writers (including the API) acquire this same transaction lock BEFORE any
-- staff/session/role row lock. Readers needing a consistent policy snapshot may
-- take the matching shared lock. PostgreSQL READ COMMITTED is required: a stale
-- REPEATABLE READ snapshot cannot count the winner of a competing transaction.
CREATE FUNCTION foundation.rbac_lock_write() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'RBAC requires READ COMMITTED' USING ERRCODE='40001';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('fixlevelup:admin-invariant',0));
    RETURN NULL;
END $$;
CREATE TRIGGER rbac_staff_write BEFORE INSERT OR UPDATE OF role,employment_state ON foundation.staff
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.rbac_lock_write();
CREATE TRIGGER rbac_assignment_write BEFORE INSERT OR UPDATE OR DELETE ON foundation.staff_role_assignments
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.rbac_lock_write();
CREATE TRIGGER rbac_role_write BEFORE INSERT OR UPDATE OR DELETE ON foundation.roles
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.rbac_lock_write();
CREATE TRIGGER rbac_catalog_write BEFORE UPDATE OR DELETE ON foundation.permissions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.rbac_lock_write();
CREATE TRIGGER rbac_grant_write BEFORE INSERT OR UPDATE OR DELETE ON foundation.role_permissions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.rbac_lock_write();
CREATE TRIGGER rbac_credential_removal BEFORE DELETE OR UPDATE OF staff_id ON foundation.staff_web_credentials
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.rbac_lock_write();

CREATE FUNCTION foundation.rbac_guard_role() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF OLD.role_type='SYSTEM' AND (TG_OP='DELETE' OR ROW(NEW.id,NEW.code,NEW.name,NEW.description,NEW.role_type,NEW.status)
        IS DISTINCT FROM ROW(OLD.id,OLD.code,OLD.name,OLD.description,OLD.role_type,OLD.status)) THEN
        RAISE EXCEPTION 'System role is immutable' USING ERRCODE='23514';
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    IF NEW.status='ARCHIVED' AND EXISTS (SELECT FROM foundation.staff_role_assignments a JOIN foundation.staff s ON s.id=a.staff_id
        WHERE a.role_id=NEW.id AND a.revoked_at IS NULL AND s.employment_state='ACTIVE') THEN
        RAISE EXCEPTION 'Role is in active use' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER rbac_guard_role BEFORE UPDATE OR DELETE ON foundation.roles FOR EACH ROW EXECUTE FUNCTION foundation.rbac_guard_role();

CREATE FUNCTION foundation.rbac_guard_catalog() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    -- Any change in protection requires a separately reviewed schema migration,
    -- not catalog DML which could silently delegate or disable a mandatory grant.
    IF (TG_OP='UPDATE' AND (OLD.protected IS DISTINCT FROM NEW.protected OR
        (OLD.protected AND (NEW.code<>OLD.code OR NOT NEW.active)))) OR (TG_OP='DELETE' AND OLD.protected) THEN
        RAISE EXCEPTION 'Mandatory permission definition is immutable' USING ERRCODE='23514';
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER rbac_guard_catalog BEFORE UPDATE OR DELETE ON foundation.permissions FOR EACH ROW EXECUTE FUNCTION foundation.rbac_guard_catalog();

CREATE FUNCTION foundation.rbac_guard_grant() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP<>'INSERT' AND EXISTS (SELECT FROM foundation.permissions WHERE code=OLD.permission_code AND protected) AND
        (TG_OP='DELETE' OR ROW(OLD.role_id,OLD.permission_code) IS DISTINCT FROM ROW(NEW.role_id,NEW.permission_code)) THEN
        RAISE EXCEPTION 'Cannot remove mandatory grant' USING ERRCODE='23514';
    END IF;
    IF TG_OP='DELETE' THEN RETURN OLD; END IF;
    IF EXISTS (SELECT FROM foundation.permissions WHERE code=NEW.permission_code AND protected) AND
        (NOT NEW.enabled OR NEW.scope_type<>'GLOBAL' OR NOT EXISTS (SELECT FROM foundation.roles
            WHERE id=NEW.role_id AND role_type='SYSTEM' AND code='ADMIN' AND status='ACTIVE')) THEN
        RAISE EXCEPTION 'Protected grant belongs to active SYSTEM ADMIN only' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER rbac_guard_grant BEFORE INSERT OR UPDATE OR DELETE ON foundation.role_permissions FOR EACH ROW EXECUTE FUNCTION foundation.rbac_guard_grant();

CREATE FUNCTION foundation.rbac_guard_assignment() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND (OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR
        ROW(OLD.id,OLD.staff_id,OLD.role_id,OLD.assigned_at,OLD.assigned_by) IS DISTINCT FROM ROW(NEW.id,NEW.staff_id,NEW.role_id,NEW.assigned_at,NEW.assigned_by))) THEN
        RAISE EXCEPTION 'Assignment history is append-only' USING ERRCODE='23514';
    END IF;
    IF TG_OP='INSERT' AND (NEW.revoked_at IS NOT NULL OR NOT EXISTS (SELECT FROM foundation.roles r JOIN foundation.staff s ON s.id=NEW.staff_id
        WHERE r.id=NEW.role_id AND r.status='ACTIVE' AND s.employment_state='ACTIVE')) THEN
        RAISE EXCEPTION 'Assignment needs active role and employee' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER rbac_guard_assignment BEFORE INSERT OR UPDATE OR DELETE ON foundation.staff_role_assignments FOR EACH ROW EXECUTE FUNCTION foundation.rbac_guard_assignment();

-- Deferred so creation/reassignment/credential bootstrap may execute in several
-- statements atomically. The partial unique index already guarantees at most one.
CREATE FUNCTION foundation.rbac_check_staff() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE subject uuid;
BEGIN
    IF TG_TABLE_NAME='staff' THEN subject:=NEW.id;
    ELSIF TG_TABLE_NAME='staff_web_credentials' THEN subject:=OLD.staff_id;
    ELSE subject:=NEW.staff_id; END IF;
    IF EXISTS (SELECT FROM foundation.staff WHERE id=subject) AND NOT EXISTS (
        SELECT FROM foundation.staff s JOIN foundation.staff_role_assignments a ON a.staff_id=s.id AND a.revoked_at IS NULL
        JOIN foundation.roles r ON r.id=a.role_id WHERE s.id=subject AND (s.employment_state='INACTIVE' OR r.status='ACTIVE')
          AND ((r.role_type='SYSTEM' AND r.code=s.role) OR (r.role_type='CUSTOM' AND s.role IN ('TECHNICIAN','MANAGER')))
          AND (r.code<>'ADMIN' OR EXISTS (SELECT FROM foundation.staff_web_credentials c WHERE c.staff_id=s.id))) THEN
        RAISE EXCEPTION 'Employee needs one valid current role and matching channel' USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS (SELECT FROM foundation.roles r JOIN foundation.staff_role_assignments a ON a.role_id=r.id AND a.revoked_at IS NULL
        JOIN foundation.staff s ON s.id=a.staff_id JOIN foundation.staff_web_credentials c ON c.staff_id=s.id
        WHERE r.code='ADMIN' AND r.role_type='SYSTEM' AND r.status='ACTIVE' AND s.role='ADMIN' AND s.employment_state='ACTIVE') THEN
        RAISE EXCEPTION 'Last active administrator' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER rbac_staff_current AFTER INSERT OR UPDATE OF employment_state,role ON foundation.staff
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.rbac_check_staff();
CREATE CONSTRAINT TRIGGER rbac_assignment_current AFTER INSERT OR UPDATE ON foundation.staff_role_assignments
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.rbac_check_staff();
CREATE CONSTRAINT TRIGGER rbac_credential_current AFTER DELETE OR UPDATE OF staff_id ON foundation.staff_web_credentials
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foundation.rbac_check_staff();

-- Trigger functions need no direct caller EXECUTE. All use invoker privileges,
-- fixed search_path and static qualified SQL. No new SECURITY DEFINER surface.
REVOKE ALL ON FUNCTION foundation.rbac_lock_write(),foundation.rbac_guard_role(),foundation.rbac_guard_grant(),
    foundation.rbac_guard_assignment(),foundation.rbac_check_staff(),foundation.rbac_guard_catalog() FROM PUBLIC;
REVOKE ALL ON foundation.permissions,foundation.roles,foundation.role_permissions,foundation.staff_role_assignments FROM PUBLIC;
REVOKE SELECT(id,staff_id,capability,scope,valid_from,valid_until,revoked_at,granted_by,created_at),
    INSERT(id,staff_id,capability,scope,valid_from,valid_until,granted_by,created_at), UPDATE(valid_until,revoked_at)
    ON foundation.user_permissions FROM fixlevelup_runtime;
GRANT SELECT(display_name,profile_version), INSERT(display_name), UPDATE(role,display_name,profile_version) ON foundation.staff TO fixlevelup_runtime;
GRANT SELECT(code,module,description,protected,active) ON foundation.permissions TO fixlevelup_runtime;
GRANT SELECT(id,code,name,description,role_type,status,version,created_by,updated_by,created_at,updated_at),
    INSERT(id,code,name,description,created_by,updated_by), UPDATE(name,description,status,version,updated_at,updated_by)
    ON foundation.roles TO fixlevelup_runtime;
GRANT SELECT(role_id,permission_code,scope_type,enabled), INSERT(role_id,permission_code,scope_type,enabled), UPDATE(enabled)
    ON foundation.role_permissions TO fixlevelup_runtime;
GRANT SELECT(id,staff_id,role_id,assigned_by,assigned_at,revoked_by,revoked_at), INSERT(id,staff_id,role_id,assigned_by), UPDATE(revoked_at,revoked_by)
    ON foundation.staff_role_assignments TO fixlevelup_runtime;

COMMIT;
