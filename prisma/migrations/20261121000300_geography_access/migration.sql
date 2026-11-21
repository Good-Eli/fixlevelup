BEGIN;

-- P03-02 geography access, data layer only (012). Additive DDL plus one narrow
-- widening of an existing constraint and one narrow column privilege. No seed of real
-- cities, districts, areas, employees or memberships; no destructive statement.
--
-- Owner decision (docs/P03-02-ACCESS.md, 21.11.2026): delegated management only in
-- assigned cities. A role grants the *operation*; an administrative city assignment
-- limits the *territory*; a technician city/zone admission is work eligibility and is
-- never administrative authority. The five geography codes are ordinary (never
-- `protected`): protection would make them mandatory on every ADMIN, while the owner
-- requires an explicit grant. The single exception is the first registered verified
-- SYSTEM ADMIN: it receives the five codes bound to its *original* assignment through
-- `geography_bootstrap_permissions`, not through its role, and no other administrator
-- ever inherits them.
--
-- Deliberate non-goals: no role receives a geography grant from this migration; no
-- automatic grant on role change, promotion, re-promotion or replay; no DELETE on grant
-- history (revocation is an UPDATE of `revoked_at`); no technician dispatch/schedule
-- table; no seed of the five catalog codes (the migration fails atomically if they
-- already exist, so an operator-seeded or drifted catalog can never be promoted here).
--
-- Lock order for every write (shared with P09 dispatch/schedule writers):
--   1. `foundation.rbac_lock_write()` -- the existing RBAC advisory lock, taken by the
--      statement triggers below (and by the application before it starts the command);
--   2. per-technician advisory lock, key `hashtextextended('fixlevelup:technician:' ||
--      technician_id::text, 0)` (row guards take it before validating/locking rows);
--   3. row locks (staff, membership, zone admission).
-- The key is the technician id alone, never `(technician, city)`: capacity and presence
-- are global across cities, so every technician operation must serialize on one key.
-- All writers must use READ COMMITTED; the RBAC lock function enforces that.

-- ---------------------------------------------------------------------------
-- 1. Catalog: five ordinary geography operation codes, or nothing at all.
-- ---------------------------------------------------------------------------
-- Refuse to run when any of the five codes already exists. A pre-existing row can only
-- come from an unapproved seed or drift, and re-using it could silently activate a
-- legacy GLOBAL grant that the owner never approved. There is deliberately no
-- `ON CONFLICT` clause: this migration either registers exactly five new inert codes or
-- aborts the whole transaction with one fixed, value-free error.
DO $$
BEGIN
    IF EXISTS (SELECT FROM foundation.permissions WHERE code IN ('geography.read','geography.manage',
        'geography.publish','staff.geography.read','staff.geography.manage')) THEN
        RAISE EXCEPTION 'Geography catalog must be empty before migration 012' USING ERRCODE='23514';
    END IF;
END $$;
INSERT INTO foundation.permissions(code,module,description,protected) VALUES
    ('geography.read','geography','Чтение города, районов, зон и их версий в разрешённых городах',false),
    ('geography.manage','geography','Подготовка настроек города, районов и черновых версий зон',false),
    ('geography.publish','geography','Публикация версий города и покрытия зон',false),
    ('staff.geography.read','geography','Чтение территориальных допусков мастеров',false),
    ('staff.geography.manage','geography','Выдача и отзыв территориальных допусков мастеров',false);

-- ---------------------------------------------------------------------------
-- 2. Narrow widening of the 009 scope CHECK.
-- ---------------------------------------------------------------------------
-- Same constraint name. Legacy codes keep exactly their previous rule: SELF only for
-- `staff.self.*`, GLOBAL for everything else. Only the five geography codes may now be
-- stored as CITY or GLOBAL, and even that is further restricted by the grant guard
-- below (GLOBAL and `geography.publish` only on SYSTEM ADMIN; the technician channel
-- role never receives geography at all).
ALTER TABLE foundation.role_permissions DROP CONSTRAINT role_permissions_scope_check;
ALTER TABLE foundation.role_permissions ADD CONSTRAINT role_permissions_scope_check CHECK (
    CASE
        WHEN permission_code LIKE 'staff.self.%' THEN scope_type = 'SELF'
        WHEN permission_code IN ('geography.read','geography.manage','geography.publish',
            'staff.geography.read','staff.geography.manage') THEN scope_type IN ('CITY','GLOBAL')
        ELSE scope_type = 'GLOBAL'
    END);

-- ---------------------------------------------------------------------------
-- 3. Founder-only bootstrap exception.
-- ---------------------------------------------------------------------------
-- One row per permission code issued to one assignment. The table is not a role grant:
-- the authorization layer resolves it only for the caller's *current* assignment, so a
-- reassignment, a revocation or a replay cannot resurrect it. `revoked_at` is the only
-- mutable column and only in the null -> non-null direction; INSERT is owner-only and
-- goes through foundation.issue_first_geo_permissions(); the runtime never inserts.
CREATE TABLE foundation.geography_bootstrap_permissions (
    assignment_id uuid NOT NULL,
    permission_code varchar(64) NOT NULL,
    revoked_at timestamptz(6),
    CONSTRAINT geography_bootstrap_permissions_pkey PRIMARY KEY (assignment_id, permission_code),
    CONSTRAINT geography_bootstrap_permissions_assignment_id_fkey FOREIGN KEY (assignment_id)
        REFERENCES foundation.staff_role_assignments(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT geography_bootstrap_permissions_permission_code_fkey FOREIGN KEY (permission_code)
        REFERENCES foundation.permissions(code) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT geography_bootstrap_permissions_code_check CHECK (permission_code IN
        ('geography.read','geography.manage','geography.publish','staff.geography.read','staff.geography.manage'))
);

-- ---------------------------------------------------------------------------
-- 4. Administrative city assignment: territory, not eligibility, not a role grant.
-- ---------------------------------------------------------------------------
-- `granted_at` is database-stamped by its DEFAULT; the runtime has no INSERT privilege
-- on that column and cannot backdate a grant. The partial unique index allows at most
-- one active assignment per staff+city pair; history stays as revoked rows (no DELETE).
-- The target must be an active web staff member with a current role (an administrative
-- grant applies to a person who actually works in the CRM), and the granting actor is
-- never the subject. Revocation stays possible after the city is suspended or the
-- employee is deactivated: the UPDATE path of the guard checks no external state.
CREATE TABLE foundation.staff_admin_city_assignments (
    id uuid PRIMARY KEY,
    staff_id uuid NOT NULL,
    city_id uuid NOT NULL,
    granted_by uuid NOT NULL,
    granted_at timestamptz(6) NOT NULL DEFAULT statement_timestamp(),
    revoked_at timestamptz(6),
    revoked_by uuid,
    CONSTRAINT staff_admin_city_assignments_staff_id_fkey FOREIGN KEY (staff_id)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT staff_admin_city_assignments_city_id_fkey FOREIGN KEY (city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT staff_admin_city_assignments_granted_by_fkey FOREIGN KEY (granted_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT staff_admin_city_assignments_revoked_by_fkey FOREIGN KEY (revoked_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT staff_admin_city_assignments_actor_check CHECK (
        granted_by <> staff_id AND (revoked_by IS NULL OR revoked_by <> staff_id)),
    CONSTRAINT staff_admin_city_assignments_revoke_check CHECK (
        (revoked_at IS NULL) = (revoked_by IS NULL)),
    CONSTRAINT staff_admin_city_assignments_period_check CHECK (
        revoked_at IS NULL OR revoked_at >= granted_at)
);
CREATE UNIQUE INDEX staff_admin_city_assignments_active_key
    ON foundation.staff_admin_city_assignments(staff_id, city_id) WHERE revoked_at IS NULL;
CREATE INDEX staff_admin_city_assignments_city_idx
    ON foundation.staff_admin_city_assignments(city_id) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- 5. Technician city admission: dated work eligibility in one city.
-- ---------------------------------------------------------------------------
-- Periods are half-open `[valid_from, valid_to)`, `valid_to IS NULL` means "open". A
-- technician may hold several *disjoint* dated admissions for one city over time; an
-- expired row (even if never revoked) must not block a new period. Overlap is refused
-- by the guard under the per-technician lock, adjacent periods are allowed, and at most
-- one *open-ended* live admission per technician+city exists (declarative index for the
-- common case). There is no `revoked_at >= valid_from` rule: a future-dated admission
-- must be revocable, so revocation may precede its own start.
CREATE TABLE foundation.technician_city_memberships (
    id uuid PRIMARY KEY,
    technician_id uuid NOT NULL,
    city_id uuid NOT NULL,
    valid_from timestamptz(6) NOT NULL,
    valid_to timestamptz(6),
    approved_by uuid NOT NULL,
    revoked_at timestamptz(6),
    revoked_by uuid,
    CONSTRAINT technician_city_memberships_technician_id_fkey FOREIGN KEY (technician_id)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT technician_city_memberships_city_id_fkey FOREIGN KEY (city_id)
        REFERENCES foundation.service_cities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT technician_city_memberships_approved_by_fkey FOREIGN KEY (approved_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT technician_city_memberships_revoked_by_fkey FOREIGN KEY (revoked_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT technician_city_memberships_interval_check CHECK (
        valid_to IS NULL OR valid_to > valid_from),
    CONSTRAINT technician_city_memberships_revoke_check CHECK (
        (revoked_at IS NULL) = (revoked_by IS NULL)),
    CONSTRAINT technician_city_memberships_actor_check CHECK (
        approved_by <> technician_id AND (revoked_by IS NULL OR revoked_by <> technician_id))
);
CREATE UNIQUE INDEX technician_city_memberships_open_key
    ON foundation.technician_city_memberships(technician_id, city_id)
    WHERE revoked_at IS NULL AND valid_to IS NULL;
CREATE INDEX technician_city_memberships_technician_city_idx
    ON foundation.technician_city_memberships(technician_id, city_id);
CREATE INDEX technician_city_memberships_city_idx
    ON foundation.technician_city_memberships(city_id) WHERE revoked_at IS NULL;
-- Composite-FK target for zone admissions: the membership id alone would not prove the
-- same technician and the same city.
CREATE UNIQUE INDEX technician_city_memberships_identity_key
    ON foundation.technician_city_memberships(technician_id, city_id, id);

-- ---------------------------------------------------------------------------
-- 6. Technician zone admission: dated eligibility for one area of the same city.
-- ---------------------------------------------------------------------------
-- Both parent links are composite and city-scoped: `(city_id, service_area_id)` names a
-- real area of that city (011 unique index), and `(technician_id, city_id,
-- membership_id)` names a city admission of the same technician in the same city. The
-- guard below additionally requires the whole admission period to sit inside the
-- membership period and refuses overlapping live admissions for one technician+area, so
-- a zone can never outlive or escape the city grant it depends on.
CREATE TABLE foundation.technician_service_areas (
    id uuid PRIMARY KEY,
    technician_id uuid NOT NULL,
    city_id uuid NOT NULL,
    service_area_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    valid_from timestamptz(6) NOT NULL,
    valid_to timestamptz(6),
    approved_by uuid NOT NULL,
    revoked_at timestamptz(6),
    revoked_by uuid,
    CONSTRAINT technician_service_areas_technician_id_fkey FOREIGN KEY (technician_id)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT technician_service_areas_city_id_service_area_id_fkey FOREIGN KEY (city_id, service_area_id)
        REFERENCES foundation.service_areas(city_id, id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT technician_service_areas_technician_id_city_id_membership_id_fkey
        FOREIGN KEY (technician_id, city_id, membership_id)
        REFERENCES foundation.technician_city_memberships(technician_id, city_id, id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT technician_service_areas_approved_by_fkey FOREIGN KEY (approved_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT technician_service_areas_revoked_by_fkey FOREIGN KEY (revoked_by)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT technician_service_areas_interval_check CHECK (
        valid_to IS NULL OR valid_to > valid_from),
    CONSTRAINT technician_service_areas_revoke_check CHECK (
        (revoked_at IS NULL) = (revoked_by IS NULL)),
    CONSTRAINT technician_service_areas_actor_check CHECK (
        approved_by <> technician_id AND (revoked_by IS NULL OR revoked_by <> technician_id))
);
CREATE UNIQUE INDEX technician_service_areas_open_key
    ON foundation.technician_service_areas(technician_id, service_area_id)
    WHERE revoked_at IS NULL AND valid_to IS NULL;
CREATE INDEX technician_service_areas_technician_area_idx
    ON foundation.technician_service_areas(technician_id, service_area_id);
CREATE INDEX technician_service_areas_membership_idx
    ON foundation.technician_service_areas(membership_id) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- 7. Command receipts: idempotency evidence, minimal and immutable.
-- ---------------------------------------------------------------------------
-- Deliberately no request body, no free text and no personal data: only the actor, the
-- operation name, the Idempotency-Key, the SHA-256 of the canonical request and the
-- created entity id/version. A replay with the same body hash returns the stored
-- receipt; a different body with the same key is a conflict. Rows are append-only.
CREATE TABLE foundation.geography_command_receipts (
    actor_id uuid NOT NULL,
    operation varchar(64) NOT NULL,
    key uuid NOT NULL,
    body_hash char(64) NOT NULL,
    entity_id uuid NOT NULL,
    entity_version integer NOT NULL,
    CONSTRAINT geography_command_receipts_pkey PRIMARY KEY (actor_id, operation, key),
    CONSTRAINT geography_command_receipts_actor_id_fkey FOREIGN KEY (actor_id)
        REFERENCES foundation.staff(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT geography_command_receipts_operation_check CHECK (operation ~ '^[A-Za-z][A-Za-z0-9]{0,63}$'),
    CONSTRAINT geography_command_receipts_body_hash_check CHECK (body_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT geography_command_receipts_entity_version_check CHECK (entity_version >= 0)
);

-- ---------------------------------------------------------------------------
-- 8. Role grant guard: the only place geography reaches a role.
-- ---------------------------------------------------------------------------
-- Defense in depth for the server rule (the role editor enforces the same contract):
--   * a geography code never belongs to the SYSTEM TECHNICIAN channel role;
--   * GLOBAL geography and `geography.publish` belong to SYSTEM ADMIN only;
--   * every other geography grant is CITY (the scope CHECK already allows only
--     CITY/GLOBAL, and this guard rejects GLOBAL for a non-administrator).
-- The runtime may update `scope_type` (see ACL below) so the role editor can move a
-- grant between CITY and GLOBAL; this guard is what keeps that write non-escalating.
-- A catalog row, a role label or a request string is never authority.
CREATE FUNCTION foundation.geography_guard_role_grant() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    target_admin boolean;
    target_technician boolean;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    IF NEW.permission_code NOT IN ('geography.read','geography.manage','geography.publish',
        'staff.geography.read','staff.geography.manage') THEN
        RETURN NEW;
    END IF;
    SELECT r.role_type = 'SYSTEM' AND r.code = 'ADMIN' AND r.status = 'ACTIVE',
           r.role_type = 'SYSTEM' AND r.code = 'TECHNICIAN'
      INTO target_admin, target_technician
      FROM foundation.roles r WHERE r.id = NEW.role_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Geography grant needs an existing role' USING ERRCODE='23503';
    END IF;
    -- Disabling a row is a removal, never an escalation: it must stay possible even for a
    -- drifted row whose role/scope combination would no longer be grantable.
    IF NOT NEW.enabled THEN
        RETURN NEW;
    END IF;
    IF target_technician THEN
        RAISE EXCEPTION 'Geography grants never belong to the technician channel role' USING ERRCODE='23514';
    END IF;
    IF NEW.scope_type = 'GLOBAL' AND NOT target_admin THEN
        RAISE EXCEPTION 'Only SYSTEM ADMIN may hold GLOBAL geography' USING ERRCODE='23514';
    END IF;
    IF NEW.permission_code = 'geography.publish' AND NOT target_admin THEN
        RAISE EXCEPTION 'Only SYSTEM ADMIN may hold geography.publish' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER geography_guard_role_grant BEFORE INSERT OR UPDATE ON foundation.role_permissions
    FOR EACH ROW EXECUTE FUNCTION foundation.geography_guard_role_grant();

-- ---------------------------------------------------------------------------
-- 9. Bootstrap guard and the single founder-only issue function.
-- ---------------------------------------------------------------------------
-- The guard re-proves the founder binding on every INSERT, so even the schema owner
-- cannot issue these rows to a different assignment: the row must belong to the
-- singleton `staff_bootstrap_marker` staff, that staff must be an ACTIVE SYSTEM ADMIN
-- with a web credential and a live SYSTEM ADMIN assignment, and that assignment must be
-- the staff's ONLY assignment ever. A demotion followed by a re-promotion creates an
-- additional assignment and therefore never qualifies again -- there is no timestamp or
-- UUID ordering to forge. `revoked_at` may only move from NULL to a value; DELETE is
-- refused. The UPDATE path deliberately reads no table, so the runtime can revoke a
-- grant with its narrow `UPDATE(revoked_at)` privilege and no access to the marker.
CREATE FUNCTION foundation.geography_bootstrap_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    founder_assignment uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Geography bootstrap grants are append-only' USING ERRCODE='23514';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
            OR NEW.assignment_id IS DISTINCT FROM OLD.assignment_id
            OR NEW.permission_code IS DISTINCT FROM OLD.permission_code THEN
            RAISE EXCEPTION 'Geography bootstrap grant may only be revoked once' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    SELECT a.id INTO founder_assignment
    FROM foundation.staff_bootstrap_marker b
    JOIN foundation.staff s ON s.id = b.staff_id
    JOIN foundation.staff_web_credentials c ON c.staff_id = s.id
    JOIN foundation.staff_role_assignments a ON a.staff_id = s.id AND a.revoked_at IS NULL
    JOIN foundation.roles r ON r.id = a.role_id
    WHERE b.id = 1 AND s.employment_state = 'ACTIVE' AND s.role = 'ADMIN'
      AND r.role_type = 'SYSTEM' AND r.code = 'ADMIN' AND r.status = 'ACTIVE'
      AND a.id = NEW.assignment_id
      AND NOT EXISTS (SELECT FROM foundation.staff_role_assignments other
          WHERE other.staff_id = a.staff_id AND other.id <> a.id);
    IF founder_assignment IS NULL THEN
        RAISE EXCEPTION 'Geography bootstrap grant belongs only to the original verified bootstrap assignment'
            USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER geography_bootstrap_guard BEFORE INSERT OR UPDATE OR DELETE
    ON foundation.geography_bootstrap_permissions
    FOR EACH ROW EXECUTE FUNCTION foundation.geography_bootstrap_guard();

-- Agreed interface for the fresh-bootstrap hook and for the one upgrade call below:
--
--   foundation.issue_first_geo_permissions() RETURNS void
--
-- SECURITY INVOKER with a fixed search_path, so the caller's own privileges apply. It is
-- executable by the migration/bootstrap principal only: the runtime role needs no read
-- access to `staff_bootstrap_marker` and can never call it. The console bootstrap must
-- call it once, in the same transaction, right after it creates the first SYSTEM ADMIN
-- role assignment. The function is idempotent and never touches `role_permissions`, so
-- "a role change grants geography" is impossible. A missing marker (fresh database
-- before bootstrap), a non-ADMIN founder, a demoted or re-promoted founder (more than
-- one assignment) and an already-revoked row are all no-ops: no fallback to another
-- staff row, no re-issue, no un-revoke.
CREATE FUNCTION foundation.issue_first_geo_permissions() RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    founder_assignment uuid;
    issued integer;
BEGIN
    SELECT a.id INTO founder_assignment
    FROM foundation.staff_bootstrap_marker b
    JOIN foundation.staff s ON s.id = b.staff_id
    JOIN foundation.staff_web_credentials c ON c.staff_id = s.id
    JOIN foundation.staff_role_assignments a ON a.staff_id = s.id AND a.revoked_at IS NULL
    JOIN foundation.roles r ON r.id = a.role_id
    WHERE b.id = 1 AND s.employment_state = 'ACTIVE' AND s.role = 'ADMIN'
      AND r.role_type = 'SYSTEM' AND r.code = 'ADMIN' AND r.status = 'ACTIVE'
      AND NOT EXISTS (SELECT FROM foundation.staff_role_assignments other
          WHERE other.staff_id = a.staff_id AND other.id <> a.id);
    IF founder_assignment IS NULL THEN
        RETURN;
    END IF;
    INSERT INTO foundation.geography_bootstrap_permissions(assignment_id, permission_code)
    SELECT founder_assignment, code
    FROM unnest(ARRAY['geography.read','geography.manage','geography.publish',
        'staff.geography.read','staff.geography.manage']) AS code
    ON CONFLICT (assignment_id, permission_code) DO NOTHING;
    GET DIAGNOSTICS issued = ROW_COUNT;
    IF issued > 0 THEN
        -- Safe append-only marker of the first issue: no staff name, no contact data and
        -- no credential value, only the internal assignment id and the fixed code list.
        INSERT INTO foundation.audit_logs(id, operation, correlation_id, details)
        VALUES (gen_random_uuid(), 'GEOGRAPHY_BOOTSTRAP_PERMISSIONS', gen_random_uuid(),
            jsonb_build_object('actor','SYSTEM_MIGRATION_012','assignmentId',founder_assignment,
                'permissions',to_jsonb(ARRAY['geography.read','geography.manage','geography.publish',
                    'staff.geography.read','staff.geography.manage'])));
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 10. Administrative assignment guard.
-- ---------------------------------------------------------------------------
-- Target: an ACTIVE web staff member with a current role and a web credential (an
-- administrative territory applies to someone who actually works in the CRM), never a
-- technician channel employee. A MANAGER is a legal subject: administrative territory is
-- delegated *to* managers, it is only never delegated *by* them. The stored actor
-- (`granted_by` on INSERT, `revoked_by` on the revocation UPDATE) must itself be an
-- ACTIVE SYSTEM ADMIN with a live SYSTEM ADMIN assignment, so a manager cannot write a
-- city assignment even if the application guard were bypassed. The actor is never the
-- subject. After INSERT only the revocation pair may change, once; history is never
-- deleted. The RBAC advisory lock is taken by the statement trigger in section 13.
CREATE FUNCTION foundation.geography_admin_assignment_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    subject record;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Administrative city assignments are history; revoke instead of delete'
            USING ERRCODE='23514';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
            OR NEW.id IS DISTINCT FROM OLD.id OR NEW.staff_id IS DISTINCT FROM OLD.staff_id
            OR NEW.city_id IS DISTINCT FROM OLD.city_id OR NEW.granted_by IS DISTINCT FROM OLD.granted_by
            OR NEW.granted_at IS DISTINCT FROM OLD.granted_at THEN
            RAISE EXCEPTION 'Administrative city assignment may only be revoked once' USING ERRCODE='23514';
        END IF;
        IF NEW.revoked_by IS NULL OR NOT EXISTS (
            SELECT FROM foundation.staff a
            JOIN foundation.staff_role_assignments ar ON ar.staff_id = a.id AND ar.revoked_at IS NULL
            JOIN foundation.roles ar_role ON ar_role.id = ar.role_id
            WHERE a.id = NEW.revoked_by AND a.employment_state = 'ACTIVE' AND a.role = 'ADMIN'
              AND ar_role.role_type = 'SYSTEM' AND ar_role.code = 'ADMIN' AND ar_role.status = 'ACTIVE') THEN
            RAISE EXCEPTION 'Administrative city assignment revocation needs an active SYSTEM ADMIN revoker'
                USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    SELECT s.role AS channel_role, s.employment_state,
           EXISTS (SELECT FROM foundation.staff_web_credentials c WHERE c.staff_id = s.id) AS has_web,
           EXISTS (SELECT FROM foundation.staff_role_assignments a
                   WHERE a.staff_id = s.id AND a.revoked_at IS NULL) AS has_role
      INTO subject FROM foundation.staff s WHERE s.id = NEW.staff_id;
    -- FOUND is checked before any field of `subject`: an unassigned record cannot be read.
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Administrative city assignment target must be an active web staff member with a current role'
            USING ERRCODE='23514';
    END IF;
    IF subject.employment_state <> 'ACTIVE' OR subject.channel_role = 'TECHNICIAN'
        OR NOT subject.has_web OR NOT subject.has_role THEN
        RAISE EXCEPTION 'Administrative city assignment target must be an active web staff member with a current role'
            USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS (
        SELECT FROM foundation.staff a
        JOIN foundation.staff_role_assignments ar ON ar.staff_id = a.id AND ar.revoked_at IS NULL
        JOIN foundation.roles ar_role ON ar_role.id = ar.role_id
        WHERE a.id = NEW.granted_by AND a.employment_state = 'ACTIVE' AND a.role = 'ADMIN'
          AND ar_role.role_type = 'SYSTEM' AND ar_role.code = 'ADMIN' AND ar_role.status = 'ACTIVE') THEN
        RAISE EXCEPTION 'Administrative city assignment needs an active SYSTEM ADMIN grantor' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER geography_admin_assignment_guard BEFORE INSERT OR UPDATE OR DELETE
    ON foundation.staff_admin_city_assignments
    FOR EACH ROW EXECUTE FUNCTION foundation.geography_admin_assignment_guard();

-- ---------------------------------------------------------------------------
-- 11. Technician admission guards (city and zone).
-- ---------------------------------------------------------------------------
-- Both guards take the canonical per-technician advisory lock before any check, so the
-- lock order is RBAC statement lock -> technician lock -> row locks even if an
-- application command forgot the explicit lock call. INSERT requires an ACTIVE
-- technician (channel role TECHNICIAN) and an ACTIVE approving actor, and refuses an
-- overlap with any live admission of the same technician+city (23P01, adjacent and
-- expired periods are fine). UPDATE is a one-way revocation of the immutable row;
-- DELETE is refused. The UPDATE path reads no table, so revocation also works for a
-- deactivated technician or a suspended city.
CREATE FUNCTION foundation.geography_membership_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    subject record;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Technician city memberships are history; revoke instead of delete' USING ERRCODE='23514';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('fixlevelup:technician:' || NEW.technician_id::text, 0));
    IF TG_OP = 'UPDATE' THEN
        IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
            OR NEW.id IS DISTINCT FROM OLD.id OR NEW.technician_id IS DISTINCT FROM OLD.technician_id
            OR NEW.city_id IS DISTINCT FROM OLD.city_id OR NEW.valid_from IS DISTINCT FROM OLD.valid_from
            OR NEW.valid_to IS DISTINCT FROM OLD.valid_to OR NEW.approved_by IS DISTINCT FROM OLD.approved_by THEN
            RAISE EXCEPTION 'Technician city membership may only be revoked once' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    SELECT s.role AS channel_role, s.employment_state INTO subject
      FROM foundation.staff s WHERE s.id = NEW.technician_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Technician city membership needs an active technician' USING ERRCODE='23514';
    END IF;
    IF subject.employment_state <> 'ACTIVE' OR subject.channel_role <> 'TECHNICIAN' THEN
        RAISE EXCEPTION 'Technician city membership needs an active technician' USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS (SELECT FROM foundation.staff a WHERE a.id = NEW.approved_by AND a.employment_state = 'ACTIVE') THEN
        RAISE EXCEPTION 'Technician city membership needs an active approving actor' USING ERRCODE='23514';
    END IF;
    IF EXISTS (SELECT FROM foundation.technician_city_memberships m
               WHERE m.technician_id = NEW.technician_id AND m.city_id = NEW.city_id
                 AND m.revoked_at IS NULL
                 AND tstzrange(m.valid_from, m.valid_to, '[)') && tstzrange(NEW.valid_from, NEW.valid_to, '[)')) THEN
        RAISE EXCEPTION 'Technician city membership periods must not overlap' USING ERRCODE='23P01';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER geography_membership_guard BEFORE INSERT OR UPDATE OR DELETE
    ON foundation.technician_city_memberships
    FOR EACH ROW EXECUTE FUNCTION foundation.geography_membership_guard();

CREATE FUNCTION foundation.geography_zone_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    subject record;
    membership record;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Technician zone admissions are history; revoke instead of delete' USING ERRCODE='23514';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('fixlevelup:technician:' || NEW.technician_id::text, 0));
    IF TG_OP = 'UPDATE' THEN
        IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
            OR NEW.id IS DISTINCT FROM OLD.id OR NEW.technician_id IS DISTINCT FROM OLD.technician_id
            OR NEW.city_id IS DISTINCT FROM OLD.city_id OR NEW.service_area_id IS DISTINCT FROM OLD.service_area_id
            OR NEW.membership_id IS DISTINCT FROM OLD.membership_id OR NEW.valid_from IS DISTINCT FROM OLD.valid_from
            OR NEW.valid_to IS DISTINCT FROM OLD.valid_to OR NEW.approved_by IS DISTINCT FROM OLD.approved_by THEN
            RAISE EXCEPTION 'Technician zone admission may only be revoked once' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    SELECT s.role AS channel_role, s.employment_state INTO subject
      FROM foundation.staff s WHERE s.id = NEW.technician_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Technician zone admission needs an active technician' USING ERRCODE='23514';
    END IF;
    IF subject.employment_state <> 'ACTIVE' OR subject.channel_role <> 'TECHNICIAN' THEN
        RAISE EXCEPTION 'Technician zone admission needs an active technician' USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS (SELECT FROM foundation.staff a WHERE a.id = NEW.approved_by AND a.employment_state = 'ACTIVE') THEN
        RAISE EXCEPTION 'Technician zone admission needs an active approving actor' USING ERRCODE='23514';
    END IF;
    -- The city admission row is locked before the containment decision, so a concurrent
    -- revocation cannot slip between this check and the INSERT.
    SELECT m.technician_id, m.city_id, m.valid_from, m.valid_to, m.revoked_at INTO membership
      FROM foundation.technician_city_memberships m WHERE m.id = NEW.membership_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Technician zone admission needs an existing city membership' USING ERRCODE='23503';
    END IF;
    IF membership.technician_id <> NEW.technician_id OR membership.city_id <> NEW.city_id THEN
        RAISE EXCEPTION 'Technician zone admission membership must belong to the same technician and city'
            USING ERRCODE='23503';
    END IF;
    IF membership.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'Technician zone admission needs a live city membership' USING ERRCODE='23514';
    END IF;
    IF NEW.valid_from < membership.valid_from
        OR (NEW.valid_to IS NULL AND membership.valid_to IS NOT NULL)
        OR (NEW.valid_to IS NOT NULL AND membership.valid_to IS NOT NULL AND NEW.valid_to > membership.valid_to) THEN
        RAISE EXCEPTION 'Technician zone admission period must sit inside its city membership period'
            USING ERRCODE='23514';
    END IF;
    IF EXISTS (SELECT FROM foundation.technician_service_areas z
               WHERE z.technician_id = NEW.technician_id AND z.service_area_id = NEW.service_area_id
                 AND z.revoked_at IS NULL
                 AND tstzrange(z.valid_from, z.valid_to, '[)') && tstzrange(NEW.valid_from, NEW.valid_to, '[)')) THEN
        RAISE EXCEPTION 'Technician zone admission periods must not overlap' USING ERRCODE='23P01';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER geography_zone_guard BEFORE INSERT OR UPDATE OR DELETE
    ON foundation.technician_service_areas
    FOR EACH ROW EXECUTE FUNCTION foundation.geography_zone_guard();

-- Revocation may arrive in either order inside one transaction (zone rows first, then
-- the membership, or the membership first as the application command does), so the
-- "no effective zone after the city grant is gone" rule is checked at COMMIT. A
-- committed state can never contain an active zone admission whose city membership is
-- revoked; a forgotten zone revocation rolls the whole transaction back.
CREATE FUNCTION foundation.geography_membership_zone_consistency() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE
    subject_membership uuid;
BEGIN
    IF TG_TABLE_NAME = 'technician_city_memberships' THEN
        subject_membership := NEW.id;
    ELSE
        subject_membership := NEW.membership_id;
    END IF;
    IF EXISTS (SELECT FROM foundation.technician_city_memberships m
               WHERE m.id = subject_membership AND m.revoked_at IS NOT NULL)
       AND EXISTS (SELECT FROM foundation.technician_service_areas z
                   WHERE z.membership_id = subject_membership AND z.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'Revoked city membership cannot keep active zone admissions' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER geography_membership_zone_consistency
    AFTER UPDATE OF revoked_at ON foundation.technician_city_memberships
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION foundation.geography_membership_zone_consistency();
CREATE CONSTRAINT TRIGGER geography_zone_membership_consistency
    AFTER INSERT OR UPDATE OF revoked_at, membership_id ON foundation.technician_service_areas
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION foundation.geography_membership_zone_consistency();

-- ---------------------------------------------------------------------------
-- 12. Immutability of receipts and refusal of TRUNCATE.
-- ---------------------------------------------------------------------------
CREATE FUNCTION foundation.geography_receipts_immutable() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'Geography command receipts are append-only (%)', TG_TABLE_NAME USING ERRCODE='23514';
END $$;
CREATE TRIGGER geography_receipts_immutable BEFORE UPDATE OR DELETE ON foundation.geography_command_receipts
    FOR EACH ROW EXECUTE FUNCTION foundation.geography_receipts_immutable();

CREATE FUNCTION foundation.geography_reject_truncate() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'Geography grant history is append-only (%)', TG_TABLE_NAME USING ERRCODE='23514';
END $$;
CREATE TRIGGER geography_bootstrap_no_truncate BEFORE TRUNCATE ON foundation.geography_bootstrap_permissions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.geography_reject_truncate();
CREATE TRIGGER geography_admin_assignment_no_truncate BEFORE TRUNCATE ON foundation.staff_admin_city_assignments
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.geography_reject_truncate();
CREATE TRIGGER geography_membership_no_truncate BEFORE TRUNCATE ON foundation.technician_city_memberships
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.geography_reject_truncate();
CREATE TRIGGER geography_zone_no_truncate BEFORE TRUNCATE ON foundation.technician_service_areas
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.geography_reject_truncate();
CREATE TRIGGER geography_receipts_no_truncate BEFORE TRUNCATE ON foundation.geography_command_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.geography_reject_truncate();

-- ---------------------------------------------------------------------------
-- 13. RBAC advisory lock on every geography grant write (step 1 of the lock order).
-- ---------------------------------------------------------------------------
-- Reuses the 009 lock function unchanged: the same key serializes a role/permission
-- change with a city assignment or a technician admission, so a command never decides
-- access from a snapshot that a concurrent role edit has already invalidated. The
-- statement trigger fires before the row guards, which take the technician lock.
CREATE TRIGGER geography_bootstrap_write BEFORE INSERT OR UPDATE ON foundation.geography_bootstrap_permissions
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.rbac_lock_write();
CREATE TRIGGER geography_admin_assignment_write BEFORE INSERT OR UPDATE ON foundation.staff_admin_city_assignments
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.rbac_lock_write();
CREATE TRIGGER geography_membership_write BEFORE INSERT OR UPDATE ON foundation.technician_city_memberships
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.rbac_lock_write();
CREATE TRIGGER geography_zone_write BEFORE INSERT OR UPDATE ON foundation.technician_service_areas
    FOR EACH STATEMENT EXECUTE FUNCTION foundation.rbac_lock_write();

-- ---------------------------------------------------------------------------
-- 14. Runtime privileges: column-scoped, least privilege, no DELETE of history.
-- ---------------------------------------------------------------------------
-- Not granted to the runtime: INSERT on the bootstrap table (owner/helper only), any
-- DELETE on a grant table, TRUNCATE anywhere, UPDATE of any identity/period/actor
-- column, INSERT of `granted_at` (database default owns it), and every guard/validator
-- function EXECUTE (trigger functions need none, and the bootstrap issue function is
-- migrator-only). `UPDATE(scope_type)` on role_permissions is the single deliberate
-- widening: the role editor moves a geography grant between CITY and GLOBAL, and the
-- guard above refuses GLOBAL for a non-administrator and publish for anyone but SYSTEM
-- ADMIN. The readiness probe must add `role_permissions.scope_type = UPDATE`.
REVOKE ALL ON FUNCTION foundation.geography_guard_role_grant(), foundation.geography_bootstrap_guard(),
    foundation.issue_first_geo_permissions(), foundation.geography_admin_assignment_guard(),
    foundation.geography_membership_guard(), foundation.geography_zone_guard(),
    foundation.geography_membership_zone_consistency(), foundation.geography_receipts_immutable(),
    foundation.geography_reject_truncate() FROM PUBLIC;
REVOKE ALL ON foundation.geography_bootstrap_permissions, foundation.staff_admin_city_assignments,
    foundation.technician_city_memberships, foundation.technician_service_areas,
    foundation.geography_command_receipts FROM PUBLIC;

-- The founder issue function is executable by the migration/bootstrap principal only.
GRANT EXECUTE ON FUNCTION foundation.issue_first_geo_permissions() TO fixlevelup_migrator;

GRANT SELECT(assignment_id,permission_code,revoked_at), UPDATE(revoked_at)
    ON foundation.geography_bootstrap_permissions TO fixlevelup_runtime;

GRANT SELECT(id,staff_id,city_id,granted_by,granted_at,revoked_at,revoked_by),
    INSERT(id,staff_id,city_id,granted_by), UPDATE(revoked_at,revoked_by)
    ON foundation.staff_admin_city_assignments TO fixlevelup_runtime;

GRANT SELECT(id,technician_id,city_id,valid_from,valid_to,approved_by,revoked_at,revoked_by),
    INSERT(id,technician_id,city_id,valid_from,valid_to,approved_by), UPDATE(revoked_at,revoked_by)
    ON foundation.technician_city_memberships TO fixlevelup_runtime;

GRANT SELECT(id,technician_id,city_id,service_area_id,membership_id,valid_from,valid_to,approved_by,revoked_at,revoked_by),
    INSERT(id,technician_id,city_id,service_area_id,membership_id,valid_from,valid_to,approved_by),
    UPDATE(revoked_at,revoked_by)
    ON foundation.technician_service_areas TO fixlevelup_runtime;

GRANT SELECT(actor_id,operation,key,body_hash,entity_id,entity_version),
    INSERT(actor_id,operation,key,body_hash,entity_id,entity_version)
    ON foundation.geography_command_receipts TO fixlevelup_runtime;

-- The role editor writes the geography scope explicitly. 009 granted only UPDATE(enabled);
-- this is the narrow delta. Everything else about a role grant stays non-updatable.
GRANT UPDATE(scope_type) ON foundation.role_permissions TO fixlevelup_runtime;

-- P03-01 city write path (010 granted read-only resolver columns only). Publication and
-- activation stay separate operations; the database still owns `row_version`, and the
-- published city/company revisions remain immutable for everyone.
GRANT SELECT(id,code,lifecycle,row_version,current_version_id), INSERT(id,code),
    UPDATE(lifecycle,current_version_id) ON foundation.service_cities TO fixlevelup_runtime;
GRANT SELECT(id,city_id,version,display_name,address_display,timezone,public_contact,office_hours,
        reviewed_by,published_at),
    INSERT(id,city_id,version,display_name,address_display,timezone,public_contact,office_hours,reviewed_by)
    ON foundation.service_city_versions TO fixlevelup_runtime;
GRANT SELECT(id,version,launch_mode,primary_city_id,reviewed_by,published_at),
    INSERT(id,version,launch_mode,primary_city_id,reviewed_by)
    ON foundation.business_settings_versions TO fixlevelup_runtime;
-- The city version CHECK and timezone trigger call these two validators as the invoking
-- user, so the runtime needs EXECUTE on exactly these two functions (and on nothing else).
GRANT EXECUTE ON FUNCTION foundation.city_office_hours_is_valid(jsonb),
    foundation.city_timezone_is_valid(text) TO fixlevelup_runtime;

-- P03-02 area write path (011 granted nothing). Draft coverage deletion is the only
-- DELETE granted: the 011 coverage guard refuses it as soon as the parent revision is
-- published, so the runtime can only correct a draft. `row_version` on a revision is
-- updatable because the 011 coverage guard bumps the draft revision with
-- `UPDATE ... SET row_version = row_version`.
GRANT SELECT(id,city_id,code,name,archived_at,row_version), INSERT(id,city_id,code,name),
    UPDATE(name,archived_at) ON foundation.administrative_districts TO fixlevelup_runtime;
GRANT SELECT(id,city_id,code,current_version_id,archived_at,row_version), INSERT(id,city_id,code),
    UPDATE(current_version_id,archived_at) ON foundation.service_areas TO fixlevelup_runtime;
GRANT SELECT(id,city_id,area_id,version,name,coverage_description,address_criteria,created_by,
        published_at,published_by,row_version),
    INSERT(id,city_id,area_id,version,name,coverage_description,address_criteria,created_by),
    UPDATE(name,coverage_description,address_criteria,published_at,published_by,row_version)
    ON foundation.service_area_versions TO fixlevelup_runtime;
GRANT SELECT(city_id,area_version_id,district_id,relation,description),
    INSERT(city_id,area_version_id,district_id,relation,description), UPDATE(relation,description), DELETE
    ON foundation.service_area_district_coverage TO fixlevelup_runtime;

-- ---------------------------------------------------------------------------
-- 15. One upgrade issue: existing verified bootstrap administrator.
-- ---------------------------------------------------------------------------
-- Fresh databases have no marker yet, so this is a no-op there; the console bootstrap
-- calls the same function after it creates the first role assignment (migrator role).
-- Replaying this migration cannot re-issue, un-revoke or extend anything.
SELECT foundation.issue_first_geo_permissions();

COMMIT;
