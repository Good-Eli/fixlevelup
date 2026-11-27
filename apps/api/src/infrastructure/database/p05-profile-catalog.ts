import type { Client } from 'pg';

type CatalogClient = Pick<Client, 'query'>;
export type P05Profile = 'S0' | 'S1' | 'S2' | 'S3';
type Layer = 'S1' | 'S2';
export const S3_HEAD = '20261125000100_request_intake_effects';

// Preserve the original migration pins; the independent enforcement hash below
// additionally covers catalog properties that those byte formats did not encode.
const BASE_PINS: Readonly<Record<Layer, string>> = Object.freeze({
  S1: '6626dcc51bf6f5c59da82b1d1d5e05e55bb7757d77ce9963d1b182d90d3dde27',
  S2: '978d2d36f4c0c385492b2478cfe1663b97ca3a18fa890e53fb97c3c0ffd15a45',
});
// ACL facts concern the runtime role even when an operator inspects a closed
// restore target. Identity of the *current* runtime connection is checked by
// the admission gate, independently of the physical catalog.
const S1_SQL = `WITH tables AS (
        SELECT * FROM pg_class WHERE relnamespace='foundation'::regnamespace AND relname IN (
          'request_policy_packages','customers','requests','request_payload_cells',
          'request_contact_revisions','request_address_revisions','request_appliance_revisions',
          'request_faults','request_preference_revisions','request_events')
      ), fence_relations AS (
        SELECT * FROM pg_class WHERE relnamespace='foundation'::regnamespace AND relname IN (
          'business_settings_versions','service_cities','service_city_versions','administrative_districts',
          'service_areas','service_area_versions','service_area_district_coverage',
          'reference_entries','reference_entry_versions')
      ), columns AS (
        SELECT t.relname,a.*,p.typname,pg_get_expr(d.adbin,d.adrelid) AS default_expr
        FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid JOIN pg_type p ON p.oid=a.atttypid
        LEFT JOIN pg_attrdef d ON d.adrelid=t.oid AND d.adnum=a.attnum
        WHERE a.attnum>0 AND NOT a.attisdropped
      ), triggers AS (
        SELECT g.* FROM pg_trigger g WHERE NOT g.tgisinternal AND g.tgrelid IN (SELECT oid FROM tables)
      ), fence_triggers AS (
        SELECT g.* FROM pg_trigger g
        WHERE NOT g.tgisinternal AND g.tgrelid IN (SELECT oid FROM fence_relations)
          AND g.tgfoid='foundation.geo_cfg_fence_guard()'::regprocedure
      ), functions AS (
        SELECT p.* FROM pg_proc p WHERE p.oid IN (SELECT tgfoid FROM triggers)
          OR (p.pronamespace='foundation'::regnamespace AND p.proname IN (
            'geo_cfg_fence_guard','requests_guard','request_faults_category_guard',
            'request_appliance_revisions_guard_basis','request_address_revisions_guard_city',
            'request_history_payload_guard'))
      ), metadata(category,name,shape) AS (
        SELECT 'table',t.relname,jsonb_build_array(pg_get_userbyid(t.relowner),t.relkind,t.relpersistence,
          t.relrowsecurity,t.relforcerowsecurity)
        FROM tables t
        UNION ALL
        SELECT 'fence_table',r.relname,jsonb_build_array(pg_get_userbyid(r.relowner),r.relkind,r.relpersistence,
          r.relrowsecurity,r.relforcerowsecurity)
        FROM fence_relations r
        UNION ALL
        SELECT 'column',a.relname||'.'||a.attname,jsonb_build_array(a.attnum,a.typname,a.atttypmod,a.attnotnull,
          a.attidentity,a.attgenerated,a.default_expr)
        FROM columns a
        UNION ALL
        SELECT 'constraint',k.conname,jsonb_build_array(k.conrelid::regclass::text,k.contype,k.convalidated,
          pg_get_constraintdef(k.oid))
        FROM pg_constraint k WHERE k.conrelid IN (SELECT oid FROM tables)
        UNION ALL
        SELECT 'index',c.relname,jsonb_build_array(i.indisvalid,i.indisunique,pg_get_indexdef(c.oid))
        FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid IN (SELECT oid FROM tables)
        UNION ALL
        SELECT 'trigger',g.tgname,jsonb_build_array(g.tgrelid::regclass::text,g.tgenabled,pg_get_triggerdef(g.oid))
        FROM triggers g
        UNION ALL
        SELECT 'fence_trigger',g.tgname,jsonb_build_array(g.tgrelid::regclass::text,g.tgenabled,pg_get_triggerdef(g.oid))
        FROM fence_triggers g
        UNION ALL
        SELECT 'function',p.proname,jsonb_build_array(pg_get_userbyid(p.proowner),p.prosecdef,p.proconfig,
          encode(sha256(convert_to(replace(p.prosrc,chr(13),''),'UTF8')),'hex'))
        FROM functions p
      ), grants AS (
        SELECT a.relname||'.'||a.attname AS name,jsonb_build_array(
          has_column_privilege('fixlevelup_runtime',a.attrelid,a.attnum,'SELECT'),
          has_column_privilege('fixlevelup_runtime',a.attrelid,a.attnum,'INSERT'),
          has_column_privilege('fixlevelup_runtime',a.attrelid,a.attnum,'UPDATE'),
          has_column_privilege('fixlevelup_runtime',a.attrelid,a.attnum,'REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION')) AS shape
        FROM columns a
      ), fence_column_grants AS (
        -- Same effective-privilege shape as grants, but for every column of
        -- the nine fence relations: fence_acl sees only the per-table
        -- booleans, and other_acl/public_acl deliberately exclude the runtime
        -- role, so without this CTE a column-only UPDATE/SELECT/INSERT drift
        -- on a fence relation (e.g. UPDATE(display_name) on
        -- service_city_versions, where the runtime holds no UPDATE at all)
        -- would not move the hash.
        SELECT r.relname||'.'||a.attname AS name,jsonb_build_array(
          has_column_privilege('fixlevelup_runtime',a.attrelid,a.attnum,'SELECT'),
          has_column_privilege('fixlevelup_runtime',a.attrelid,a.attnum,'INSERT'),
          has_column_privilege('fixlevelup_runtime',a.attrelid,a.attnum,'UPDATE'),
          has_column_privilege('fixlevelup_runtime',a.attrelid,a.attnum,'REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION')) AS shape
        FROM fence_relations r JOIN pg_attribute a ON a.attrelid=r.oid
        WHERE a.attnum>0 AND NOT a.attisdropped
      ), fence_acl AS (
        -- Runtime table privileges per PRIVILEGE, never as one any-of
        -- boolean: with DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN merged
        -- into a single has_table_privilege() call, an extra runtime grant
        -- (e.g. TRUNCATE where DELETE is already held) would not move the
        -- hash. Each privilege is its own array element instead. Runtime
        -- table GRANTABILITY is fingerprinted per privilege as well: the
        -- owner upgrading an existing plain grant to WITH GRANT OPTION
        -- changes the runtime's authority without moving any plain boolean,
        -- so each privilege's '... WITH GRANT OPTION' variant is its own
        -- element too.
        SELECT r.relname AS name,jsonb_build_array(pg_get_userbyid(r.relowner),
          has_table_privilege('fixlevelup_runtime',r.oid,'SELECT'),
          has_table_privilege('fixlevelup_runtime',r.oid,'INSERT'),
          has_table_privilege('fixlevelup_runtime',r.oid,'UPDATE'),
          has_table_privilege('fixlevelup_runtime',r.oid,'DELETE'),
          has_table_privilege('fixlevelup_runtime',r.oid,'TRUNCATE'),
          has_table_privilege('fixlevelup_runtime',r.oid,'REFERENCES'),
          has_table_privilege('fixlevelup_runtime',r.oid,'TRIGGER'),
          has_table_privilege('fixlevelup_runtime',r.oid,'MAINTAIN'),
          has_table_privilege('fixlevelup_runtime',r.oid,'SELECT WITH GRANT OPTION'),
          has_table_privilege('fixlevelup_runtime',r.oid,'INSERT WITH GRANT OPTION'),
          has_table_privilege('fixlevelup_runtime',r.oid,'UPDATE WITH GRANT OPTION'),
          has_table_privilege('fixlevelup_runtime',r.oid,'DELETE WITH GRANT OPTION'),
          has_table_privilege('fixlevelup_runtime',r.oid,'TRUNCATE WITH GRANT OPTION')) AS shape
        FROM fence_relations r
        UNION ALL
        SELECT t.relname,jsonb_build_array(pg_get_userbyid(t.relowner),
          has_table_privilege('fixlevelup_runtime',t.oid,'SELECT'),
          has_table_privilege('fixlevelup_runtime',t.oid,'INSERT'),
          has_table_privilege('fixlevelup_runtime',t.oid,'UPDATE'),
          has_table_privilege('fixlevelup_runtime',t.oid,'DELETE'),
          has_table_privilege('fixlevelup_runtime',t.oid,'TRUNCATE'),
          has_table_privilege('fixlevelup_runtime',t.oid,'REFERENCES'),
          has_table_privilege('fixlevelup_runtime',t.oid,'TRIGGER'),
          has_table_privilege('fixlevelup_runtime',t.oid,'MAINTAIN'),
          has_table_privilege('fixlevelup_runtime',t.oid,'SELECT WITH GRANT OPTION'),
          has_table_privilege('fixlevelup_runtime',t.oid,'INSERT WITH GRANT OPTION'),
          has_table_privilege('fixlevelup_runtime',t.oid,'UPDATE WITH GRANT OPTION'),
          has_table_privilege('fixlevelup_runtime',t.oid,'DELETE WITH GRANT OPTION'),
          has_table_privilege('fixlevelup_runtime',t.oid,'TRUNCATE WITH GRANT OPTION')) AS shape
        FROM tables t
      ), public_acl AS (
        -- PUBLIC entries of any privilege on the ten P05 tables AND the nine
        -- fence relations — all 19 relations (table or column level), checked
        -- against the stored ACL so a duplicate PUBLIC grant cannot hide
        -- behind an existing runtime grant or behind being on a fence
        -- relation instead of a P05 table.
        SELECT c.relname AS name,jsonb_build_array(x.privilege_type) AS shape
        FROM (SELECT * FROM tables UNION ALL SELECT * FROM fence_relations) c
        CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) x
        WHERE x.grantee=0
        UNION ALL
        SELECT c.relname||'.'||a.attname,jsonb_build_array(y.privilege_type)
        FROM (SELECT * FROM tables UNION ALL SELECT * FROM fence_relations) c
        JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
        CROSS JOIN LATERAL aclexplode(a.attacl) y
        WHERE y.grantee=0
      ), sequence AS (
        SELECT 'sequence'||s.relname AS name,jsonb_build_array(pg_get_userbyid(s.relowner),
          has_sequence_privilege('fixlevelup_runtime',s.oid,'USAGE'),has_sequence_privilege('fixlevelup_runtime',s.oid,'SELECT,UPDATE'),
          -- Raw stored sequence ACL entries: any grantee beyond the owner and
          -- this runtime role changes the hash (no silent third-party access).
          (SELECT coalesce(jsonb_agg(jsonb_build_array(pg_get_userbyid(a.grantor),
             CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
             a.privilege_type,a.is_grantable) ORDER BY (CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END) COLLATE "C", a.privilege_type COLLATE "C"),'[]'::jsonb)
           FROM aclexplode(coalesce(s.relacl,acldefault('S',s.relowner))) a)) AS shape
        FROM pg_class s WHERE s.oid='foundation.request_public_numbers'::regclass
      ), other_acl AS (
        -- Every non-runtime, non-owner, non-PUBLIC ACL entry on the ten P05
        -- tables and the nine fence relations, at TABLE level (relacl).
        -- Runtime and PUBLIC are deliberately excluded here: the runtime
        -- role's exact per-privilege shape is already fingerprinted by
        -- fence_acl (individual booleans), and PUBLIC is covered by
        -- public_acl across all 19 relations — so this raw branch catches
        -- exactly the third-party entries nothing else would see.
        SELECT c.relname AS name,jsonb_build_array(pg_get_userbyid(a.grantor),
          CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
          a.privilege_type,a.is_grantable) AS shape
        FROM (SELECT * FROM tables UNION ALL SELECT * FROM fence_relations) c
        CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
        WHERE a.grantee NOT IN (0, (SELECT oid FROM pg_roles WHERE rolname='fixlevelup_runtime'), c.relowner)
        UNION ALL
        -- ...and at COLUMN level (attacl): a third role gaining column SELECT
        -- on the ciphertext must also change the hash. Runtime and PUBLIC are
        -- excluded for the same reasons as in the table-level branch above
        -- (fence_acl per-privilege booleans and public_acl respectively).
        SELECT c.relname||'.'||a2.attname AS name,jsonb_build_array(pg_get_userbyid(x.grantor),
          CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
          x.privilege_type,x.is_grantable) AS shape
        FROM (SELECT * FROM tables UNION ALL SELECT * FROM fence_relations) c
        JOIN pg_attribute a2 ON a2.attrelid=c.oid AND a2.attnum>0 AND NOT a2.attisdropped
        CROSS JOIN LATERAL aclexplode(a2.attacl) x
        WHERE x.grantee NOT IN (0, (SELECT oid FROM pg_roles WHERE rolname='fixlevelup_runtime'), c.relowner)
      ), checked AS (
        SELECT * FROM metadata
        UNION ALL SELECT 'grant',name,shape FROM grants
        UNION ALL SELECT 'fence_grant',name,shape FROM fence_column_grants
        UNION ALL SELECT 'fence_acl',name,shape FROM fence_acl
        UNION ALL SELECT 'public_acl',name,shape FROM public_acl
        UNION ALL SELECT 'other_acl',name,shape FROM other_acl
        UNION ALL SELECT 'metadata',name,shape FROM sequence
      )
      SELECT encode(sha256(convert_to((SELECT jsonb_agg(jsonb_build_array(category,name,shape)
          ORDER BY category COLLATE "C",name COLLATE "C",shape::text COLLATE "C")::text FROM checked),'UTF8')),'hex') AS metadata,
        NOT pg_catalog.pg_is_in_recovery()
        AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='fixlevelup_runtime'))
        AND NOT has_schema_privilege('fixlevelup_runtime','foundation','CREATE')
        AND NOT has_schema_privilege('fixlevelup_runtime','public','CREATE')
        AND NOT has_database_privilege('fixlevelup_runtime',current_database(),'CREATE,TEMP')
        AND NOT (SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit
          FROM pg_roles WHERE rolname='fixlevelup_runtime')
        AND NOT EXISTS(SELECT FROM functions f WHERE has_function_privilege('fixlevelup_runtime',f.oid,'EXECUTE'))
        AND (SELECT count(*) FROM fence_triggers) = 9 AS compatible`;

const S2_SQL = `WITH tables AS (
        SELECT * FROM pg_class WHERE relnamespace='foundation'::regnamespace AND relname IN (
          'form_browser_groups','form_session_group_memberships','form_throttle_buckets')
      ), columns AS (
        SELECT t.relname,a.*,p.typname,pg_get_expr(d.adbin,d.adrelid) AS default_expr
        FROM tables t JOIN pg_attribute a ON a.attrelid=t.oid JOIN pg_type p ON p.oid=a.atttypid
        LEFT JOIN pg_attrdef d ON d.adrelid=t.oid AND d.adnum=a.attnum
        WHERE a.attnum>0 AND NOT a.attisdropped
      ), triggers AS (
        SELECT g.* FROM pg_trigger g WHERE NOT g.tgisinternal AND g.tgrelid IN (SELECT oid FROM tables)
      ), functions AS (
        SELECT p.* FROM pg_proc p WHERE p.oid IN (SELECT tgfoid FROM triggers)
          OR (p.pronamespace='foundation'::regnamespace AND p.proname IN (
            'form_browser_groups_guard','form_session_group_memberships_guard',
            'form_throttle_buckets_guard','form_history_reject_truncate'))
      ), metadata(category,name,shape) AS (
        SELECT 'table',t.relname,jsonb_build_array(pg_get_userbyid(t.relowner),t.relkind,t.relpersistence,
          t.relrowsecurity,t.relforcerowsecurity)
        FROM tables t
        UNION ALL
        SELECT 'column',a.relname||'.'||a.attname,jsonb_build_array(a.attnum,a.typname,a.atttypmod,a.attnotnull,
          a.attidentity,a.attgenerated,a.default_expr)
        FROM columns a
        UNION ALL
        SELECT 'constraint',k.conname,jsonb_build_array(k.conrelid::regclass::text,k.contype,k.convalidated,
          pg_get_constraintdef(k.oid))
        FROM pg_constraint k WHERE k.conrelid IN (SELECT oid FROM tables)
        UNION ALL
        SELECT 'index',c.relname,jsonb_build_array(i.indisvalid,i.indisunique,pg_get_indexdef(c.oid))
        FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid IN (SELECT oid FROM tables)
        UNION ALL
        SELECT 'trigger',g.tgname,jsonb_build_array(g.tgrelid::regclass::text,g.tgenabled,pg_get_triggerdef(g.oid))
        FROM triggers g
        UNION ALL
        SELECT 'function',p.proname,jsonb_build_array(pg_get_userbyid(p.proowner),p.prosecdef,p.proconfig,
          encode(sha256(convert_to(replace(p.prosrc,chr(13),''),'UTF8')),'hex'))
        FROM functions p
      ), grants AS (
        -- Effective runtime column privileges per column (SELECT/INSERT/UPDATE/
        -- REFERENCES+grant-option): the exact 023 column grants, never an
        -- any-of table boolean.
        SELECT a.relname||'.'||a.attname AS name,jsonb_build_array(
          has_column_privilege('fixlevelup_runtime',a.attrelid,a.attnum,'SELECT'),
          has_column_privilege('fixlevelup_runtime',a.attrelid,a.attnum,'INSERT'),
          has_column_privilege('fixlevelup_runtime',a.attrelid,a.attnum,'UPDATE'),
          has_column_privilege('fixlevelup_runtime',a.attrelid,a.attnum,'REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION')) AS shape
        FROM columns a
      ), table_acl AS (
        -- Runtime table privileges per PRIVILEGE (plus the owner), never one
        -- any-of boolean: an extra runtime grant (e.g. DELETE where UPDATE is
        -- already held) or a WITH GRANT OPTION upgrade moves the hash. Each
        -- privilege and its grant-option variant is its own array element.
        SELECT t.relname AS name,jsonb_build_array(pg_get_userbyid(t.relowner),
          has_table_privilege('fixlevelup_runtime',t.oid,'SELECT'),
          has_table_privilege('fixlevelup_runtime',t.oid,'INSERT'),
          has_table_privilege('fixlevelup_runtime',t.oid,'UPDATE'),
          has_table_privilege('fixlevelup_runtime',t.oid,'DELETE'),
          has_table_privilege('fixlevelup_runtime',t.oid,'TRUNCATE'),
          has_table_privilege('fixlevelup_runtime',t.oid,'REFERENCES'),
          has_table_privilege('fixlevelup_runtime',t.oid,'TRIGGER'),
          has_table_privilege('fixlevelup_runtime',t.oid,'MAINTAIN'),
          has_table_privilege('fixlevelup_runtime',t.oid,'SELECT WITH GRANT OPTION'),
          has_table_privilege('fixlevelup_runtime',t.oid,'INSERT WITH GRANT OPTION'),
          has_table_privilege('fixlevelup_runtime',t.oid,'UPDATE WITH GRANT OPTION'),
          has_table_privilege('fixlevelup_runtime',t.oid,'DELETE WITH GRANT OPTION'),
          has_table_privilege('fixlevelup_runtime',t.oid,'TRUNCATE WITH GRANT OPTION')) AS shape
        FROM tables t
      ), public_acl AS (
        -- PUBLIC entries of any privilege on the three 023 tables (table or
        -- column level), checked against the stored ACL so a duplicate PUBLIC
        -- grant cannot hide behind an existing runtime grant.
        SELECT c.relname AS name,jsonb_build_array(x.privilege_type) AS shape
        FROM tables c
        CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) x
        WHERE x.grantee=0
        UNION ALL
        SELECT c.relname||'.'||a.attname,jsonb_build_array(y.privilege_type)
        FROM tables c
        JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
        CROSS JOIN LATERAL aclexplode(a.attacl) y
        WHERE y.grantee=0
      ), other_acl AS (
        -- Every non-runtime, non-owner, non-PUBLIC ACL entry on the three
        -- 023 tables, at table and column level. Runtime and PUBLIC are
        -- deliberately excluded: the runtime role's exact shape is already
        -- fingerprinted (grants + table_acl) and PUBLIC is covered by
        -- public_acl — so this raw branch catches exactly the third-party
        -- entries nothing else would see.
        SELECT c.relname AS name,jsonb_build_array(pg_get_userbyid(a.grantor),
          CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
          a.privilege_type,a.is_grantable) AS shape
        FROM tables c
        CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
        WHERE a.grantee NOT IN (0, (SELECT oid FROM pg_roles WHERE rolname='fixlevelup_runtime'), c.relowner)
        UNION ALL
        SELECT c.relname||'.'||a2.attname AS name,jsonb_build_array(pg_get_userbyid(x.grantor),
          CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,
          x.privilege_type,x.is_grantable) AS shape
        FROM tables c
        JOIN pg_attribute a2 ON a2.attrelid=c.oid AND a2.attnum>0 AND NOT a2.attisdropped
        CROSS JOIN LATERAL aclexplode(a2.attacl) x
        WHERE x.grantee NOT IN (0, (SELECT oid FROM pg_roles WHERE rolname='fixlevelup_runtime'), c.relowner)
      ), checked AS (
        SELECT * FROM metadata
        UNION ALL
        -- MUST 10 (Astra round 1): FK enforcement state by STABLE identity, not
        -- by the internal RI_ConstraintTrigger_* name (which embeds OIDs).
        -- Disabling FK enforcement (ALTER TABLE ... DISABLE TRIGGER ALL/USER)
        -- flips tgenabled O->D and moves the hash deterministically across
        -- databases, with no OID in key or value.
        SELECT 'fk_trigger', k.conname || ':' || g.tgrelid::regclass::text || ':' || g.tgtype::int::text,
          jsonb_build_array(g.tgenabled, g.tgdeferrable, g.tginitdeferred, pg_get_function_identity_arguments(g.tgfoid),
            (SELECT proname FROM pg_proc WHERE oid = g.tgfoid))
        FROM pg_constraint k
        JOIN pg_trigger g ON g.tgconstraint = k.oid
        WHERE k.contype = 'f' AND (k.conrelid IN (SELECT oid FROM tables) OR k.confrelid IN (SELECT oid FROM tables))
        UNION ALL
        -- MUST 10 (Astra round 1): exact function ACL entries of the four guard
        -- functions — checked against the stored ACL (COALESCE with acldefault),
        -- so a surplus GRANT EXECUTE TO PUBLIC or TO any third role moves the
        -- hash even while the runtime's effective EXECUTE stays false.
        SELECT 'function_acl', p.proname,
          jsonb_build_array(pg_get_userbyid(a.grantor),
            CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
            a.privilege_type, a.is_grantable)
        FROM functions p
        CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
        UNION ALL SELECT 'grant',name,shape FROM grants
        UNION ALL SELECT 'table_acl',name,shape FROM table_acl
        UNION ALL SELECT 'public_acl',name,shape FROM public_acl
        UNION ALL SELECT 'other_acl',name,shape FROM other_acl
      )
      SELECT encode(sha256(convert_to((SELECT jsonb_agg(jsonb_build_array(category,name,shape)
          ORDER BY category COLLATE "C",name COLLATE "C",shape::text COLLATE "C")::text FROM checked),'UTF8')),'hex') AS metadata,
        NOT pg_catalog.pg_is_in_recovery()
        AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='fixlevelup_runtime'))
        AND NOT has_schema_privilege('fixlevelup_runtime','foundation','CREATE')
        AND NOT has_schema_privilege('fixlevelup_runtime','public','CREATE')
        AND NOT has_database_privilege('fixlevelup_runtime',current_database(),'CREATE,TEMP')
        AND NOT (SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit
          FROM pg_roles WHERE rolname='fixlevelup_runtime')
        AND NOT EXISTS(SELECT FROM functions f WHERE has_function_privilege('fixlevelup_runtime',f.oid,'EXECUTE'))
        AND (SELECT count(*) FROM tables) = 3
        AND (SELECT count(*) FROM functions) = 4
        AND (SELECT count(*) FROM triggers) = 6 AS compatible`;

export const S1_TABLES = Object.freeze(['request_policy_packages', 'customers', 'requests', 'request_payload_cells',
  'request_contact_revisions', 'request_address_revisions', 'request_appliance_revisions', 'request_faults',
  'request_preference_revisions', 'request_events']);
export const S2_TABLES = Object.freeze(['form_browser_groups', 'form_session_group_memberships', 'form_throttle_buckets']);
const FENCES = Object.freeze(['business_settings_versions', 'service_cities', 'service_city_versions',
  'administrative_districts', 'service_areas', 'service_area_versions', 'service_area_district_coverage',
  'reference_entries', 'reference_entry_versions']);
const S1_FUNCTIONS = Object.freeze(['geo_cfg_fence_guard', 'requests_guard', 'request_faults_category_guard',
  'request_appliance_revisions_guard_basis', 'request_address_revisions_guard_city', 'request_history_payload_guard']);
const S2_FUNCTIONS = Object.freeze(['form_browser_groups_guard', 'form_session_group_memberships_guard',
  'form_throttle_buckets_guard', 'form_history_reject_truncate']);

// Internal RI trigger names embed OIDs; sequence last_value is application data.
// Neither is a stable schema identity. Use qualified names and immutable sequence parameters.
const ENFORCEMENT_SQL = `WITH app AS (
  SELECT c.* FROM pg_catalog.pg_class c WHERE c.relnamespace='foundation'::regnamespace AND c.relname=ANY($1::text[])
), basis AS (
  SELECT c.* FROM pg_catalog.pg_class c WHERE c.relnamespace='foundation'::regnamespace AND c.relname=ANY($2::text[])
), seq AS (
  SELECT c.* FROM pg_catalog.pg_class c WHERE c.relnamespace='foundation'::regnamespace AND c.relname=ANY($4::text[])
), rels AS (SELECT * FROM app UNION ALL SELECT * FROM basis UNION ALL SELECT * FROM seq),
  funcs AS (SELECT p.* FROM pg_catalog.pg_proc p WHERE
    (p.pronamespace='foundation'::regnamespace AND p.proname=ANY($3::text[])) OR p.oid IN
    (SELECT tgfoid FROM pg_catalog.pg_trigger WHERE NOT tgisinternal AND tgrelid IN (SELECT oid FROM app))),
  facts(section, name, value) AS (
    SELECT 'function', n.nspname||'.'||p.proname,jsonb_build_array(pg_get_userbyid(p.proowner),
      replace(pg_get_functiondef(p.oid),chr(13)||chr(10),chr(10)),p.prokind,p.proleakproof,p.proparallel,p.proisstrict,
      pg_get_function_identity_arguments(p.oid)) FROM funcs p JOIN pg_namespace n ON n.oid=p.pronamespace
    UNION ALL SELECT 'relation',r.relname,jsonb_build_array(r.relkind,r.relpersistence,r.relispartition,r.relhasrules,
      r.relrowsecurity,r.relforcerowsecurity,am.amname) FROM rels r LEFT JOIN pg_am am ON am.oid=r.relam
    UNION ALL SELECT 'column',t.relname||'.'||a.attname,jsonb_build_array(a.attnum,ns.nspname,p.typname,
      a.atttypmod,a.attnotnull,a.attidentity,a.attgenerated,cn.nspname,co.collname)
      FROM app t JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped
      JOIN pg_type p ON p.oid=a.atttypid JOIN pg_namespace ns ON ns.oid=p.typnamespace
      LEFT JOIN pg_collation co ON co.oid=a.attcollation LEFT JOIN pg_namespace cn ON cn.oid=co.collnamespace
    UNION ALL SELECT 'constraint',r.relname||'.'||k.conname,jsonb_build_array(k.contype,k.convalidated,k.conenforced,
      k.condeferrable,k.condeferred,k.connoinherit,pg_get_constraintdef(k.oid)) FROM app r JOIN pg_constraint k ON k.conrelid=r.oid
    UNION ALL SELECT 'ri',k.conrelid::regclass::text||'.'||k.conname,jsonb_build_array(g.tgrelid::regclass::text,
      g.tgtype,g.tgenabled,g.tgdeferrable,g.tginitdeferred,n.nspname,p.proname)
      FROM pg_constraint k JOIN pg_trigger g ON g.tgconstraint=k.oid JOIN pg_proc p ON p.oid=g.tgfoid
      JOIN pg_namespace n ON n.oid=p.pronamespace WHERE k.contype='f' AND
        (k.conrelid IN (SELECT oid FROM app) OR k.confrelid IN (SELECT oid FROM app))
    UNION ALL SELECT 'index',i.indexrelid::regclass::text,jsonb_build_array(i.indisvalid,i.indisready,i.indislive,
      i.indisunique,i.indimmediate,i.indnullsnotdistinct,pg_get_indexdef(i.indexrelid))
      FROM pg_index i WHERE i.indrelid IN (SELECT oid FROM app)
    UNION ALL SELECT 'sequence',r.relname,jsonb_build_array(s.seqtypid::regtype::text,s.seqstart,s.seqincrement,
      s.seqmax,s.seqmin,s.seqcache,s.seqcycle) FROM seq r JOIN pg_sequence s ON s.seqrelid=r.oid
    UNION ALL SELECT 'inheritance',i.inhrelid::regclass::text,jsonb_build_array(i.inhparent::regclass::text,i.inhseqno)
      FROM pg_inherits i WHERE i.inhrelid IN (SELECT oid FROM app) OR i.inhparent IN (SELECT oid FROM app)
    UNION ALL SELECT 'rewrite',r.relname||'.'||w.rulename,jsonb_build_array(w.ev_enabled,pg_get_ruledef(w.oid))
      FROM app r JOIN pg_rewrite w ON w.ev_class=r.oid
  ), acls(section,name,entries) AS (
    SELECT 'rel_acl',r.relname,coalesce(r.relacl,acldefault(CASE WHEN r.relkind='S' THEN 'S' ELSE 'r' END::"char",r.relowner)) FROM rels r
    UNION ALL SELECT 'col_acl',r.relname||'.'||a.attname,a.attacl FROM rels r JOIN pg_attribute a
      ON a.attrelid=r.oid AND a.attnum>0 AND NOT a.attisdropped
    UNION ALL SELECT 'fn_acl',n.nspname||'.'||p.proname,coalesce(p.proacl,acldefault('f',p.proowner))
      FROM funcs p JOIN pg_namespace n ON n.oid=p.pronamespace
  ), all_facts AS (
    SELECT * FROM facts UNION ALL SELECT a.section,a.name,jsonb_build_array(pg_get_userbyid(x.grantor),
      CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,x.privilege_type,x.is_grantable)
      FROM acls a CROSS JOIN LATERAL aclexplode(a.entries) x
  ) SELECT encode(sha256(convert_to(jsonb_agg(jsonb_build_array(section,name,value)
     ORDER BY section COLLATE "C",name COLLATE "C",value::text COLLATE "C")::text,'UTF8')),'hex') AS enforcement FROM all_facts`;

const ENFORCEMENT_PINS: Readonly<Record<Layer, string>> = Object.freeze({
  S1: '1adbd9cda4a7bd874c358e337055730ab9417ee956dd95f04205e39cfe4aa171',
  S2: 'b0d1690f052669f276bb376c61ccd1e78594e2f027ddd22f32076481d1a9388a',
});

export const S3_TABLES = Object.freeze(['request_staff_evidence', 'request_command_receipts', 'request_session_submits',
  'phone_permission_events', 'request_files', 'request_appliance_brands', 'request_channel_choices', 'request_address_review_attempts',
  'request_coverage_assessments', 'request_intake_provenance']);
const S3_FUNCTIONS = Object.freeze(['request_role_grant_guard', 'request_effect_guard', 'request_aggregate_guard',
  'request_phone_permission_guard']);
const S3_DEPENDENCIES = Object.freeze(['role_permissions', 'permissions', 'file_privacy_controls', 'file_publications',
  'file_upload_intents', 'request_sessions', 'consent_records']);
const S3_INDEXES = Object.freeze(['request_sessions_intake_tuple_key', 'consent_records_request_given_tuple_key',
  'request_events_receipt_tuple_key', 'request_events_request_version_key', 'request_events_form_submit_key',
  'file_publications_intent_file_key', 'file_privacy_controls_intent_open_key', 'requests_id_city_key']);
const S3_CODES = Object.freeze(['requests.read', 'requests.create', 'requests.review', 'requests.coverage.assess',
  'requests.contact.manage', 'requests.ready', 'requests.cancel']);

// Positive S3 represents the whole reviewed delta, including objects on legacy
// parents and the closed permission catalogue. No business rows enter the hash.
const S3_SQL = `WITH app AS (
  SELECT * FROM pg_catalog.pg_class WHERE relnamespace='foundation'::regnamespace AND relname=ANY($1::text[])
), boundary AS (
  SELECT * FROM pg_catalog.pg_class WHERE relnamespace='foundation'::regnamespace AND relname=ANY($2::text[])
), rels AS (SELECT * FROM app UNION ALL SELECT * FROM boundary), facts(section,name,value) AS (
  SELECT 'owner',r.relname,jsonb_build_array(pg_get_userbyid(r.relowner)) FROM rels r
  UNION ALL SELECT 'column',r.relname||'.'||a.attname,jsonb_build_array(pg_get_expr(d.adbin,d.adrelid))
    FROM app r JOIN pg_attribute a ON a.attrelid=r.oid AND a.attnum>0 AND NOT a.attisdropped
    LEFT JOIN pg_attrdef d ON d.adrelid=r.oid AND d.adnum=a.attnum
  UNION ALL SELECT 'trigger',r.relname||'.'||g.tgname,jsonb_build_array(g.tgenabled,pg_get_triggerdef(g.oid))
    FROM rels r JOIN pg_trigger g ON g.tgrelid=r.oid AND NOT g.tgisinternal
  UNION ALL SELECT 'function',n.nspname||'.'||p.proname,jsonb_build_array(pg_get_userbyid(p.proowner),
    replace(pg_get_functiondef(p.oid),chr(13)||chr(10),chr(10)),p.prokind,p.proleakproof,p.proparallel,p.proisstrict)
    FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.oid IN
      (SELECT g.tgfoid FROM rels r JOIN pg_trigger g ON g.tgrelid=r.oid AND NOT g.tgisinternal)
  UNION ALL SELECT 'policy',r.relname||'.'||p.polname,jsonb_build_array(p.polroles,p.polpermissive,p.polcmd,
    pg_get_expr(p.polqual,r.oid),pg_get_expr(p.polwithcheck,r.oid))
    FROM rels r JOIN pg_policy p ON p.polrelid=r.oid
  UNION ALL SELECT 'constraint',r.relname||'.'||k.conname,jsonb_build_array(k.contype,k.convalidated,k.conenforced,
    pg_get_constraintdef(k.oid)) FROM boundary r JOIN pg_constraint k ON k.conrelid=r.oid
  UNION ALL SELECT 'index',i.indexrelid::regclass::text,jsonb_build_array(i.indisvalid,i.indisready,i.indislive,
    pg_get_indexdef(i.indexrelid)) FROM boundary r JOIN pg_index i ON i.indrelid=r.oid
  UNION ALL SELECT 'permission',p.code,jsonb_build_array(p.module,p.description,p.active,p.protected)
    FROM foundation.permissions p WHERE p.code=ANY($3::text[])
) SELECT encode(sha256(convert_to(jsonb_agg(jsonb_build_array(section,name,value)
    ORDER BY section COLLATE "C",name COLLATE "C",value::text COLLATE "C")::text,'UTF8')),'hex') AS metadata FROM facts`;

// Measured on freshly migrated isolated PostgreSQL 18.7, not on a launch target.
// Re-pinned after the reviewed 024 PHONE-completeness guard was added: the new
// `request_phone_permission_guard` trigger function enters the enforcement graph and
// `request_effect_guard` is re-created, which also moves the S1 base hashes.
// Re-measured on a fresh isolated PostgreSQL 18.7 (server_version_num 180007)
// after F-01 tightened request_role_grant_guard in migration 024. The base S1
// fingerprints are unchanged; only the 024 metadata/enforcement pins moved.
const S3_PINS = Object.freeze({
  metadata: '48e679cca9c8037d7c4c27d7091411611f5cf5f59c1969ea0fb7f045c1787940',
  enforcement: '74630e5e03405de512bf4bc7677534d33e6b851daca9d08dbb625585bdb71977',
  base: 'fdb0e4bfd8554af5d4a3b96dc87ee855f3dd2e1ce051124de0e81f6c4e353d4d',
  baseEnforcement: '967e5798d23f2c138a5de44feaf83fb992feafd1ccd87319aee4ac53dc51334f',
});

export async function readS3Metadata(client: CatalogClient) {
  const { rows: [facts] } = await client.query<{ metadata: string }>(S3_SQL, [S3_TABLES, S3_DEPENDENCIES, S3_CODES]);
  const { rows: [enforcement] } = await client.query<{ enforcement: string }>(ENFORCEMENT_SQL,
    [S3_TABLES, S3_DEPENDENCIES, S3_FUNCTIONS, []]);
  const base = await readP05Metadata(client, 'S1');
  return { metadata: facts?.metadata, enforcement: enforcement?.enforcement,
    base: base?.metadata, baseEnforcement: base?.enforcement, baseCompatible: base?.compatible === true };
}

type Measurement = { metadata: string | null; enforcement: string | null; compatible: boolean };

/** Read metadata only. Admission never learns an allowlist from its target. */
export async function readP05Metadata(client: CatalogClient, layer: Layer): Promise<Measurement | undefined> {
  const first = layer === 'S1';
  const sql = `SELECT b.metadata,b.compatible,e.enforcement FROM (${first ? S1_SQL : S2_SQL}) b CROSS JOIN (${ENFORCEMENT_SQL}) e`;
  const args = first ? [S1_TABLES, FENCES, S1_FUNCTIONS, ['request_public_numbers']] : [S2_TABLES, [], S2_FUNCTIONS, []];
  return (await client.query<Measurement>(sql, args)).rows[0];
}

// Absence is an inventory fact, not admission to S0: the caller separately
// requires the exact legacy base. The absence layer also works on an empty DB.
const ABSENCE_SQL = `SELECT NOT pg_is_in_recovery()
 AND NOT EXISTS (SELECT FROM pg_class WHERE relnamespace=to_regnamespace('foundation') AND relname=ANY($1::text[]))
 AND NOT EXISTS (SELECT FROM pg_type WHERE typnamespace=to_regnamespace('foundation') AND typname=ANY($1::text[]))
 AND NOT EXISTS (SELECT FROM pg_proc WHERE pronamespace=to_regnamespace('foundation') AND proname=ANY($2::text[]))
 AND NOT EXISTS (SELECT FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid
   WHERE c.relnamespace=to_regnamespace('foundation') AND NOT g.tgisinternal AND g.tgname=ANY($3::text[]))
 AND NOT EXISTS (SELECT FROM (
   SELECT relname::text AS name FROM pg_class WHERE relnamespace=to_regnamespace('foundation')
   UNION ALL SELECT conname FROM pg_constraint WHERE connamespace=to_regnamespace('foundation')
   UNION ALL SELECT p.proname FROM pg_proc p WHERE p.pronamespace=to_regnamespace('foundation')
   UNION ALL SELECT ltrim(t.typname, '_') FROM pg_type t WHERE t.typnamespace=to_regnamespace('foundation')
   UNION ALL SELECT g.tgname FROM pg_trigger g JOIN pg_class c ON c.oid=g.tgrelid
     WHERE c.relnamespace=to_regnamespace('foundation') AND NOT g.tgisinternal
 ) AS reserved CROSS JOIN unnest($4::text[]) AS stem(name)
 WHERE reserved.name=stem.name OR starts_with(reserved.name,stem.name||'_')) AS absent`;

const sourceIndexes = ['requests_is_waiting_link_idx', 'requests_customer_id_idx', 'request_events_request_idx',
  'requests_current_contact_key', 'requests_current_address_key', 'requests_current_appliance_key', 'requests_current_preference_key'];
const formIndexes = ['form_browser_groups_secret_hash_key', 'form_session_group_memberships_group_id_idx',
  'form_throttle_buckets_kind_key_hash_window_started_at_key'];

// Positive S2 checks must also reject extension objects in the reserved namespace.
// The per-table hashes cannot see, for example, an independent view or table.
// Named objects on S2 tables are already checked by BASE/ENFORCEMENT; here only
// the reviewed relations/routines and their automatically created row types are
// allowed in the namespace, never a same-prefixed sibling outside those checks.
const FORM_NAMESPACE_SQL = `WITH holders AS (
    SELECT c.oid,c.relname FROM pg_catalog.pg_class c
    WHERE c.relnamespace='foundation'::regnamespace AND c.relname=ANY($1::text[])
  ), objects(name, allowed) AS (
    SELECT c.relname, c.relname=ANY($2::text[]) OR ($5::boolean AND EXISTS (
      SELECT FROM pg_catalog.pg_index i JOIN holders h ON h.oid=i.indrelid WHERE i.indexrelid=c.oid))
      FROM pg_catalog.pg_class c WHERE c.relnamespace='foundation'::regnamespace
    UNION ALL SELECT ltrim(t.typname, '_'), EXISTS (SELECT FROM holders h WHERE h.oid=t.typrelid OR h.oid=element.typrelid)
      FROM pg_catalog.pg_type t LEFT JOIN pg_catalog.pg_type element ON element.oid=t.typelem
      WHERE t.typnamespace='foundation'::regnamespace
    UNION ALL SELECT p.proname, p.proname=ANY($3::text[]) FROM pg_catalog.pg_proc p WHERE p.pronamespace='foundation'::regnamespace
    UNION ALL SELECT k.conname, EXISTS (SELECT FROM holders h WHERE h.oid=k.conrelid)
      FROM pg_catalog.pg_constraint k WHERE k.connamespace='foundation'::regnamespace
    UNION ALL SELECT g.tgname, EXISTS (SELECT FROM holders h WHERE h.oid=g.tgrelid)
      FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class c ON c.oid=g.tgrelid
      WHERE c.relnamespace='foundation'::regnamespace AND NOT g.tgisinternal
  ) SELECT NOT EXISTS (SELECT FROM objects o CROSS JOIN unnest($4::text[]) AS stem(name)
    WHERE NOT o.allowed AND (o.name=stem.name OR starts_with(o.name,stem.name||'_'))) AS exact`;

async function formNamespaceExact(client: CatalogClient): Promise<boolean> {
  const relations = [...S2_TABLES, ...S2_TABLES.map((name) => name + '_pkey'), ...formIndexes];
  return (await client.query<{ exact: boolean }>(FORM_NAMESPACE_SQL, [S2_TABLES, relations, S2_FUNCTIONS,
    [...S2_TABLES, 'form_history_reject_truncate'], false])).rows[0]?.exact === true;
}

export async function preS3Absent(client: CatalogClient): Promise<boolean> {
  const absent = (await client.query<{ absent: boolean }>(ABSENCE_SQL, [S3_TABLES.concat(S3_INDEXES),
    S3_FUNCTIONS, ['request_effect_complete', 'request_aggregate_complete', 'request_role_grant_guard',
      'phone_permission_complete'], S3_TABLES])).rows[0]?.absent;
  if (absent !== true) { return false; }
  const { rows } = await client.query<{ absent: boolean }>(`SELECT
    NOT EXISTS (SELECT FROM pg_catalog.pg_attribute WHERE attrelid=to_regclass('foundation.requests')
      AND attname='current_assessment_id' AND NOT attisdropped)
    AND NOT EXISTS (SELECT FROM foundation.permissions WHERE code=ANY($1::text[])) AS absent`, [S3_CODES]);
  return rows[0]?.absent === true;
}

export async function probeP05Layer(client: CatalogClient, layer: Layer | 'S3' | 'NO_S1' | 'NO_S2'): Promise<boolean> {
  try {
    if (layer === 'S3') {
      const m = await readS3Metadata(client);
      if (!m.baseCompatible || m.metadata !== S3_PINS.metadata || m.enforcement !== S3_PINS.enforcement
        || m.base !== S3_PINS.base || m.baseEnforcement !== S3_PINS.baseEnforcement) { return false; }
      return (await client.query<{ exact: boolean }>(FORM_NAMESPACE_SQL,
        [S3_TABLES, [...S3_TABLES, ...S3_INDEXES], S3_FUNCTIONS, S3_TABLES, true])).rows[0]?.exact === true;
    }
    if (layer === 'NO_S1' || layer === 'NO_S2') {
      const first = layer === 'NO_S1';
      const tables = first ? S1_TABLES : S2_TABLES;
      const names = [...tables, ...tables.map(name => name + '_pkey'), ...(first ? [...sourceIndexes, 'request_public_numbers'] : formIndexes)];
      const triggers = first ? FENCES.map(name => name + '_geo_cfg_fence') : S2_TABLES.flatMap(name => [name + '_guard', name + '_reject_truncate']);
      return (await client.query<{ absent: boolean }>(ABSENCE_SQL, [names, first ? S1_FUNCTIONS : S2_FUNCTIONS, triggers,
        first ? tables : [...tables, 'form_history_reject_truncate']])).rows[0]?.absent === true;
    }
    if (!Object.hasOwn(BASE_PINS, layer)) { return false; }
    const m = await readP05Metadata(client, layer);
    return m?.compatible === true && m.metadata === BASE_PINS[layer] && Boolean(ENFORCEMENT_PINS[layer])
      && m.enforcement === ENFORCEMENT_PINS[layer] && (layer !== 'S2' || await formNamespaceExact(client));
  } catch { return false; }
}

export async function probeP05Catalog(client: CatalogClient, profile: P05Profile): Promise<boolean> {
  try {
    if (profile === 'S3') { return await probeP05Layer(client, 'S2') && await probeP05Layer(client, 'S3'); }
    if (!await preS3Absent(client)) { return false; }
    switch (profile) {
      case 'S0': return await probeP05Layer(client, 'NO_S1') && await probeP05Layer(client, 'NO_S2');
      case 'S1': return await probeP05Layer(client, 'S1') && await probeP05Layer(client, 'NO_S2');
      case 'S2': return await probeP05Layer(client, 'S1') && await probeP05Layer(client, 'S2');
      default: return false;
    }
  } catch { return false; }
}
