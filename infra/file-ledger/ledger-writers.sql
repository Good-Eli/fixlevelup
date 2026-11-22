BEGIN;
SET LOCAL ROLE file_ledger_owner;
CREATE TABLE file_ledger.namespace_writers (
  namespace_id uuid NOT NULL REFERENCES file_ledger.namespace_heads(namespace_id),
  writer_epoch bigint NOT NULL CHECK (writer_epoch > 0),
  writer_role_oid oid NOT NULL,
  PRIMARY KEY(namespace_id, writer_epoch), UNIQUE(namespace_id, writer_role_oid)
);
CREATE TRIGGER immutable_writer BEFORE UPDATE OR DELETE OR TRUNCATE ON file_ledger.namespace_writers
FOR EACH STATEMENT EXECUTE FUNCTION file_ledger.immutable_event();

-- Pre-existing synthetic namespaces have no credential provenance and are not
-- backfilled. They remain readable, but have no executable writer authority.
ALTER FUNCTION file_ledger.append(uuid,uuid,bigint,uuid,uuid,bigint,bytea) RENAME TO append_unbound;
ALTER FUNCTION file_ledger.initialize(uuid,uuid,bigint,text) RENAME TO initialize_unbound;
ALTER FUNCTION file_ledger.fence_writer(uuid,uuid,bigint,bigint) RENAME TO fence_writer_unbound;
REVOKE ALL ON FUNCTION file_ledger.append_unbound(uuid,uuid,bigint,uuid,uuid,bigint,bytea) FROM PUBLIC, file_ledger_writer;
REVOKE ALL ON FUNCTION file_ledger.initialize_unbound(uuid,uuid,bigint,text),
  file_ledger.fence_writer_unbound(uuid,uuid,bigint,bigint) FROM PUBLIC, file_ledger_operator;

CREATE FUNCTION file_ledger.resolve_writer(p_role text) RETURNS oid
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE role_oid oid;
BEGIN
  SELECT oid INTO role_oid FROM pg_catalog.pg_roles
    WHERE rolname::text = p_role AND rolcanlogin AND NOT rolsuper AND NOT rolcreaterole
      AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls
      AND pg_has_role(oid, 'file_ledger_appenders'::regrole, 'USAGE');
  IF NOT FOUND THEN RAISE EXCEPTION 'LEDGER_DENIED' USING ERRCODE = 'FL002'; END IF;
  RETURN role_oid;
END $$;
CREATE FUNCTION file_ledger.initialize(p_namespace uuid, p_incarnation uuid, p_epoch bigint, p_genesis text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM file_ledger.initialize_unbound(p_namespace,p_incarnation,p_epoch,p_genesis);
  INSERT INTO file_ledger.namespace_writers VALUES (p_namespace,p_epoch,file_ledger.resolve_writer('file_ledger_writer'));
END $$;
CREATE FUNCTION file_ledger.fence_writer(p_namespace uuid, p_incarnation uuid, p_epoch bigint, p_next bigint, p_role text)
RETURNS file_ledger.namespace_heads LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE h file_ledger.namespace_heads; writer_oid oid;
BEGIN
  writer_oid := file_ledger.resolve_writer(p_role);
  h := file_ledger.fence_writer_unbound(p_namespace,p_incarnation,p_epoch,p_next);
  IF NOT EXISTS (SELECT FROM file_ledger.namespace_writers WHERE namespace_id = p_namespace AND writer_epoch = p_epoch)
    OR EXISTS (SELECT FROM file_ledger.namespace_writers WHERE namespace_id = p_namespace AND writer_role_oid = writer_oid) THEN
    RAISE EXCEPTION 'LEDGER_DENIED' USING ERRCODE = 'FL002';
  END IF;
  INSERT INTO file_ledger.namespace_writers VALUES (p_namespace,p_next,writer_oid);
  RETURN h;
END $$;
CREATE FUNCTION file_ledger.append(p_namespace uuid, p_incarnation uuid, p_epoch bigint,
  p_event uuid, p_intent uuid, p_access bigint, p_payload bytea) RETURNS TABLE(seq bigint, sha256 varchar(64))
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE h file_ledger.namespace_heads;
BEGIN
  SELECT * INTO h FROM file_ledger.namespace_heads WHERE namespace_id = p_namespace FOR UPDATE;
  IF NOT FOUND OR h.incarnation_id IS DISTINCT FROM p_incarnation OR h.writer_epoch IS DISTINCT FROM p_epoch
    OR NOT EXISTS (SELECT FROM file_ledger.namespace_writers w WHERE w.namespace_id = p_namespace AND w.writer_epoch = p_epoch
      AND w.writer_role_oid = file_ledger.resolve_writer(SESSION_USER::text)) THEN
    RAISE EXCEPTION 'LEDGER_DENIED' USING ERRCODE = 'FL002';
  END IF;
  RETURN QUERY SELECT a.seq,a.sha256 FROM file_ledger.append_unbound(p_namespace,p_incarnation,p_epoch,p_event,p_intent,p_access,p_payload) a;
END $$;
REVOKE ALL ON FUNCTION file_ledger.resolve_writer(text), file_ledger.initialize(uuid,uuid,bigint,text),
  file_ledger.append(uuid,uuid,bigint,uuid,uuid,bigint,bytea), file_ledger.fence_writer(uuid,uuid,bigint,bigint,text) FROM PUBLIC;
GRANT USAGE ON SCHEMA file_ledger TO file_ledger_appenders;
GRANT EXECUTE ON FUNCTION file_ledger.append(uuid,uuid,bigint,uuid,uuid,bigint,bytea) TO file_ledger_appenders;
GRANT EXECUTE ON FUNCTION file_ledger.initialize(uuid,uuid,bigint,text),
  file_ledger.fence_writer(uuid,uuid,bigint,bigint,text) TO file_ledger_operator;
COMMIT;