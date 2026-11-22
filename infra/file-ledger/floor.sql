\set ON_ERROR_STOP on
\getenv verifier_secret FILE_FLOOR_VERIFIER_PASSWORD
\getenv operator_secret FILE_FLOOR_OPERATOR_PASSWORD
CREATE ROLE file_floor_owner NOLOGIN;
CREATE ROLE file_floor_verifier LOGIN PASSWORD :'verifier_secret';
CREATE ROLE file_floor_operator LOGIN PASSWORD :'operator_secret';
SELECT pg_catalog.format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database()) \gexec
SELECT pg_catalog.format('GRANT CONNECT ON DATABASE %I TO file_floor_verifier, file_floor_operator', current_database()) \gexec
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA file_floor AUTHORIZATION file_floor_owner;
SET ROLE file_floor_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
CREATE TABLE file_floor.current_heads (
  namespace_id uuid PRIMARY KEY, incarnation_id uuid UNIQUE NOT NULL, key_sha256 varchar(64) NOT NULL CHECK (key_sha256 ~ '^[0-9a-f]{64}$'),
  seq bigint NOT NULL CHECK (seq >= 0), chain_sha256 varchar(64) NOT NULL CHECK (chain_sha256 ~ '^[0-9a-f]{64}$'),
  writer_epoch bigint NOT NULL CHECK (writer_epoch > 0)
);
CREATE FUNCTION file_floor.guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.namespace_id = OLD.namespace_id AND NEW.incarnation_id = OLD.incarnation_id
    AND NEW.key_sha256 = OLD.key_sha256 AND NEW.seq >= OLD.seq AND NEW.writer_epoch >= OLD.writer_epoch
    AND (NEW.seq > OLD.seq OR NEW.chain_sha256 = OLD.chain_sha256) THEN RETURN NEW; END IF;
  RAISE EXCEPTION 'FLOOR_IMMUTABLE' USING ERRCODE = 'FL002';
END $$;
CREATE TRIGGER floor_no_removal BEFORE DELETE OR TRUNCATE ON file_floor.current_heads
FOR EACH STATEMENT EXECUTE FUNCTION file_floor.guard();
CREATE TRIGGER floor_monotonic BEFORE UPDATE ON file_floor.current_heads
FOR EACH ROW EXECUTE FUNCTION file_floor.guard();

-- No caller can choose the namespace/incarnation, even with bootstrap credentials.
CREATE FUNCTION file_floor.initialize(p_epoch bigint, p_key text) RETURNS file_floor.current_heads
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE ns uuid := gen_random_uuid(); inc uuid := gen_random_uuid(); h file_floor.current_heads; genesis text;
BEGIN
  IF pg_is_in_recovery() OR current_setting('fsync') <> 'on' OR p_key IS NULL OR length(p_key) <> 64 OR p_key !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'FLOOR_DENIED' USING ERRCODE = 'FL002';
  END IF;
  PERFORM set_config('synchronous_commit', 'on', true);
  genesis := encode(sha256(convert_to(replace(jsonb_build_array('fixlevelup/file-ledger/genesis/v1',ns::text,inc::text,p_epoch::text,p_key)::text, ', ', ','), 'UTF8')), 'hex');
  INSERT INTO file_floor.current_heads VALUES (ns,inc,p_key,0,genesis,p_epoch) RETURNING * INTO h;
  RETURN h;
END $$;
CREATE FUNCTION file_floor.pin(p_namespace uuid, p_incarnation uuid, p_key text,
  p_old_seq bigint, p_old_hash text, p_old_epoch bigint, p_seq bigint, p_hash text, p_epoch bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE h file_floor.current_heads;
BEGIN
  IF pg_is_in_recovery() OR current_setting('fsync') <> 'on' THEN
    RAISE EXCEPTION 'FLOOR_DENIED' USING ERRCODE = 'FL002';
  END IF;
  PERFORM set_config('synchronous_commit', 'on', true);
  SELECT * INTO h FROM file_floor.current_heads WHERE namespace_id = p_namespace FOR UPDATE;
  IF NOT FOUND OR h.incarnation_id IS DISTINCT FROM p_incarnation OR h.key_sha256 IS DISTINCT FROM p_key THEN
    RAISE EXCEPTION 'FLOOR_DENIED' USING ERRCODE = 'FL002';
  END IF;
  IF h.seq IS DISTINCT FROM p_old_seq OR h.chain_sha256 IS DISTINCT FROM p_old_hash OR h.writer_epoch IS DISTINCT FROM p_old_epoch THEN
    RETURN false;
  END IF;
  -- Even equal pins WAL-write/flush: a concurrently visible prior pin not yet
  -- acknowledged flushes before this caller can issue a grant.
  UPDATE file_floor.current_heads SET seq = p_seq, chain_sha256 = p_hash, writer_epoch = p_epoch WHERE namespace_id = p_namespace;
  RETURN true;
END $$;
GRANT USAGE ON SCHEMA file_floor TO file_floor_operator, file_floor_verifier;
GRANT SELECT ON file_floor.current_heads TO file_floor_verifier;
GRANT EXECUTE ON FUNCTION file_floor.initialize(bigint,text) TO file_floor_operator;
GRANT EXECUTE ON FUNCTION file_floor.pin(uuid,uuid,text,bigint,text,bigint,bigint,text,bigint) TO file_floor_verifier;
RESET ROLE;