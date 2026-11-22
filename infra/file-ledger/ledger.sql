\set ON_ERROR_STOP on
\getenv writer_secret FILE_LEDGER_WRITER_PASSWORD
\getenv signer_secret FILE_LEDGER_SIGNER_PASSWORD
\getenv operator_secret FILE_LEDGER_OPERATOR_PASSWORD
CREATE ROLE file_ledger_owner NOLOGIN;
CREATE ROLE file_ledger_writer LOGIN PASSWORD :'writer_secret';
CREATE ROLE file_ledger_signer LOGIN PASSWORD :'signer_secret';
CREATE ROLE file_ledger_operator LOGIN PASSWORD :'operator_secret';
SELECT pg_catalog.format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database()) \gexec
SELECT pg_catalog.format('GRANT CONNECT ON DATABASE %I TO file_ledger_writer, file_ledger_signer, file_ledger_operator', current_database()) \gexec
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA file_ledger AUTHORIZATION file_ledger_owner;
SET ROLE file_ledger_owner;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
CREATE TABLE file_ledger.namespace_heads (
  namespace_id uuid PRIMARY KEY, incarnation_id uuid UNIQUE NOT NULL,
  seq bigint NOT NULL CHECK (seq >= 0), chain_sha256 varchar(64) NOT NULL CHECK (chain_sha256 ~ '^[0-9a-f]{64}$'),
  writer_epoch bigint NOT NULL CHECK (writer_epoch > 0)
);
CREATE TABLE file_ledger.events (
  namespace_id uuid NOT NULL REFERENCES file_ledger.namespace_heads(namespace_id),
  seq bigint NOT NULL CHECK (seq > 0), event_id uuid NOT NULL,
  writer_epoch bigint NOT NULL CHECK (writer_epoch > 0), intent_id uuid NOT NULL, access_epoch bigint NOT NULL CHECK (access_epoch > 0),
  prev_sha256 varchar(64) NOT NULL CHECK (prev_sha256 ~ '^[0-9a-f]{64}$'),
  payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 524288),
  sha256 varchar(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  recorded_at timestamptz(6) NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (namespace_id, seq), UNIQUE (namespace_id, event_id)
);
CREATE FUNCTION file_ledger.immutable_event() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'LEDGER_HISTORY_IMMUTABLE' USING ERRCODE = 'FL002';
END $$;
CREATE TRIGGER immutable_event BEFORE UPDATE OR DELETE OR TRUNCATE ON file_ledger.events
FOR EACH STATEMENT EXECUTE FUNCTION file_ledger.immutable_event();

CREATE FUNCTION file_ledger.initialize(p_namespace uuid, p_incarnation uuid, p_epoch bigint, p_genesis text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF pg_is_in_recovery() OR current_setting('fsync') <> 'on' THEN
    RAISE EXCEPTION 'LEDGER_DENIED' USING ERRCODE = 'FL002';
  END IF;
  PERFORM set_config('synchronous_commit', 'on', true);
  INSERT INTO file_ledger.namespace_heads VALUES (p_namespace, p_incarnation, 0, p_genesis, p_epoch);
END $$;

CREATE FUNCTION file_ledger.fence_writer(p_namespace uuid, p_incarnation uuid, p_epoch bigint, p_next bigint)
RETURNS file_ledger.namespace_heads
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE h file_ledger.namespace_heads;
BEGIN
  IF pg_is_in_recovery() OR current_setting('fsync') <> 'on' OR p_next IS NULL OR p_next <= p_epoch THEN
    RAISE EXCEPTION 'LEDGER_DENIED' USING ERRCODE = 'FL002';
  END IF;
  PERFORM set_config('synchronous_commit', 'on', true);
  UPDATE file_ledger.namespace_heads SET writer_epoch = p_next
    WHERE namespace_id = p_namespace AND incarnation_id = p_incarnation AND writer_epoch = p_epoch RETURNING * INTO h;
  IF NOT FOUND THEN RAISE EXCEPTION 'LEDGER_DENIED' USING ERRCODE = 'FL002'; END IF;
  RETURN h;
END $$;

CREATE FUNCTION file_ledger.append(p_namespace uuid, p_incarnation uuid, p_epoch bigint,
  p_event uuid, p_intent uuid, p_access bigint, p_payload bytea)
RETURNS TABLE(seq bigint, sha256 varchar(64))
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE h file_ledger.namespace_heads; e file_ledger.events; p jsonb; item jsonb; body text;
  item_order text; last_order text; prefix text; port text;
  uuid4 constant text := '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
BEGIN
  IF pg_is_in_recovery() OR current_setting('fsync') <> 'on' OR p_payload IS NULL
    OR octet_length(p_payload) NOT BETWEEN 1 AND 524288 OR p_event IS NULL OR p_intent IS NULL OR p_access IS NULL OR p_access <= 0 THEN
    RAISE EXCEPTION 'LEDGER_DENIED' USING ERRCODE = 'FL002';
  END IF;
  PERFORM set_config('synchronous_commit', 'on', true);
  SELECT * INTO h FROM file_ledger.namespace_heads WHERE namespace_id = p_namespace FOR UPDATE;
  IF NOT FOUND OR h.incarnation_id IS DISTINCT FROM p_incarnation OR h.writer_epoch IS DISTINCT FROM p_epoch THEN
    RAISE EXCEPTION 'LEDGER_DENIED' USING ERRCODE = 'FL002';
  END IF;
  SELECT * INTO e FROM file_ledger.events WHERE namespace_id = p_namespace AND event_id = p_event;
  IF FOUND THEN
    IF e.payload <> p_payload OR e.intent_id <> p_intent OR e.access_epoch <> p_access OR e.writer_epoch <> p_epoch THEN
      RAISE EXCEPTION 'LEDGER_CONFLICT' USING ERRCODE = 'FL001';
    END IF;
    RETURN QUERY SELECT e.seq, e.sha256;
    RETURN;
  END IF;
  body := convert_from(p_payload, 'UTF8');
  p := body::jsonb;
  IF jsonb_typeof(p) <> 'array' OR jsonb_array_length(p) <> 9 OR jsonb_typeof(p->8) <> 'array'
    OR jsonb_array_length(p->8) > 2048
    OR p <> jsonb_build_array(1,p_namespace::text,p_incarnation::text,p_epoch::text,p_event::text,p_intent::text,p_access::text,jsonb_array_length(p->8),p->8)
    OR body <> replace(p::text, ', ', ',') THEN
    RAISE EXCEPTION 'LEDGER_DENIED' USING ERRCODE = 'FL002';
  END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(p->8) LOOP
    IF jsonb_typeof(item) <> 'array' OR jsonb_array_length(item) <> 7
      OR EXISTS (SELECT FROM jsonb_array_elements(item) elem WHERE jsonb_typeof(elem) <> 'string') THEN
      RAISE EXCEPTION 'LEDGER_DENIED' USING ERRCODE = 'FL002';
    END IF;
    item_order := (item->>0) || '/' || (item->>1);
    prefix := CASE item->>0 WHEN 'RAW' THEN 'quarantine' WHEN 'SANITIZED' THEN 'sanitized' END;
    port := substring(item->>2 FROM '^http://127[.]0[.]0[.]1:([1-9][0-9]{0,4})$');
    IF prefix IS NULL OR (item->>1) !~ ('^' || uuid4 || '$') OR length(item->>1) <> 36
      OR port IS NULL OR port::integer > 65535 OR (item->>2) <> 'http://127.0.0.1:' || port
      OR (item->>3) !~ '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' OR (item->>4) !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
      OR (item->>5) !~ ('^' || prefix || '/' || (item->>1) || '/' || uuid4 || '$')
      OR length(item->>5) <> length(prefix) + 74
      OR (item->>6) NOT IN ('NEVER_DISPATCHED','VERIFIED_SETTLED','UNKNOWN')
      OR (last_order COLLATE "C") >= (item_order COLLATE "C") THEN
      RAISE EXCEPTION 'LEDGER_DENIED' USING ERRCODE = 'FL002';
    END IF;
    last_order := item_order;
  END LOOP;
  seq := h.seq + 1;
  sha256 := encode(pg_catalog.sha256(convert_to('fixlevelup/file-ledger/chain/v1' || chr(10) || h.chain_sha256 || chr(10) || seq::text || chr(10), 'UTF8') || p_payload), 'hex');
  INSERT INTO file_ledger.events(namespace_id,seq,event_id,writer_epoch,intent_id,access_epoch,prev_sha256,payload,sha256)
    VALUES (p_namespace,seq,p_event,p_epoch,p_intent,p_access,h.chain_sha256,p_payload,sha256);
  UPDATE file_ledger.namespace_heads SET seq = h.seq + 1, chain_sha256 = sha256 WHERE namespace_id = p_namespace;
  RETURN NEXT;
END $$;
GRANT USAGE ON SCHEMA file_ledger TO file_ledger_writer, file_ledger_signer, file_ledger_operator;
GRANT SELECT ON file_ledger.namespace_heads, file_ledger.events TO file_ledger_signer;
GRANT EXECUTE ON FUNCTION file_ledger.initialize(uuid,uuid,bigint,text), file_ledger.fence_writer(uuid,uuid,bigint,bigint) TO file_ledger_operator;
GRANT EXECUTE ON FUNCTION file_ledger.append(uuid,uuid,bigint,uuid,uuid,bigint,bytea) TO file_ledger_writer;
RESET ROLE;
