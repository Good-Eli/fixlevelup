-- P01-01.7B synthetic proof ONLY. Never apply to the development business schema.
CREATE EXTENSION btree_gist;
CREATE SCHEMA proof;
REVOKE ALL ON SCHEMA proof FROM PUBLIC;
GRANT USAGE ON SCHEMA proof TO fixlevelup_runtime;

CREATE TABLE proof.city (id integer PRIMARY KEY, name text NOT NULL);
CREATE TABLE proof.city_version (
  city_id integer NOT NULL REFERENCES proof.city(id), version integer NOT NULL,
  name text NOT NULL, timezone text NOT NULL,
  PRIMARY KEY (city_id,version)
);
CREATE TABLE proof.zone_version (
  city_id integer NOT NULL REFERENCES proof.city(id), id integer NOT NULL, version integer NOT NULL,
  label text NOT NULL, PRIMARY KEY(city_id,id,version)
);
CREATE TABLE proof.district (
  city_id integer NOT NULL REFERENCES proof.city(id), id integer NOT NULL,
  PRIMARY KEY(city_id,id)
);
CREATE TABLE proof.coverage (
  city_id integer NOT NULL, zone_id integer NOT NULL, zone_version integer NOT NULL, district_id integer NOT NULL,
  relation text NOT NULL CHECK(relation IN ('FULL','PARTIAL')),
  PRIMARY KEY(city_id,zone_id,zone_version,district_id),
  FOREIGN KEY(city_id,zone_id,zone_version) REFERENCES proof.zone_version(city_id,id,version),
  FOREIGN KEY(city_id,district_id) REFERENCES proof.district(city_id,id)
);
CREATE TABLE proof.request (
  id integer PRIMARY KEY, city_id integer NOT NULL, city_version integer NOT NULL,
  UNIQUE(id,city_id), FOREIGN KEY(city_id,city_version) REFERENCES proof.city_version(city_id,version)
);
CREATE TABLE proof.address_snapshot (
  id integer PRIMARY KEY, request_id integer NOT NULL, city_id integer NOT NULL, city_version integer NOT NULL,
  city_name text NOT NULL, timezone text NOT NULL, zone_id integer, zone_version integer, zone_label text,
  UNIQUE(request_id,city_id,id),
  FOREIGN KEY(request_id,city_id) REFERENCES proof.request(id,city_id),
  FOREIGN KEY(city_id,city_version) REFERENCES proof.city_version(city_id,version),
  FOREIGN KEY(city_id,zone_id,zone_version) REFERENCES proof.zone_version(city_id,id,version),
  CHECK((zone_id IS NULL AND zone_version IS NULL AND zone_label IS NULL)
    OR (zone_id IS NOT NULL AND zone_version IS NOT NULL AND zone_label IS NOT NULL))
);
CREATE TABLE proof.plan (
  id integer PRIMARY KEY, request_id integer NOT NULL, city_id integer NOT NULL, snapshot_id integer NOT NULL,
  starts_at timestamptz NOT NULL, ends_at timestamptz NOT NULL, active boolean NOT NULL,
  FOREIGN KEY(request_id,city_id,snapshot_id) REFERENCES proof.address_snapshot(request_id,city_id,id),
  CHECK(starts_at<ends_at)
);
CREATE UNIQUE INDEX one_active_plan ON proof.plan(request_id) WHERE active;
CREATE TABLE proof.file (id integer PRIMARY KEY);
CREATE TABLE proof.report (
  id integer PRIMARY KEY, request_id integer NOT NULL REFERENCES proof.request(id),
  UNIQUE(request_id,id)
);
CREATE TABLE proof.report_file (
  request_id integer NOT NULL, report_id integer NOT NULL, file_id integer NOT NULL REFERENCES proof.file(id),
  PRIMARY KEY(report_id,file_id), FOREIGN KEY(request_id,report_id) REFERENCES proof.report(request_id,id)
);
CREATE TABLE proof.quote (
  id integer PRIMARY KEY, request_id integer NOT NULL REFERENCES proof.request(id), UNIQUE(request_id,id)
);
CREATE TABLE proof.quote_line (
  id integer PRIMARY KEY, request_id integer NOT NULL, quote_id integer NOT NULL,
  amount_minor bigint NOT NULL CHECK(amount_minor>=0), quantity numeric NOT NULL CHECK(quantity>0),
  UNIQUE(request_id,quote_id,id), FOREIGN KEY(request_id,quote_id) REFERENCES proof.quote(request_id,id)
);
ALTER TABLE proof.report ADD COLUMN quote_id integer;
ALTER TABLE proof.report ADD CONSTRAINT report_quote_fk FOREIGN KEY(request_id,quote_id) REFERENCES proof.quote(request_id,id);
ALTER TABLE proof.report ADD CONSTRAINT report_quote_key UNIQUE(request_id,id,quote_id);
CREATE TABLE proof.report_line (
  report_id integer NOT NULL, request_id integer NOT NULL, quote_id integer NOT NULL, quote_line_id integer NOT NULL,
  PRIMARY KEY(report_id,quote_line_id),
  FOREIGN KEY(request_id,report_id,quote_id) REFERENCES proof.report(request_id,id,quote_id),
  FOREIGN KEY(request_id,quote_id,quote_line_id) REFERENCES proof.quote_line(request_id,quote_id,id)
);
CREATE TABLE proof.price (
  id integer PRIMARY KEY, city_id integer NOT NULL REFERENCES proof.city(id), item_id integer NOT NULL,
  valid_during tstzrange NOT NULL, amount_minor bigint NOT NULL CHECK(amount_minor>=0),
  CHECK(NOT isempty(valid_during) AND NOT lower_inf(valid_during) AND NOT upper_inf(valid_during)
    AND lower_inc(valid_during) AND NOT upper_inc(valid_during)),
  UNIQUE(city_id,id), EXCLUDE USING gist(city_id WITH =, item_id WITH =, valid_during WITH &&)
);
CREATE TABLE proof.accepted_price_snapshot (
  id integer PRIMARY KEY, request_id integer NOT NULL, city_id integer NOT NULL, price_id integer NOT NULL,
  amount_minor bigint NOT NULL CHECK(amount_minor>=0),
  FOREIGN KEY(request_id,city_id) REFERENCES proof.request(id,city_id),
  FOREIGN KEY(city_id,price_id) REFERENCES proof.price(city_id,id)
);
CREATE TABLE proof.membership (
  technician_id integer NOT NULL, city_id integer NOT NULL REFERENCES proof.city(id),
  PRIMARY KEY(technician_id,city_id)
);
CREATE TABLE proof.zone_grant (
  technician_id integer NOT NULL, city_id integer NOT NULL, zone_id integer NOT NULL, zone_version integer NOT NULL,
  PRIMARY KEY(technician_id,city_id,zone_id),
  FOREIGN KEY(technician_id,city_id) REFERENCES proof.membership(technician_id,city_id),
  FOREIGN KEY(city_id,zone_id,zone_version) REFERENCES proof.zone_version(city_id,id,version)
);
CREATE FUNCTION proof.reject_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Immutable synthetic history' USING ERRCODE='42501'; END;
$$;
CREATE TRIGGER immutable_city_version BEFORE UPDATE OR DELETE ON proof.city_version FOR EACH ROW EXECUTE FUNCTION proof.reject_immutable();
CREATE TRIGGER immutable_zone_version BEFORE UPDATE OR DELETE ON proof.zone_version FOR EACH ROW EXECUTE FUNCTION proof.reject_immutable();
CREATE TRIGGER immutable_address BEFORE UPDATE OR DELETE ON proof.address_snapshot FOR EACH ROW EXECUTE FUNCTION proof.reject_immutable();
CREATE TRIGGER immutable_accepted_price BEFORE UPDATE OR DELETE ON proof.accepted_price_snapshot FOR EACH ROW EXECUTE FUNCTION proof.reject_immutable();
CREATE FUNCTION proof.reject_request_city_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN IF NEW.city_id IS DISTINCT FROM OLD.city_id THEN RAISE EXCEPTION 'Stable synthetic city' USING ERRCODE='42501'; END IF; RETURN NEW; END;
$$;
CREATE TRIGGER stable_request_city BEFORE UPDATE ON proof.request FOR EACH ROW EXECUTE FUNCTION proof.reject_request_city_change();

GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA proof TO fixlevelup_runtime;
