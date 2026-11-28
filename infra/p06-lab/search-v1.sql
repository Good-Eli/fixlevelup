-- Derived search data in the isolated CRM overlay.
BEGIN;

CREATE TABLE p06_crm.search_generation (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    generation uuid NOT NULL,
    key_check bytea NOT NULL CHECK (octet_length(key_check) = 32)
);

CREATE TABLE p06_crm.contact_search (
    request_id uuid PRIMARY KEY,
    city_id uuid NOT NULL,
    contact_revision_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    public_number bigint NOT NULL,
    name_token bytea NOT NULL CHECK (octet_length(name_token) = 32),
    phone_token bytea CHECK (octet_length(phone_token) = 32)
);

CREATE INDEX contact_search_name_idx ON p06_crm.contact_search(city_id,name_token,created_at DESC,public_number DESC);
CREATE INDEX contact_search_phone_idx ON p06_crm.contact_search(city_id,phone_token,created_at DESC,public_number DESC) WHERE phone_token IS NOT NULL;

CREATE TABLE p06_crm.search_budget (
    scope text NOT NULL CHECK (scope IN ('STAFF','CITY')),
    city_id uuid NOT NULL,
    subject_id uuid NOT NULL,
    minute timestamptz NOT NULL,
    used integer NOT NULL CHECK (used BETWEEN 1 AND 240),
    PRIMARY KEY (scope,city_id,subject_id)
);

GRANT SELECT ON p06_crm.search_generation TO fixlevelup_runtime;
GRANT SELECT,INSERT,DELETE ON p06_crm.contact_search TO fixlevelup_runtime;
GRANT UPDATE (phone_token) ON p06_crm.contact_search TO fixlevelup_runtime;
GRANT SELECT,INSERT,UPDATE ON p06_crm.search_budget TO fixlevelup_runtime;

COMMIT;
