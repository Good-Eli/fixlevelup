BEGIN;

CREATE TABLE "foundation"."staff_telegram_links" (
    "id" UUID NOT NULL,
    "staff_id" UUID NOT NULL,
    "telegram_user_id" BIGINT NOT NULL,
    "username" VARCHAR(64),
    "linked_by" UUID,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revoked_at" TIMESTAMPTZ(6),
    CONSTRAINT "staff_telegram_links_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "staff_telegram_links_staff_id_fkey" FOREIGN KEY ("staff_id")
        REFERENCES "foundation"."staff"("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "staff_telegram_links_linked_by_fkey" FOREIGN KEY ("linked_by")
        REFERENCES "foundation"."staff"("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "staff_telegram_links_telegram_user_id_check" CHECK ("telegram_user_id" > 0),
    CONSTRAINT "staff_telegram_links_username_check" CHECK ("username" IS NULL OR length(trim("username")) > 0),
    CONSTRAINT "staff_telegram_links_revoked_at_check" CHECK ("revoked_at" IS NULL OR "revoked_at" >= "created_at")
);
-- One active link per Telegram subject and per staff member; rebind revokes the old
-- row and inserts a new one in one transaction (same pattern as user_permissions_active_key).
-- telegram_user_id stays BIGINT end to end: the application binds the validated decimal
-- string as $1::bigint and never converts it to a JavaScript Number.
CREATE UNIQUE INDEX "staff_telegram_links_active_key"
    ON "foundation"."staff_telegram_links"("telegram_user_id") WHERE "revoked_at" IS NULL;
CREATE UNIQUE INDEX "staff_telegram_links_active_staff_key"
    ON "foundation"."staff_telegram_links"("staff_id") WHERE "revoked_at" IS NULL;
CREATE INDEX "staff_telegram_links_staff_id_idx" ON "foundation"."staff_telegram_links"("staff_id");

-- CRM rows keep the DEFAULT 'CRM'; TG exchange sets channel/initdata columns explicitly.
-- channel, initdata and telegram_link_id columns are immutable in a row: re-exchange inserts
-- a new row and revokes the old one. telegram_link_id pins the session to the exact
-- staff_telegram_links row used at exchange, so revoking that link (and re-binding a
-- different Telegram id) invalidates the old session instead of silently surviving
-- on any other active link of the same staff member.
-- TTL stays application policy (CRM 30m/12h, TG 2h/24h); the DB keeps only the shared
-- boundary CHECK web_sessions_expiry_check created in 20261120000500_web_auth.
ALTER TABLE "foundation"."web_sessions"
    ADD COLUMN "channel" VARCHAR(16) NOT NULL DEFAULT 'CRM',
    ADD COLUMN "initdata_digest" VARCHAR(64),
    ADD COLUMN "initdata_exchanged_at" TIMESTAMPTZ(6),
    ADD COLUMN "telegram_link_id" UUID,
    ADD CONSTRAINT "web_sessions_channel_check" CHECK ("channel" IN ('CRM', 'STAFF_TELEGRAM')),
    ADD CONSTRAINT "web_sessions_initdata_digest_check"
        CHECK ("initdata_digest" IS NULL OR "initdata_digest" ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT "web_sessions_channel_pair_check" CHECK (
        ("channel" = 'CRM' AND "initdata_digest" IS NULL AND "initdata_exchanged_at" IS NULL AND "telegram_link_id" IS NULL)
        OR ("channel" = 'STAFF_TELEGRAM' AND "initdata_digest" IS NOT NULL AND "initdata_exchanged_at" IS NOT NULL AND "telegram_link_id" IS NOT NULL)
    ),
    ADD CONSTRAINT "web_sessions_initdata_exchanged_at_check"
        CHECK ("initdata_exchanged_at" IS NULL OR "initdata_exchanged_at" >= "created_at"),
    ADD CONSTRAINT "web_sessions_telegram_link_id_fkey" FOREIGN KEY ("telegram_link_id")
        REFERENCES "foundation"."staff_telegram_links"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- Digest policy (owner-approved): single exchange with a 60-second grace window.
-- Deliberately a plain partial index, NOT unique: the application looks up an active
-- session by initdata_digest and returns that same session while
-- clock_timestamp() <= initdata_exchanged_at + 60 seconds; a repeat exchange after
-- the grace window is denied. Raw initData is never stored or logged, only this hash.
CREATE INDEX "web_sessions_initdata_digest_idx"
    ON "foundation"."web_sessions"("initdata_digest") WHERE "initdata_digest" IS NOT NULL;

REVOKE ALL ON "foundation"."staff_telegram_links" FROM PUBLIC;

-- Exchange lookup only: the binding flow (INSERT of links) stays outside P02-05 and
-- tests insert synthetic link fixtures as the migration role. UPDATE is limited to
-- revocation and username refresh; no INSERT/DELETE/TRUNCATE for the runtime role.
-- Telegram authentication must re-check an active link (EXISTS ... revoked_at IS NULL)
-- and serialize revoke-vs-exchange on the staff row lock (SELECT ... FOR UPDATE),
-- reusing the staff-before-session lock order of web authentication.
GRANT SELECT ("id", "staff_id", "telegram_user_id", "username", "linked_by", "created_at", "revoked_at"),
    UPDATE ("revoked_at", "username")
    ON "foundation"."staff_telegram_links" TO "fixlevelup_runtime";
GRANT SELECT ("channel", "initdata_digest", "initdata_exchanged_at", "telegram_link_id"),
    INSERT ("channel", "initdata_digest", "initdata_exchanged_at", "telegram_link_id")
    ON "foundation"."web_sessions" TO "fixlevelup_runtime";

-- initData exchange throttling reuses foundation.web_auth_throttles/web_auth_attempts
-- (granted in 20261120000500_web_auth) with HMAC dimensions 'telegram-user'
-- (validated telegram_user_id string) and 'source', limit 5 per 15 minutes each;
-- no new throttle tables.

COMMIT;
