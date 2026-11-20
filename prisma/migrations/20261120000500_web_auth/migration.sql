BEGIN;

CREATE TABLE "foundation"."web_sessions" (
    "id" UUID NOT NULL,
    "staff_id" UUID NOT NULL,
    "token_hash" VARCHAR(64) NOT NULL,
    "auth_version" INTEGER NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "idle_expires_at" TIMESTAMPTZ(6) NOT NULL,
    "absolute_expires_at" TIMESTAMPTZ(6) NOT NULL,
    "revoked_at" TIMESTAMPTZ(6),
    CONSTRAINT "web_sessions_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "web_sessions_staff_id_fkey" FOREIGN KEY ("staff_id")
        REFERENCES "foundation"."staff"("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "web_sessions_token_hash_check" CHECK ("token_hash" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT "web_sessions_auth_version_check" CHECK ("auth_version" >= 0),
    CONSTRAINT "web_sessions_expiry_check" CHECK ("created_at" < "idle_expires_at" AND "idle_expires_at" <= "absolute_expires_at"),
    CONSTRAINT "web_sessions_revoked_at_check" CHECK ("revoked_at" IS NULL OR "revoked_at" >= "created_at")
);
CREATE UNIQUE INDEX "web_sessions_token_hash_key" ON "foundation"."web_sessions"("token_hash");
CREATE INDEX "web_sessions_staff_id_idx" ON "foundation"."web_sessions"("staff_id");
CREATE INDEX "web_sessions_absolute_expiry_idx" ON "foundation"."web_sessions"("absolute_expires_at");

CREATE TABLE "foundation"."web_auth_throttles" (
    "key_hash" VARCHAR(64) NOT NULL,
    CONSTRAINT "web_auth_throttles_pkey" PRIMARY KEY ("key_hash"),
    CONSTRAINT "web_auth_throttles_key_hash_check" CHECK ("key_hash" ~ '^[0-9a-f]{64}$')
);

CREATE TABLE "foundation"."web_auth_attempts" (
    "id" UUID NOT NULL,
    "key_hash" VARCHAR(64) NOT NULL,
    "reserved_at" TIMESTAMPTZ(6) NOT NULL,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "failed_at" TIMESTAMPTZ(6),
    "completed_at" TIMESTAMPTZ(6),
    CONSTRAINT "web_auth_attempts_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "web_auth_attempts_key_hash_fkey" FOREIGN KEY ("key_hash")
        REFERENCES "foundation"."web_auth_throttles"("key_hash") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "web_auth_attempts_expiry_check" CHECK ("expires_at" > "reserved_at"),
    CONSTRAINT "web_auth_attempts_completion_check" CHECK (
        ("completed_at" IS NULL AND "failed_at" IS NULL) OR
        ("completed_at" IS NOT NULL AND "completed_at" >= "reserved_at" AND ("failed_at" IS NULL OR
            ("failed_at" = "completed_at" AND "expires_at" >= "failed_at" + INTERVAL '15 minutes')))
    )
);
CREATE INDEX "web_auth_attempts_key_expiry_idx" ON "foundation"."web_auth_attempts"("key_hash", "expires_at");
CREATE INDEX "web_auth_attempts_expiry_idx" ON "foundation"."web_auth_attempts"("expires_at");

REVOKE ALL ON "foundation"."web_sessions", "foundation"."web_auth_throttles", "foundation"."web_auth_attempts" FROM PUBLIC;

GRANT SELECT ("id", "role", "employment_state", "auth_version"), UPDATE ("auth_version")
    ON "foundation"."staff" TO "fixlevelup_runtime";
GRANT SELECT ("staff_id", "login", "password_hash"), UPDATE ("password_hash")
    ON "foundation"."staff_web_credentials" TO "fixlevelup_runtime";
GRANT SELECT ("id", "staff_id", "token_hash", "auth_version", "created_at", "idle_expires_at", "absolute_expires_at", "revoked_at"),
    INSERT ("id", "staff_id", "token_hash", "auth_version", "created_at", "idle_expires_at", "absolute_expires_at", "revoked_at"),
    UPDATE ("token_hash", "auth_version", "idle_expires_at", "revoked_at")
    ON "foundation"."web_sessions" TO "fixlevelup_runtime";
GRANT SELECT ("key_hash"), INSERT ("key_hash"), UPDATE ("key_hash")
    ON "foundation"."web_auth_throttles" TO "fixlevelup_runtime";
GRANT SELECT ("id", "key_hash", "reserved_at", "expires_at", "failed_at", "completed_at"),
    INSERT ("id", "key_hash", "reserved_at", "expires_at", "failed_at", "completed_at"),
    UPDATE ("expires_at", "failed_at", "completed_at")
    ON "foundation"."web_auth_attempts" TO "fixlevelup_runtime";

-- SECURITY DEFINER functions are owned by the migration role, not the runtime role.
-- Fixed search paths and fully qualified objects prevent caller-controlled name resolution.
CREATE FUNCTION "foundation"."cleanup_web_auth_attempts"() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE deleted_count integer;
BEGIN
    WITH candidates AS (
        SELECT "id" FROM "foundation"."web_auth_attempts"
        WHERE "expires_at" <= statement_timestamp()
        ORDER BY "expires_at", "id" LIMIT 100 FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM "foundation"."web_auth_attempts" a USING candidates c
        WHERE a."id" = c."id" AND a."expires_at" <= statement_timestamp()
        RETURNING 1
    ) SELECT count(*)::integer INTO deleted_count FROM deleted;
    RETURN deleted_count;
END;
$$;

-- Call only after deleting expired attempts. Key locks serialize against reservations;
-- the foreign key also prevents removal while any attempt still references a key.
CREATE FUNCTION "foundation"."cleanup_web_auth_throttles"() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE deleted_count integer;
BEGIN
    WITH candidates AS (
        SELECT t."key_hash" FROM "foundation"."web_auth_throttles" t
        WHERE NOT EXISTS (SELECT 1 FROM "foundation"."web_auth_attempts" a WHERE a."key_hash" = t."key_hash")
        ORDER BY t."key_hash" LIMIT 100 FOR UPDATE OF t SKIP LOCKED
    ), deleted AS (
        DELETE FROM "foundation"."web_auth_throttles" t USING candidates c
        WHERE t."key_hash" = c."key_hash"
          AND NOT EXISTS (SELECT 1 FROM "foundation"."web_auth_attempts" a WHERE a."key_hash" = t."key_hash")
        RETURNING 1
    ) SELECT count(*)::integer INTO deleted_count FROM deleted;
    RETURN deleted_count;
END;
$$;

CREATE FUNCTION "foundation"."cleanup_web_sessions"() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE deleted_count integer;
BEGIN
    WITH candidates AS (
        SELECT "id" FROM "foundation"."web_sessions"
        WHERE "absolute_expires_at" <= statement_timestamp() - INTERVAL '30 days'
        ORDER BY "absolute_expires_at", "id" LIMIT 100 FOR UPDATE SKIP LOCKED
    ), deleted AS (
        DELETE FROM "foundation"."web_sessions" s USING candidates c
        WHERE s."id" = c."id" AND s."absolute_expires_at" <= statement_timestamp() - INTERVAL '30 days'
        RETURNING 1
    ) SELECT count(*)::integer INTO deleted_count FROM deleted;
    RETURN deleted_count;
END;
$$;
REVOKE ALL ON FUNCTION "foundation"."cleanup_web_auth_attempts"(), "foundation"."cleanup_web_auth_throttles"(), "foundation"."cleanup_web_sessions"() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION "foundation"."cleanup_web_auth_attempts"(), "foundation"."cleanup_web_auth_throttles"(), "foundation"."cleanup_web_sessions"() TO "fixlevelup_runtime";

COMMIT;
