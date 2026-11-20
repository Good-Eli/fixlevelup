BEGIN;

CREATE TABLE "foundation"."user_permissions" (
    "id" UUID NOT NULL,
    "staff_id" UUID NOT NULL,
    "capability" VARCHAR(64) NOT NULL,
    "scope" VARCHAR(16) NOT NULL,
    "valid_from" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "valid_until" TIMESTAMPTZ(6),
    "revoked_at" TIMESTAMPTZ(6),
    "granted_by" UUID,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "user_permissions_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "user_permissions_staff_id_fkey" FOREIGN KEY ("staff_id")
        REFERENCES "foundation"."staff"("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "user_permissions_granted_by_fkey" FOREIGN KEY ("granted_by")
        REFERENCES "foundation"."staff"("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "user_permissions_capability_check" CHECK (length(trim("capability")) > 0),
    CONSTRAINT "user_permissions_scope_check" CHECK ("scope" IN ('GLOBAL')),
    CONSTRAINT "user_permissions_validity_check" CHECK ("valid_until" IS NULL OR "valid_until" > "valid_from"),
    CONSTRAINT "user_permissions_revoked_at_check" CHECK ("revoked_at" IS NULL OR "revoked_at" >= "created_at")
);
-- One non-revoked row per (staff, capability, scope); time validity is enforced by the
-- application per query because now() is not IMMUTABLE and cannot appear in an index
-- predicate. Re-granting revokes the old row and inserts a new one in one transaction.
CREATE UNIQUE INDEX "user_permissions_active_key"
    ON "foundation"."user_permissions"("staff_id", "capability", "scope") WHERE "revoked_at" IS NULL;
CREATE INDEX "user_permissions_staff_id_idx" ON "foundation"."user_permissions"("staff_id");

REVOKE ALL ON "foundation"."user_permissions" FROM PUBLIC;

-- SELECT/INSERT/UPDATE are strictly column-scoped; no DELETE or TRUNCATE.
GRANT SELECT ("id", "staff_id", "capability", "scope", "valid_from", "valid_until", "revoked_at", "granted_by", "created_at"),
    INSERT ("id", "staff_id", "capability", "scope", "valid_from", "valid_until", "granted_by", "created_at"),
    UPDATE ("valid_until", "revoked_at")
    ON "foundation"."user_permissions" TO "fixlevelup_runtime";
-- POST /staff guard needs to create pre-registered staff rows; UPDATE of
-- role/employment_state stays reserved for the P02-06 lifecycle.
GRANT INSERT ("id", "role", "employment_state", "auth_version")
    ON "foundation"."staff" TO "fixlevelup_runtime";

COMMIT;
