BEGIN;

CREATE TABLE "foundation"."staff" (
    "id" UUID NOT NULL,
    "role" VARCHAR(16) NOT NULL,
    "employment_state" VARCHAR(16) NOT NULL,
    "auth_version" INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT "staff_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "staff_role_check" CHECK ("role" IN ('ADMIN', 'MANAGER', 'TECHNICIAN')),
    CONSTRAINT "staff_employment_state_check" CHECK ("employment_state" IN ('ACTIVE', 'INACTIVE')),
    CONSTRAINT "staff_auth_version_check" CHECK ("auth_version" >= 0)
);

CREATE TABLE "foundation"."staff_web_credentials" (
    "staff_id" UUID NOT NULL,
    "login" VARCHAR(255) NOT NULL,
    "password_hash" VARCHAR(255) NOT NULL,
    CONSTRAINT "staff_web_credentials_pkey" PRIMARY KEY ("staff_id"),
    CONSTRAINT "staff_web_credentials_staff_id_fkey" FOREIGN KEY ("staff_id")
        REFERENCES "foundation"."staff"("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
    CONSTRAINT "staff_web_credentials_login_check" CHECK (length(trim("login")) > 0),
    CONSTRAINT "staff_web_credentials_password_hash_check" CHECK (length(trim("password_hash")) > 0)
);
CREATE UNIQUE INDEX "staff_web_credentials_login_key" ON "foundation"."staff_web_credentials"("login");

CREATE TABLE "foundation"."staff_bootstrap_marker" (
    "id" SMALLINT NOT NULL,
    "staff_id" UUID NOT NULL,
    CONSTRAINT "staff_bootstrap_marker_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "staff_bootstrap_marker_singleton_check" CHECK ("id" = 1),
    CONSTRAINT "staff_bootstrap_marker_staff_id_fkey" FOREIGN KEY ("staff_id")
        REFERENCES "foundation"."staff"("id") ON DELETE RESTRICT ON UPDATE RESTRICT
);
CREATE UNIQUE INDEX "staff_bootstrap_marker_staff_id_key" ON "foundation"."staff_bootstrap_marker"("staff_id");

REVOKE ALL ON "foundation"."staff", "foundation"."staff_web_credentials", "foundation"."staff_bootstrap_marker" FROM PUBLIC;

COMMIT;
