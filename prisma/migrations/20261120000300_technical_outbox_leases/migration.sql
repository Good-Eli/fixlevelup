BEGIN;

ALTER TABLE "foundation"."outbox_events"
    ADD COLUMN "lease_owner" UUID,
    ADD COLUMN "lease_generation" BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN "lease_expires_at" TIMESTAMPTZ(6),
    ADD COLUMN "next_attempt_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN "last_error_code" VARCHAR(32),
    ADD CONSTRAINT "outbox_events_lease_generation_check" CHECK ("lease_generation" >= 0),
    ADD CONSTRAINT "outbox_events_lease_pair_check" CHECK (("lease_owner" IS NULL) = ("lease_expires_at" IS NULL)),
    ADD CONSTRAINT "outbox_events_lease_pending_check" CHECK ("lease_owner" IS NULL OR "status" = 'PENDING'),
    ADD CONSTRAINT "outbox_events_last_error_code_check" CHECK ("last_error_code" IN ('HANDLER_FAILED', 'ATTEMPTS_EXHAUSTED'));

CREATE INDEX "outbox_events_due_idx" ON "foundation"."outbox_events"("status", "next_attempt_at", "created_at", "id");
GRANT UPDATE ("lease_owner", "lease_generation", "lease_expires_at", "next_attempt_at", "last_error_code")
    ON "foundation"."outbox_events" TO "fixlevelup_runtime";

COMMIT;
