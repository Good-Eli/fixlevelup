BEGIN;

ALTER TABLE "foundation"."outbox_events"
    ADD COLUMN "attempt_count" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "foundation"."outbox_events"
    ADD CONSTRAINT "outbox_events_attempt_count_check" CHECK ("attempt_count" >= 0);
CREATE INDEX "outbox_events_queue_idx" ON "foundation"."outbox_events"("status", "created_at");
GRANT UPDATE ("attempt_count") ON "foundation"."outbox_events" TO "fixlevelup_runtime";

COMMIT;
