BEGIN;

CREATE SCHEMA IF NOT EXISTS "foundation";
REVOKE ALL ON SCHEMA "foundation" FROM PUBLIC;
GRANT USAGE ON SCHEMA "foundation" TO "fixlevelup_runtime";

CREATE TABLE "foundation"."audit_logs" (
    "id" UUID NOT NULL,
    "operation" VARCHAR(64) NOT NULL,
    "correlation_id" UUID NOT NULL,
    "occurred_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "details" JSONB NOT NULL DEFAULT '{}',
    CONSTRAINT "audit_logs_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "audit_logs_operation_check" CHECK (length("operation") > 0)
);

CREATE TABLE "foundation"."outbox_events" (
    "id" UUID NOT NULL,
    "event_id" UUID NOT NULL,
    "event_type" VARCHAR(64) NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "status" VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    "payload" JSONB NOT NULL DEFAULT '{}',
    CONSTRAINT "outbox_events_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "outbox_events_status_check" CHECK ("status" IN ('PENDING', 'EXPANDED', 'FAILED')),
    CONSTRAINT "outbox_events_type_check" CHECK (length("event_type") > 0)
);
CREATE UNIQUE INDEX "outbox_events_event_id_key" ON "foundation"."outbox_events"("event_id");

REVOKE ALL ON ALL TABLES IN SCHEMA "foundation" FROM PUBLIC;
GRANT SELECT, INSERT ON "foundation"."audit_logs" TO "fixlevelup_runtime";
GRANT SELECT, INSERT ON "foundation"."outbox_events" TO "fixlevelup_runtime";
GRANT UPDATE ("status") ON "foundation"."outbox_events" TO "fixlevelup_runtime";

COMMIT;
