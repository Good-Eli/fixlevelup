# P05-03 — Callback, repair, manual intake, attachments and staff bridge

## Status

**IMPLEMENTED / COMPLETE.** P05-03 is implemented in the current P05 candidate
as the S3 request-effects profile (migration 024), integrated with the F
foundation from P05-02. Final full-stage technical acceptance is pending the
corrected exact-head CI run described in [P05-EVIDENCE](P05-EVIDENCE.md).

All P05 HTTP endpoints are constructed only in isolated test composition T;
release composition R does not register them. This is not a production or
live-channel activation claim.

## Delivered scope

- F submit paths for short callback and full repair request, using the existing
  P03 session anchor, current consent/evidence, exact city context and
  idempotency key. A callback does not need an address and does not serialize
  address/contact PII into its public response.
- Staff manual intake with a separate staff-evidence path; it does not forge a
  client F consent. Staff authorization rechecks actor, permission, current
  CITY assignment and state after relevant lock waits.
- Explicit channel choice/offer and readiness state for TG/VK/MAX without
  dispatch or transport delivery. A no-call option remains an explicit stored
  preference, not consent to call.
- Current contact PHONE permission is append-only GIVEN/REVOKED evidence tied
  to request/contact revision/purpose. Choosing or withdrawing PHONE is an
  explicit command; changing contact does not carry forward previous consent.
- READY file attachment is limited to the exact current F owner, evidence,
  published READY file and access window. The DB interlock prevents an attached
  file moving from OPEN to PENDING_LEDGER while the attachment remains;
  attach-first and delete-first outcomes are checked against real PostgreSQL,
  Garage objects and the file ledger.
- Request creation, submit edge, immutable events, receipts, audit/outbox
  projection and attachment links form one guarded effect graph. Partial or
  uncertain projections fail closed and same-key replay does not duplicate
  requests or file links.

## Implementation and migration

- `apps/api/src/requests/intake/http.ts` — public F and staff route surface,
  parsing, Origin/CSRF/session proof, staff mutation guard and safe problem
  responses.
- `service.ts`, `store.ts`, `effects.ts`, `coverage.ts`, `basis.ts`,
  `waiting.ts` in the same intake module — commands, transaction/effect
  graph, immutable projections, coverage and waiting facts.
- `apps/api/src/requests/crypto/payload-key-directory.ts` and
  `payload-key-recovery.ts` — per-cell managed key slots and verified
  offline recovery evidence.
- `apps/api/src/authz/p05-grants.ts` and bridge/profile code — scoped
  staff/customer request-grant bridge and runtime DB fence.
- `prisma/migrations/20261125000100_request_intake_effects/migration.sql`
  — additive S3 / migration 024: ten request-intake effect tables and thirty
  new CHECK constraints with exact ACL and immutability guards.

## Verification required for final full-stage PASS

The exact-head full CI Gate must show:
- real Nest HTTPS + PostgreSQL P05 intake, staff bridge and role/state checks;
- the full 432-cell CITY-RBAC × state × command oracle;
- PII-before-decrypt, partial receipt/audit/outbox failure, rollback and replay;
- isolated PG 18.7 + Garage + ledger/trust-floor opt-in, migration/restore and
  old-binary checks;
- all real ClamAV/Sharp engine cases, including both
  `p05-attachment-http.test.ts` cases as **passed**, not skipped;
- API/Web/Mini builds, typecheck, P03/P04/P05 wire parity and browser proof;
- exact source-tree freeze after all required jobs succeed.

The old run 45942722310 did not execute the two attachment HTTP cases because
the workflow omitted required opt-in flags; it is not evidence for those
scenarios. The corrected workflow and suite fail closed on missing opt-ins
and on reuse of the single-use engine ticket. See [P05-EVIDENCE](P05-EVIDENCE.md).

## Boundaries / non-goals

No live Telegram/VK/MAX delivery, real channel accounts, manager notification
delivery, production customer database, real PII, public file upload/download
or signed URL transport is enabled by P05-03. P05 stores readiness/offers and
durable manager outbox intent only; actual provider delivery belongs to P07.
The test-only T composition is not registered in release `AppModule` R.
Migration 024 is tested only on disposable PostgreSQL; no developer or
production database was migrated.
