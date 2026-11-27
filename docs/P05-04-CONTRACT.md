# P05-04 — Early commands, bounded reads and P05 wire contract

## Status

**IMPLEMENTED / OWNER ACCEPTED — 27.11.2026.** P05-04 implements the early P05 command/read surface and closes the shared P05 wire contract. The owner accepted all four P05 slices and explicitly equated ChatGPT `PASS — FULL P05` with the required Astra full-stage verdict. Exact technical evidence: run `45953489126`, SHA `0d7f60dbee1bddca63e9f1868a03ebf1230ec69f`, 8/8 success and frozen candidate. Acceptance is synthetic-scope only.

P05 HTTP controllers are present only in isolated test composition T;
release composition R remains free of P05 controllers and routes.

## Delivered scope

- Canonical F and staff command allowlists: create callback/repair, read own
  request session, choose callback/PHONE fallback, withdraw PHONE permission,
  cancel through original F where allowed, staff manual creation, narrow staff
  read and early staff state commands.
- Staff GET is a bounded non-PII projection, protected by current staff web
  authentication, capability, CITY scope and request state. It is not the P06
  CRM card, broad PII search or an attachment download endpoint.
- Read-only selectors expose waiting/reminder and cleanup facts without
  introducing a dispatcher, scheduled worker or provider delivery path.
- Mutations require the applicable proof, exact Origin/CSRF where applicable,
  idempotency identity and current version (If-Match) where specified. Replay
  is exact and side-effect-safe; stale scope/state/version fails closed.
- The P05 wire contract contains exact route vocabulary, closed DTO decoders,
  closed problem codes, byte/UTF-8 caps, strong ETag grammar and explicit
  not-modified semantics. The typed client sends canonical methods, paths and
  headers, performs no retries and adds no credentials.
- OpenAPI 3.1 generation, runtime route table, hand-written DTO decoders and
  typed client are checked for parity. P03/P04 wire surfaces remain unchanged.

## Implementation and verification

- `apps/api/src/requests/intake/http.ts` — controller and route/mutation
  dispatch.
- `packages/p03-contracts/p05-openapi.mjs`,
  `p05-verify.mjs` and generated `dist/p05-openapi.json` — OpenAPI/wire
  contract and runtime parity verification.
- `apps/api/tests/p05-wire.test.ts` — route closure, DTO decode/encode,
  semantic-vs-malformed errors, ETag/projections and typed-client headers.
- `apps/api/tests/p05-release-composition.test.ts` — release boundary:
  compiled R entrypoints exclude P05 modules, route strings, controllers and
  outbox consumer.
- `apps/api/tests/p05-intake-http.test.ts` and
  `p05-bridge-profiles.test.ts` — real HTTPS/PG commands, state/scope checks,
  staff bridge, revoke/replay and negative direct-DML cases.
- CI builds API, Web and Mini App, runs workspace typecheck, checks the
  24-migration history and P03/P04/P05 wire parity, and runs Chromium,
  Firefox and WebKit desktop/mobile browser proof.

## Boundaries / non-goals

P05-04 does not implement later workflow states, scheduling, visits, estimates,
payments, broad CRM, channel dispatch, manager delivery, real platform
credentials or production activation. No live P05 API is enabled in release R.
Waiting and cleanup selectors are read-only; they do not perform external
actions. No working database was migrated by the test Gate.
