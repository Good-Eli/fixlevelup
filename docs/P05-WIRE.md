# P05 wire contract — `@fixlevelup/p03-contracts/p05`

Shared, side-effect-free P05-03/P05-04 wire contract: strict closed DTOs, exact
route matching, strong-ETag syntax, safe response projections and a typed client.
Source: [`packages/p03-contracts/src/p05.ts`](../packages/p03-contracts/src/p05.ts).
Normative surface: [P05-PLAN §4.3, §6.1, §6.3](P05-PLAN.md#L65-L73).

This document describes **syntax only**. It grants no authority and is not a
runtime review, acceptance or deployment claim.

## Boundaries

- The package parses syntax, normalizes and freezes DTOs, matches exact routes
  and drives an injected transport. It performs **no** network I/O, reads no
  configuration, hashes no ETag, opens no database and computes no coverage.
- Controllers must run the P05 authority chain **before** any decoder:
  - F: live original F anchor, exact `Origin`, CSRF proof, current legal basis,
    and only then body parsing;
  - staff: live web session, exact `requests.*` capability + `requests.read` in
    the same target, and only then body parsing.
- A DTO is not an admission gate. A `P05DecodeError` never means "authorized";
  an accepted DTO never means "allowed".
- The two canonical GETs (`readRequestSession`, `readStaffRequest`) return only
  `{data: …}`; the strong `ETag: "p05-r1-<sha256>"` is computed by the server
  over the exact representation bytes. The package validates the tag syntax and
  round-trips it, and never derives it.
- P03/P04 wire (`index`, `p04`, `p04-json`) is unchanged; P05 lives behind its
  own subpath export.

## Routes (16 exact operations)

Exact method + canonical pathname only: no query string, fragment, trailing
slash, double slash, `%`-encoding, case-folded method or aliased path.

| Operation | Method | Path (relative to `/api/v1`) | Scope |
|---|---|---|---|
| `createCallback` | POST | `/public/callback-requests` | F |
| `createRepair` | POST | `/public/repair-requests` | F |
| `readRequestSession` | GET | `/public/request-session` | F |
| `chooseCallback` | POST | `/public/request-session/contact-mode` | F |
| `withdrawPhonePermission` | POST | `/public/request-session/phone-permissions` | F |
| `cancelRequestF` | POST | `/public/request-session/cancel` | F |
| `createManualRequest` | POST | `/requests` | STAFF |
| `readStaffRequest` | GET | `/requests/{id}` | STAFF |
| `startReview` | POST | `/requests/{id}/commands/start-review` | STAFF |
| `convertCallback` | POST | `/requests/{id}/commands/convert-callback` | STAFF |
| `changeDetails` | POST | `/requests/{id}/commands/change-details` | STAFF |
| `recordCoverage` | POST | `/requests/{id}/commands/record-coverage` | STAFF |
| `changeContact` | POST | `/requests/{id}/commands/change-contact` | STAFF |
| `readyForDispatch` | POST | `/requests/{id}/commands/ready-for-dispatch` | STAFF |
| `withdrawPhoneStaff` | POST | `/requests/{id}/commands/withdraw-phone` | STAFF |
| `cancelRequestStaff` | POST | `/requests/{id}/commands/cancel` | STAFF |

Headers (`P05_HEADERS`): `origin`, `x-form-session-id` (F selector, required on
every F request including the GET), `x-csrf-token` (F stateless proof or the
staff session-bound token), `idempotency-key`, `if-match`, `if-none-match`.

## Body caps and grammar

- 16 KiB (`P05_BODY_BYTES`) checked before parsing; no compression.
- Strict UTF-8, duplicate-aware JSON, depth 8 / 256 nodes (`P05_MAX_DEPTH`,
  `P05_MAX_NODES`), closed objects: an unknown member is a malformed `400`.
- At most 32 IDs in `fault.faultIds` and `attachments` (`P05_MAX_IDS`); duplicate
  IDs are a semantic `422`.

## DTO summary (closed, normalized, frozen)

- `P05FContact {name, phone}` — phone is `+` and 10..15 digits.
- `P05Consent {evidenceId, documentVersionId, accepted: true}` — `false` is a
  semantic `422`; the server re-validates it.
- `P05ChannelSelection {provider: TG|VK|MAX, optionVersionId, catalogVersionId,
  purpose: REQUEST_CONFIRMATION}`.
- `P05Address {street, building, districtId?, apartment?, entrance?, floor?,
  intercom?, accessNotes?}` — no city or coverage override.
- `P05Appliance {categoryId, brandId?, modelId?, modelText?, approximateAge?}`.
- `P05Fault {faultIds: string[], otherDescription?, description?, errorCode?}` —
  **completeness rule** (P05-PLAN §1, Q12/Q16): a repair is complete with at
  least one selected published fault of the request's category **or** an
  "other fault" with a non-empty `otherDescription`. `faultIds` is therefore
  optional on the wire: omitting it (or sending `[]`) is accepted and
  **normalizes to an empty frozen array**, so the canonical re-encoded bytes
  always carry `faultIds`. A block with neither a selected id nor
  `otherDescription` is a semantic `422 FAULT_REQUIRED` (never a malformed
  `400`); blank/oversized text stays a `400`, and unknown members stay a `400`.
  The same rule applies to every fault block: `createRepair`,
  `createManualRequest` (REPAIR), `convertCallback`, `changeDetails`
  (`APPLIANCE` section).
- `P05PreferredVisit {from, to}` — bounded time preference, not an appointment.
- `P05CallbackRequest {contact, consent, phonePermission: true,
  callbackIntervalId?, comment?}`.
- `P05RepairRequest {contact, consent, channelSelection, address, appliance,
  fault, urgency?, preferredVisit?, attachments?}` — messenger channel only.
- `P05ManualRequest` — discriminated by `type`:
  - `CALLBACK`: `{type, sourceEntryId, evidenceId, contact: P05ManualPhoneContact,
    callbackIntervalId?, comment?}`; PHONE contact only.
  - `REPAIR`: `{type, sourceEntryId, evidenceId, contact, address, appliance,
    fault, urgency?, preferredVisit?}`; contact is PHONE or CHANNEL.
- `P05ManualPhoneContact {mode: PHONE, name, phone, phonePermission: true,
  phoneEvidenceId}`.
- `P05ManualChannelContact {mode: CHANNEL, name, phone, channelSelection}` — the
  normalized phone is **kept** for manual no-call intake but is explicitly not a
  permission proof; there is no `phonePermission` member.
- `P05ContactModeInput {phonePermission: true}` (ChooseCallback).
- `P05PhoneWithdrawalInput {action: 'REVOKED'}`; `P05CancelInput {reasonEntryId}`;
  `P05EmptyInput {}`.
- `P05ConvertCallbackInput {address, appliance, fault, urgency?,
  preferredVisit?}` — contact and channel are not replaceable here.
- `P05ChangeDetailsInput` — one named section:
  - `ADDRESS`: `{section, address}`;
  - `APPLIANCE`: `{section, appliance, fault}` — a new appliance invalidates the
    old fault selection, so the fault block is replaced with it, never dropped;
  - `PREFERENCE`: `{section, urgency?, preferredVisit?}`; empty is a `422`.
- `P05CoverageInput {evidenceId, areaId?, outcome, reason?}` — aligned with
  migration 024 `request_coverage_assessments`
  (`CHECK (outcome NOT IN ('IN_ZONE','EXCEPTION') OR area_id IS NOT NULL)`,
  `CHECK (outcome NOT IN ('OUTSIDE','EXCEPTION') OR reason IS NOT NULL)`):
  - `IN_ZONE` requires `areaId`; an optional `reason` may only be
    `OVERLAP_REVIEW` (positive overlap decision);
  - `EXCEPTION` requires `areaId` **and** an explicit rationale — `OUTSIDE_REVIEW`
    or `OPERATOR_REVIEW`; `EXCEPTION` is never automatic;
  - `OUTSIDE` requires `OUTSIDE_REVIEW` or `OPERATOR_REVIEW`; `areaId` is refused
    because a selected zone would imply positive authority;
  - `REVIEW` requires `OVERLAP_REVIEW` or `OPERATOR_REVIEW`; `areaId` is refused.
  The candidate basis is taken only via the server port; the body cannot name it.
- `P05ChangeContactInput {contact: P05FContact, evidenceId}` — contact values
  only. The contact mode is persisted server-side, and no `mode`,
  `channelSelection` or `phonePermission` member exists, so a replacement can
  never switch channel or grant PHONE.
- `P05StaffWithdrawInput {evidenceId}`.

Urgency uses the migration 022 source vocabulary exactly: `FLEXIBLE`,
`WITHIN_DAY`, `URGENT`.

## Receipts and projections

- `P05FWriteReceipt {publicNumber, status, version}`.
- `P05StaffWriteReceipt {id, publicNumber, status, version}`.
- `P05EffectReceipt {applied, version}`.
- `P05RequestSessionData` = `{publicNumber, status, version}` | `{version}`.
- `P05StaffRequestData` = `{id, publicNumber, type, status, version}` |
  `{version}`.
- `publicNumber` is a decimal **bigint string** (migration 022 uses `bigint`):
  canonical digits, no sign, no leading zero, bounded by int64. It is never a
  JSON number here.
- No write receipt carries an ETag.

## Errors

`P05DecodeError {kind: 'MALFORMED'|'SEMANTIC', code, path}` with
`p05DecodeStatus()` mapping: semantic → `422`; over the body cap → `413`; an
unusable response projection → safe `503`; everything else → `400`.

`P05Problem` is the closed five-key envelope
`{type: 'about:blank', title, status, code, requestId}`; `title` must equal
`code` and `status` must equal `P05_PROBLEM_STATUS[code]`. `P05WireError`
carries the status, code and (when present) the parsed problem.

Closed vocabulary: `REQUEST_REJECTED`, `MALFORMED` (400), `UNAUTHORIZED` (401),
`FORBIDDEN` (403), `NOT_FOUND` (404), `REQUEST_TIMEOUT` (408), `CONFLICT`,
`CITY_CONTEXT_STALE`, `CONSENT_REQUIRED`, `CHANNEL_OPTIONS_CHANGED`,
`CHANNEL_OFFER_DISABLED`, `CHANNEL_NOT_READY`, `FORM_ALREADY_SUBMITTED`,
`IDEMPOTENCY_KEY_REUSED`, `COVERAGE_ASSESSMENT_STALE` (409), `VERSION_MISMATCH`
(412), `BODY_TOO_LARGE` (413), `UNSUPPORTED_MEDIA_TYPE` (415), `SEMANTIC` (422),
`PRECONDITION_REQUIRED` (428), `QUOTA` (429), `INTERNAL_ERROR` (500),
`REQUEST_RULES_UNAVAILABLE`, `NOT_READY` (503). A missing, unsupported or
unpinned saved policy package refuses a new effect as `REQUEST_RULES_UNAVAILABLE`;
its digest is checked against the independently reviewed package pin.

## Typed client

`createP05Client(transport, {origin})` returns `P05Client.request(operation,
input)`. Input is strictly typed per operation: `id` only for staff by-id,
`body` only for body operations, `idempotencyKey` for every mutation,
`csrfToken` and exact `Origin` for every mutation (an F proof or the existing staff session-bound token, respectively), `formSessionId` for every F request,
`expectedVersion` (`If-Match`) for by-id commands and the F mutations,
`ifNoneMatch` only for the two canonical GETs. Results are
`{kind:'data', status, data, etag}` or `{kind:'not-modified', status: 304,
etag}`; non-success statuses raise `P05WireError`. The client performs no
retries and adds no credentials.

## Artifacts and checks

- `dist/p05-openapi.json` — OpenAPI 3.1.0, generated by `generate-p05.mjs` from
  `p05-openapi.mjs` (data only; the DTO decoders are hand-written).
- `p05-verify.mjs` — asserts artifact ↔ runtime route table ↔ decoders ↔ client
  parity, exact-route refusal, cap/UTF-8/duplicate handling, the semantic-422
  split, the ETag grammar, closed projections and the client header contract.
- `apps/api/tests/p05-wire.test.ts` — self-contained Vitest mirror; no database,
  no HTTP server, no network.

Commands:

```
corepack pnpm --filter @fixlevelup/p03-contracts run build   # tsc + p04/p05 artifacts
node packages/p03-contracts/p05-verify.mjs
node node_modules/vitest/vitest.mjs run apps/api/tests/p05-wire.test.ts
```

## Not in scope

No controllers, no database, no migrations, no RBAC grants, no working
database run, no git commit. The X01 acceptance oracle (§8) is not wired here.
