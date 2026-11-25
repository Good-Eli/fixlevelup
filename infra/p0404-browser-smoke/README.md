# P04-04 production HTTPS browser proof (pinned S0 cap)

Run from the repository root with Windows PowerShell and the local Docker Linux engine:

```powershell
pwsh -File infra/p0305-browser-smoke/build-live.ps1 -Image fixlevelup-p0404-browser:local
pwsh -File infra/p0404-browser-smoke/run-live.ps1 -Image fixlevelup-p0404-browser:local
```

The first command reuses the pinned P03 proof base and builds the production artifacts with the frozen lockfile. The runner verifies the selected Linux image, creates a new PG 18.7 container with `--network none`, loopback-only listeners and in-memory (tmpfs) database storage, then shares only that network namespace with the browser container. No host ports, working DB, external dependencies or credentials are used at runtime.

## Schema profile

The current migration chain has 24 directories. This proof applies exactly the **reviewed pinned 21-migration prefix (S0)**, byte-verified against `SHA256SUMS`, and reports the excluded `20261123000100_request_intake_foundation`, `20261124000100_form_session_foundation`, `20261125000100_request_intake_effects` suffix explicitly. Any prefix/checksum drift refuses before a database is touched. `prisma migrate deploy` is not used because it would apply the excluded P05 migrations too.

## Admission

Nest is not composed around the P05-01 §7 admission — it is started through it. The fixture creates a separate disposable control database owned by the cluster operator, with exactly one narrow launcher role (schema USAGE, SELECT/INSERT on `launch_control.launch_proofs`, UPDATE of `state`/`consumed_at` only, no DELETE/DDL). `fixlevelup_runtime` and `fixlevelup_migrator` get no CONNECT on it. PostgreSQL separately verifies the unique cluster marker, exact database name, server version, role, loopback TCP peer, the initial absence of prior application schema/roles, and — after the contour exists — that the cluster contains exactly this run's application database, its two application roles and one control database with one narrow launcher role.

The launcher holds the witness lock on the application database, signs and registers one short-lived proof, and the production `superviseLaunch` owns the child's inherited IPC channel and performs the single-winner CAS. `launch-api.mjs` then follows the production sequence: `loadRuntimeAdmission` → `admitProcess` → `createApi` → both real readiness gates → ready message. The registry row is asserted `CONSUMED` after activation. The launcher/registry/control-contour modules are excluded from the release build, so they are compiled from this image's own reviewed sources into a unique ephemeral scratch output at container start; `dist` and the release graph are untouched.

The founder provisions the published `p04-primary` (`P04 Primary`, ACTIVE) and `p04-outside` (`P04 Outside`, DRAFT) via actual P03 geography commands. The founder creates and assigns a custom `P04 Price Only` role (`pricing.read`/`pricing.manage`, CITY only), assigns that employee only to the primary city, and logs out. The manager's ephemeral web credential is the only employee seed written directly by the migrator. Playwright receives the P0404 admin/manager logins, passwords and staff IDs, both city IDs and a private proof token; it creates real fresh browser sessions.

The Playwright worker (not page JavaScript) POSTs JSON to `http://127.0.0.1:4177/proof` with `Authorization: Bearer <P0404_PROOF_TOKEN>` and `Content-Type: application/json`. The request is `{ writes, deniedKeys? }`. Each write is `{ kind, actor, id, key, version }` plus fields below. No reviewed text, auth/session headers from Nest, amounts, raw actor IDs or database details are submitted to or returned by the observer.

| `kind` | `actor` | Committed command | Additional request fields |
| --- | --- | --- | --- |
| `item` | `admin` | P04 item publication | `revisionId`, `revisionVersion` |
| `price` | `manager` | P04 fixed-price publication in primary city (RUB max signed INT64; future start) | `revisionId`, `revisionVersion`, `itemId` |
| `district` | `admin` | P03 district creation in primary city | none |
| `coverage` | `admin` | P03 replacement of district coverage on the draft (`id` is the area version ID) | `areaId`, `districtId` |
| `faq` | `admin` | P03 FAQ publication | `revisionId`, `revisionVersion` |
| `contact` | `admin` | P03 publication of the new immutable primary-city contact revision (`id` is the city ID) | `revisionId` |

Each write reports whether the intended domain row, receipt, audit and correlated outbox event exist exactly once. The read-only observer also returns operation/table counts and the number of receipts with any submitted denied key. The runner expects all six proofs before and after denial with unchanged counts and no denied receipt. Raw application, database and Playwright diagnostics are not printed. Both verified container names and IDs are printed and only those containers are stopped and removed; no images or volumes are pruned.

`-FixtureOnly` runs an independent compiled Nest / PostgreSQL / observer command proof against the selected image without starting Next or Playwright. This is useful for fixture validation but does not count as browser acceptance.
