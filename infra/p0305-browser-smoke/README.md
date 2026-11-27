# P03-05 browser proof (synthetic only, pinned S0 cap)

Two independent proofs use the matching Chromium/Firefox/WebKit installation from the existing Node 24.22.3 + Playwright 1.65.1 proof image. The default suite includes a new production-Next/intercepted CRM suite in all six existing desktop/mobile viewport projects and retains technical/P02/P03-02 tests as separate UI proofs. The isolated live config registers one Chromium case only when the live runner sets its fixture variables. No trace, video, screenshot or scope URL/body logging is enabled by the new suites. No production data, services, CA trust or DSH server is touched.

## Schema profile and launch contract

The current migration chain has 24 directories. This proof applies exactly the **reviewed pinned 21-migration prefix (S0)** and reports the excluded suffix explicitly — it never hides the real chain:

- applied: `20261120000100_technical_audit_outbox` … `20261122000700_catalog_management` (21, byte-verified against `infra/p0404-browser-smoke/SHA256SUMS`);
- excluded and reported: `20261123000100_request_intake_foundation`, `20261124000100_form_session_foundation`, `20261125000100_request_intake_effects` (the P05 022–024 layers).

Any prefix, ordering or checksum drift refuses before a database is touched. `prisma migrate deploy` is deliberately not used: it would apply the whole chain, including the excluded P05 migrations.

The compiled API is started through the **real P05-01 §7 admission contour**, not around it: a disposable control database with a narrow launcher role, a launcher-held witness lock on the application database, a signed one-time Ed25519 proof, the production `superviseLaunch` over the child's inherited private IPC channel, and the real single-winner ISSUED→CONSUMED CAS in the control registry. The child receives only its own `LAUNCH_*` facts; it never sees control credentials. The runner asserts the registry row is `CONSUMED` after activation. The launcher/registry/control-contour modules are excluded from the release build on purpose, so they are compiled from this image's own reviewed sources into a unique ephemeral scratch output at container start; nothing is written into `dist` or the release graph.

## Run

From the repo root and after sources are frozen, choose a fresh image tag:

```powershell
$image = "fixlevelup-p0305-browser:proof-" + [guid]::NewGuid().ToString('N').Substring(0,12)
pwsh -File infra/p0305-browser-smoke/build-live.ps1 -Image $image
pwsh -File infra/p0305-browser-smoke/run-live.ps1 -Image $image
```

The build requires the exact cached proof image and store (`infra/browser-proof`), and the PostgreSQL 18.7 digest already used by the repository. It copies source only (root Docker exclusions), uses the existing frozen external dependency graph with dependency hooks disabled. Only the frozen install layer can fetch registry metadata (the pinned cached image does not contain a complete metadata mirror); the compile layer has no network. Browser executables are already in the pinned base, and the run never downloads them. Runtime receives no source checkout, sockets, dev environment files, host bind mounts or forwarded ports.

Live: a unique PostgreSQL container runs with `--network none`, fresh **in-memory (tmpfs)** storage and no persistent volume. The browser/Next/Nest container shares only its loopback namespace. The database fixture proves generated cluster identity and absence of prior roles/schema before using its own one-time credentials, applies the pinned 21 migrations as the distinct migrator role, and invokes the actual compiled first-admin bootstrap (not synthetic administrator grant inserts). A synthetic manager web credential is provisioned in that fixture only. PostgreSQL uses the `fixlevelup_dev` database name expected by the unchanged production entry point, but no connection to the host or preexisting `fixlevelup_dev` is possible. Next and Nest run production artifacts; the fixture TLS proxy forwards same-origin requests unchanged, and only the disposable browser context accepts its self-signed loopback certificate. The test asserts Secure/HttpOnly/SameSite=Strict cookies, an actual admin publication, exact PostgreSQL binding to the verified actor and one matching receipt/audit/outbox pair, then a valid-CSRF direct manager publication POST returning 403 and no extra writes. The proof observer returns only counts/booleans. The ephemeral key and certificate are generated under the image's ignored node_modules cache, not in the repository. Both owned containers are verified by ID, label and network mode, then stopped and removed; no image or volume is pruned.

The intercepted suite's unknown requests and the live suite's unknown proxy routes fail; there is also no non-loopback network interface. Existing technical tests retain their own preexisting synthetic screenshot behavior; direct reports from the new suites contain neither screenshots nor body/credential dumps. This is not a live deployment, release, accessibility audit or production TLS test.
