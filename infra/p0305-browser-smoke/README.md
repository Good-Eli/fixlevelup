# P03-05 browser proof (synthetic only)

Two independent proofs use the matching Chromium/Firefox/WebKit installation from the existing Node 24.22.3 + Playwright 1.65.1 proof image. The default suite includes a new production-Next/intercepted CRM suite in all six existing desktop/mobile viewport projects and retains technical/P02/P03-02 tests as separate UI proofs. The isolated live config registers one Chromium case only when the live runner sets its fixture variables. No trace, video, screenshot or scope URL/body logging is enabled by the new suites. No production data, services, CA trust or DSH server is touched.

From the repo root and after sources are frozen, choose a fresh image tag:

```powershell
$image = "fixlevelup-p0305-browser:proof-" + [guid]::NewGuid().ToString('N').Substring(0,12)
pwsh -File infra/p0305-browser-smoke/build-live.ps1 -Image $image
$engine = 'npipe:////./pipe/dockerDesktopLinuxEngine'
docker --host $engine run --name ("fixlevelup-p0305-ui-" + [guid]::NewGuid().ToString('N')) --pull never --network none --shm-size 1g --memory 4g --cpus 2 $image
pwsh -File infra/p0305-browser-smoke/run-live.ps1 -Image $image
```

The build requires the exact cached proof image and store (`infra/browser-proof`), and the PostgreSQL 18.7 digest already used by the repository. It copies source only (root Docker exclusions), uses the existing frozen external dependency graph with dependency hooks disabled. Only the frozen install layer can fetch registry metadata (the pinned cached image does not contain a complete metadata mirror); the compile layer has no network. Browser executables are already in the pinned base, and the run never downloads them. Runtime receives no source checkout, sockets, dev environment files, host bind mounts or forwarded ports.

Live: a unique PostgreSQL container runs with `--network none` and its own uniquely named volume. The browser/Next/Nest container shares only its loopback namespace. The database fixture proves generated cluster identity and absence of prior roles/schema before using its own one-time credentials, applies 18 migrations as the distinct migrator role, and invokes the actual compiled first-admin bootstrap (not synthetic administrator grant inserts). A synthetic manager web credential is provisioned in that fixture only. PostgreSQL uses the `fixlevelup_dev` database name expected by the unchanged production entry point, but no connection to the host or preexisting `fixlevelup_dev` is possible. Next and Nest run production artifacts; the fixture TLS proxy forwards same-origin requests unchanged, and only the disposable browser context accepts its self-signed loopback certificate. The test asserts Secure/HttpOnly/SameSite=Strict cookies, an actual admin publication, exact PostgreSQL binding to the verified actor and one matching receipt/audit/outbox pair, then a valid-CSRF direct manager publication POST returning 403 and no extra writes. The proof observer returns only counts/booleans. The ephemeral key and certificate are generated under the image's ignored node_modules cache, not in the repository. The dedicated containers and fresh named volume are retained; the runner only stops its PostgreSQL container. Nothing on preexisting containers/databases is reset or dropped.

The intercepted suite's unknown requests and the live suite's unknown proxy routes fail; there is also no non-loopback network interface. Existing technical tests retain their own preexisting synthetic screenshot behavior; direct reports from the new suites contain neither screenshots nor body/credential dumps. This is not a live deployment, release, accessibility audit or production TLS test.
