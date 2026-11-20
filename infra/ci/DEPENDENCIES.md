# Dependency and license gate

[dependencies.mjs](<dependencies.mjs>) is an executable CI gate, not a dependency installer. It intentionally uses the exact repository-pinned **Node 24.22.3** and **pnpm 12.21.0** already present in the lockfile. pnpm 12's built-in `licenses list --json` is the lightest available inventory source and requires no new runtime or CI dependency.

## Contract

```text
node infra/ci/dependencies.mjs --check --output artifacts/dependencies.json
```

CI creates `artifacts/` before invoking the command. `--output` creates a new file exclusively and refuses to overwrite an existing file; without it the same JSON is written to stdout. The command never reads dotenv files, never installs/updates/removes packages, never changes the lockfile, and never accepts advisory suppressions. It expects the workflow's preceding installation to use:

```text
corepack pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies
```

The command inventories every direct and transitive identity in the frozen workspace graph, including optional and platform-skipped identities and the pinned pnpm package-manager identity. Installed identities are checked against pnpm's own package manifest metadata. Platform-skipped identities are fetched one exact `name/version` at a time from the public npm registry; an unavailable or malformed response fails the gate. The lockfile is the completeness boundary. Output is redacted JSON containing package names, versions, direct/transitive flags, license expressions, source kind, technical review state, audit severity counts, and a lockfile SHA-256. It excludes paths, usernames, repository/homepage URLs, authors, environment values, and raw subprocess/registry diagnostics. If a malformed license string contains path-like data, only its SHA-256 is emitted.

Exit status is **0** only when all identities have complete metadata, every license expression is technically reviewed, the full pnpm audit has zero advisories at every severity (`info`, `low`, `moderate`, `high`, `critical`), and audit dependency counts equal the lockfile inventory. Exit **1** means a dependency, metadata, license-review, or vulnerability finding; exit **2** means invalid CLI arguments. `--check` is intentionally retained as an explicit CI/readability mode even though enforcement is never bypassed when omitted.

## Review policy and obligations

The allowlist is a technical inventory classification, not legal or production approval. MIT, ISC, Apache-2.0, BSD variants, 0BSD, BlueOak-1.0.0, and Unlicense are marked `technical-reviewed-existing-baseline`. Existing baseline expressions that require further distribution/legal review are listed in `licenseInventory.requiresLegalReview` and only pass when the exact package/version is listed in the scoped technical table:

- MPL-2.0 (`lightningcss`): retain notices and disclose source for modified MPL-covered files on distribution.
- EPL-2.0 (`elkjs`): retain notices and satisfy source/notice terms for distributed modifications.
- CC-BY-4.0 (`caniuse-lite`): retain attribution and indicate changes for covered data/content.
- LGPL-3.0-or-later (`@img/sharp-libvips-*`): retain notices, corresponding source, and relinking rights where applicable.
- Combined Apache/LGPL/MIT expressions (Sharp platform packages) and `MIT and ISC` (`@visx/vendor`): retain all applicable notices and satisfy the corresponding source/relinking or attribution terms where applicable.

Every such entry carries `technical-reviewed-existing-baseline`, an explicit `obligations` field, and `reviewNote: Technical inventory only; this is not legal or production approval.` Any unknown, free-form, newly introduced, or unlisted expression remains unreviewed and fails closed. Distribution obligations must be revisited before shipping artifacts or making a production/legal approval.
