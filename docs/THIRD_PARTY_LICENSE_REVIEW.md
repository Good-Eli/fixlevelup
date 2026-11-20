# Third-party license review — P01-12B.1

**Review date:** 20.11.2026  
**Repository HEAD reviewed:** `b42e0efa23d7c67b17271cf3a4f489660a95ebe5`  
**Lockfile:** `pnpm-lock.yaml`, Git blob SHA `cf391e5a44f72950b844c75cfca46bcd1991b3a2` (Git object SHA-1, not a file SHA-256).  
**Scope:** the 29 exact package/version identities in `infra/ci/dependencies.mjs` → `TECHNICAL_EXCEPTIONS`.

## Executive result

- All **29/29** exact package/version identities listed by the technical exception table are present in the frozen lockfile and snapshot graph.
- All 29 are reached as **transitive** dependencies; none is a direct dependency declared by a workspace importer.
- The source graph distinguishes development-only branches from packages reachable through the Web runtime dependency tree. It is incorrect to classify the entire list as dev-only.
- Exact upstream release manifests/license files were read for the principal source packages. Some platform-specific package variants are verified through the repository's published package metadata/lockfile relationship rather than an individually downloaded npm tarball. Those entries are marked accordingly.
- The exact `@visx/vendor@4.0.0-alpha.0` tarball and its embedded vendored dependency license files were not independently inspected. That entry remains partial.
- No production Docker image, standalone deployment bundle or distributable archive exists in the inspected P01 tree. Therefore actual distribution contents and SBOM are **not yet determinable**.
- CI run [44675339571](https://github.com/Good-Eli/fixlevelup/actions/runs/44675339571) on the reviewed HEAD completed successfully, including the dependency/license/lockfile/secret job. The CI gate verifies metadata/inventory, vulnerability audit and secret scanning; it does **not** independently inspect every upstream archive's complete LICENSE/NOTICE corpus or the eventual production artifact.

**Conclusion:** the technical exception table is traceable and its license expressions are substantially corroborated by exact release-source metadata. This is not a legal opinion, final distribution review or release approval. Keep F06 **PARTIAL** until artifact composition, notices/source obligations and distribution scenario have been checked by the responsible owner/legal reviewer.

## Method

1. Read `infra/ci/DEPENDENCIES.md`, `infra/ci/dependencies.mjs`, root/workspace `package.json` and `pnpm-lock.yaml` at the reviewed HEAD.
2. Extracted all exact package/version pairs from `TECHNICAL_EXCEPTIONS` (29 entries) and confirmed matching package identities in the lockfile/snapshot graph.
3. Traced snapshot dependency paths back to workspace importers. The full lock graph includes platform-specific optional packages; their presence in the lockfile does not mean every platform variant is installed in every environment.
4. Compared exact-tag upstream package manifests and license files where available. For registry/platform packages, metadata agreement is recorded separately from complete inspection of the published archive's files.
5. Reviewed the upstream `sharp-libvips` third-party notice inventory because its LGPL package expression is not the whole story for the native libraries it bundles.
6. Checked current remote CI run metadata/jobs. No CI ZIP artifact was downloaded and independently unpacked during this review. No package install/lifecycle script was executed here, and no repository dependency or lockfile was changed.

### Evidence boundaries

- GitHub source files and tags are authoritative evidence of the upstream repository contents at those refs, but are not byte-for-byte proof that every published npm tarball contains the same set of files.
- `pnpm-lock.yaml` confirms exact resolved versions/integrity and dependency relationships, not what a future production packager will retain.
- `infra/ci/dependencies.mjs` reads installed package metadata and registry metadata for platform-skipped packages. It does not itself inspect every package's full license text or build a final application SBOM.
- The GitHub Actions successful security job is a technical gate, not legal advice.

## Exact inventory

All entries below are transitive in the reviewed workspace graph. Paths are abbreviated to the first relevant importer route; other importer routes may also reach the same package. `Optional` means pnpm records the platform dependency as optional; actual installation depends on OS/CPU/libc and package manager selection.

| # | Exact package identity | License expression | Lockfile route / role | Technical evidence | Review status |
|---:|---|---|---|---|---|
| 1 | `lightningcss@1.33.0` | `MPL-2.0` | root `vite → lightningcss`; also `apps/miniapp` and Vitest | Exact upstream tag `v1.33.0`, root `package.json`, `LICENSE` and `selectors/LICENSE`; both license files are MPL 2.0. | PARTIALLY VERIFIED — base source verified; platform variants rely on family metadata/lock graph |
| 2 | `lightningcss-android-arm64@1.33.0` | `MPL-2.0` | Optional child of `lightningcss` | Exact lock identity; package metadata in platform family; platform tarball not separately unpacked. | PARTIALLY VERIFIED |
| 3 | `lightningcss-darwin-arm64@1.33.0` | `MPL-2.0` | Optional child of `lightningcss` | Exact lock identity; package metadata in platform family; platform tarball not separately unpacked. | PARTIALLY VERIFIED |
| 4 | `lightningcss-darwin-x64@1.33.0` | `MPL-2.0` | Optional child of `lightningcss` | Exact lock identity; package metadata in platform family; platform tarball not separately unpacked. | PARTIALLY VERIFIED |
| 5 | `lightningcss-freebsd-x64@1.33.0` | `MPL-2.0` | Optional child of `lightningcss` | Exact lock identity; package metadata in platform family; platform tarball not separately unpacked. | PARTIALLY VERIFIED |
| 6 | `lightningcss-linux-arm-gnueabihf@1.33.0` | `MPL-2.0` | Optional child of `lightningcss` | Exact lock identity; package metadata in platform family; platform tarball not separately unpacked. | PARTIALLY VERIFIED |
| 7 | `lightningcss-linux-arm64-gnu@1.33.0` | `MPL-2.0` | Optional child of `lightningcss` | Exact lock identity; package metadata in platform family; platform tarball not separately unpacked. | PARTIALLY VERIFIED |
| 8 | `lightningcss-linux-arm64-musl@1.33.0` | `MPL-2.0` | Optional child of `lightningcss` | Exact lock identity; package metadata in platform family; platform tarball not separately unpacked. | PARTIALLY VERIFIED |
| 9 | `lightningcss-linux-x64-gnu@1.33.0` | `MPL-2.0` | Optional child of `lightningcss` | Exact lock identity; package metadata in platform family; platform tarball not separately unpacked. | PARTIALLY VERIFIED |
| 10 | `lightningcss-linux-x64-musl@1.33.0` | `MPL-2.0` | Optional child of `lightningcss` | Exact lock identity; package metadata in platform family; platform tarball not separately unpacked. | PARTIALLY VERIFIED |
| 11 | `lightningcss-win32-arm64-msvc@1.33.0` | `MPL-2.0` | Optional child of `lightningcss` | Exact lock identity; package metadata in platform family; platform tarball not separately unpacked. | PARTIALLY VERIFIED |
| 12 | `lightningcss-win32-x64-msvc@1.33.0` | `MPL-2.0` | Optional child of `lightningcss` | Exact lock identity; package metadata in platform family; platform tarball not separately unpacked. | PARTIALLY VERIFIED |
| 13 | `elkjs@0.11.1` | `EPL-2.0` | `packages/database-tooling → prisma → @prisma/studio-core → elkjs` | Exact upstream tag `0.11.1`; `package.json` declares EPL-2.0 and `LICENSE.md` contains Eclipse Public License 2.0. | TECHNICALLY VERIFIED — package identity and license text corroborated |
| 14 | `caniuse-lite@1.0.30001826` | `CC-BY-4.0` | `apps/web → next → caniuse-lite` | Exact upstream tag/package version manifest declares CC-BY-4.0; exact source tree contains `LICENSE`. | TECHNICALLY VERIFIED — package identity/expression corroborated; release notices still need delivery review |
| 15 | `@visx/vendor@4.0.0-alpha.0` | `MIT and ISC` | `packages/database-tooling → prisma → @prisma/studio-core → @visx/curve → @visx/vendor` | Exact lock/registry identity. Upstream visx vendor build documentation says vendored subpackages carry their original LICENSE files; current upstream manifest declares MIT and ISC. Exact alpha.0 tarball and its embedded license set not unpacked. | PARTIALLY VERIFIED — exact published archive inspection remains open |
| 16 | `@img/sharp-win32-x64@0.35.5` | `Apache-2.0 AND LGPL-3.0-or-later` | `apps/web → next → sharp → optional platform package` | Exact Sharp release tag `v0.35.5`, corresponding platform `package.json` declares the composite expression. | PARTIALLY VERIFIED — package metadata corroborated; archive notices and native payload require release review |
| 17 | `@img/sharp-win32-arm64@0.35.5` | `Apache-2.0 AND LGPL-3.0-or-later` | `apps/web → next → sharp → optional platform package` | Exact Sharp release tag `v0.35.5`, corresponding platform manifest declares the composite expression. | PARTIALLY VERIFIED |
| 18 | `@img/sharp-win32-ia32@0.35.5` | `Apache-2.0 AND LGPL-3.0-or-later` | `apps/web → next → sharp → optional platform package` | Exact Sharp release tag `v0.35.5`, corresponding platform manifest declares the composite expression. | PARTIALLY VERIFIED |
| 19 | `@img/sharp-wasm32@0.35.5` | `Apache-2.0 AND LGPL-3.0-or-later AND MIT` | `apps/web → next → sharp → sharp-freebsd-wasm32 → optional wasm32` | Exact Sharp release tag `v0.35.5`, `npm/wasm32/package.json` declares the three-part expression. | PARTIALLY VERIFIED |
| 20 | `@img/sharp-libvips-darwin-arm64@1.3.4` | `LGPL-3.0-or-later` | `apps/web → next → sharp → optional libvips platform package` | Exact `sharp-libvips` tag `v1.3.4`, matching `npm/darwin-arm64/package.json` declares the expression. Root third-party notice inventory reviewed. | PARTIALLY VERIFIED — bundled notices/components need artifact-level review |
| 21 | `@img/sharp-libvips-darwin-x64@1.3.4` | `LGPL-3.0-or-later` | `apps/web → next → sharp → optional libvips platform package` | Exact tag `v1.3.4`, matching `npm/darwin-x64/package.json`; common third-party notices reviewed. | PARTIALLY VERIFIED |
| 22 | `@img/sharp-libvips-linux-arm@1.3.4` | `LGPL-3.0-or-later` | `apps/web → next → sharp → optional libvips platform package` | Exact tag `v1.3.4`, matching `npm/linux-arm/package.json`; common third-party notices reviewed. | PARTIALLY VERIFIED |
| 23 | `@img/sharp-libvips-linux-arm64@1.3.4` | `LGPL-3.0-or-later` | `apps/web → next → sharp → optional libvips platform package` | Exact tag `v1.3.4`, matching `npm/linux-arm64/package.json`; common third-party notices reviewed. | PARTIALLY VERIFIED |
| 24 | `@img/sharp-libvips-linux-ppc64@1.3.4` | `LGPL-3.0-or-later` | `apps/web → next → sharp → optional libvips platform package` | Exact tag `v1.3.4`, matching `npm/linux-ppc64/package.json`; common third-party notices reviewed. | PARTIALLY VERIFIED |
| 25 | `@img/sharp-libvips-linux-riscv64@1.3.4` | `LGPL-3.0-or-later` | `apps/web → next → sharp → optional libvips platform package` | Exact tag `v1.3.4`, matching `npm/linux-riscv64/package.json`; common third-party notices reviewed. | PARTIALLY VERIFIED |
| 26 | `@img/sharp-libvips-linux-s390x@1.3.4` | `LGPL-3.0-or-later` | `apps/web → next → sharp → optional libvips platform package` | Exact tag `v1.3.4`, matching `npm/linux-s390x/package.json`; common third-party notices reviewed. | PARTIALLY VERIFIED |
| 27 | `@img/sharp-libvips-linux-x64@1.3.4` | `LGPL-3.0-or-later` | `apps/web → next → sharp → optional libvips platform package` | Exact tag `v1.3.4`, matching `npm/linux-x64/package.json`; common third-party notices reviewed. | PARTIALLY VERIFIED |
| 28 | `@img/sharp-libvips-linuxmusl-arm64@1.3.4` | `LGPL-3.0-or-later` | `apps/web → next → sharp → optional libvips platform package` | Exact tag `v1.3.4`, matching `npm/linuxmusl-arm64/package.json`; common third-party notices reviewed. | PARTIALLY VERIFIED |
| 29 | `@img/sharp-libvips-linuxmusl-x64@1.3.4` | `LGPL-3.0-or-later` | `apps/web → next → sharp → optional libvips platform package` | Exact tag `v1.3.4`, matching `npm/linuxmusl-x64/package.json`; common third-party notices reviewed. | PARTIALLY VERIFIED |

## License-specific observations

### MPL-2.0 — Lightning CSS

The exact `lightningcss@1.33.0` upstream release contains MPL 2.0 text in both root `LICENSE` and `selectors/LICENSE`. MPL-2.0 is file-level copyleft: when distributing covered source files or executable forms, the specific source disclosure/notice conditions apply to the covered software and its modifications; it does not automatically relicense unrelated files in a larger work. Preserve the license and notices, and review whether any covered files are modified or shipped in source/binary form. The 11 platform package variants are recorded by the lockfile and CI metadata; individual package archives were not unpacked in this review.

### EPL-2.0 — elkjs

The exact `elkjs@0.11.1` upstream release declares EPL-2.0 and ships `LICENSE.md` with EPL 2.0 text. The exact dependency path is within the Prisma Studio graph of the dev-only database tooling package; Studio is not started by the project. If a future distribution includes the program, review EPL §3 requirements, including making the corresponding source available and informing recipients how to obtain it. Do not infer a SaaS/network obligation from the fact that a package exists in the dev lockfile.

### CC-BY-4.0 — caniuse-lite

The exact `caniuse-lite@1.0.30001826` package declares CC-BY-4.0 and contains a `LICENSE` file. It is reached through `apps/web → next`; unlike the Prisma Studio packages, it is not confined to the dev-only database tooling graph. Preserve appropriate attribution and license reference, and indicate changes where applicable if this dataset is distributed. Confirm the final Web deployment package's actual contents before release.

### MIT and ISC — @visx/vendor

The exact package identity is pinned in the lockfile and technical inventory. The upstream visx vendor build process documents copying the original vendored package LICENSE files into vendor output. The exact alpha.0 npm tarball was not downloaded/unpacked here, so the exact set of included third-party licenses remains unverified. Preserve both MIT and ISC notices and the upstream per-vendored-package license files in any artifact that includes this package. The dependency path is under Prisma Studio within `packages/database-tooling`; that package README identifies its React/Visx dependencies as Prisma Studio peer providers and states that Studio is not launched.

### Sharp / libvips — combined expressions and native components

The exact Sharp 0.35.5 platform package manifests in the `lovell/sharp` release declare the composite expressions recorded above. The exact `lovell/sharp-libvips` 1.3.4 release package manifests for the ten locked platform variants declare LGPL-3.0-or-later. Its upstream `THIRD-PARTY-NOTICES.md` lists additional native components and licenses including BSD, MIT, MPL 1.1, LGPLv3 and the Alliance for Open Media Patent License 1.0 (AOM patent license), among others. This native notice inventory is a release concern: the top-level SPDX expression alone is not the full inventory of bundled native components. Keep the notices and exact source/offer/rel linking obligations applicable to each component under review. Confirm the actual OS/CPU/libc-specific payload copied into each target image.

## Distribution scenarios

| Scenario | What can be said now | Required gate before distribution |
|---|---|---|
| Hosted SaaS on the operator's server | No customer-side executable is necessarily transferred by hosting alone, but server-side software and any source/object transfers to contractors or customers require separate analysis. `caniuse-lite` and Sharp are on the Web dependency path; Lightning CSS is in Vite/tooling graph; elkjs/visx are in Prisma Studio tooling graph. | Produce deployment SBOM and actual image/file inventory; verify whether dev dependencies and Prisma Studio are excluded; check local law, contracts, hosting/outsourcing, notices and license applicability with counsel. |
| Docker image delivered to a customer | No production Dockerfile/image at this P01 HEAD was available for inspection. Contents cannot be inferred from lockfile alone. | Build final image for each target; scan layers and filesystem; create SBOM; confirm optional Sharp/libvips native package; attach required LICENSE/NOTICE/third-party notices and source/relinking arrangements where applicable. |
| Installable/binary package | No distributable application package exists in this P01 tree. | Inspect exact package contents, transitive native binaries, all notice files, modified files, source offer/relinking requirements, and delivery metadata. |
| Source archive / repository transfer | Current public repository exposes project source and lockfile; not all npm package source is necessarily copied into a repository archive. | Determine the precise source archive/dependency-vendoring model; include applicable license texts and notices; preserve MPL/EPL-covered source rights and bundled third-party notices. |
| Browser bundle | Web code is a Next.js target and the current source does not establish a final exported/static bundle. Next's server dependency graph includes `caniuse-lite` and optional `sharp`; CSS build tooling includes Lightning CSS. | Build actual Web artifact, inspect its output and external/server dependencies, generate artifact SBOM; decide whether any of these components or their generated outputs are distributed to browser clients. |

## Release gates

1. Generate an SBOM from the **actual** release image/package and every supported architecture/OS target; do not use lockfile inventory as a substitute.
2. Confirm whether `@prisma/studio-core`, `elkjs` and `@visx/vendor` are excluded from runtime artifacts. Keep Prisma Studio disabled unless explicitly needed.
3. Inspect the exact published `@visx/vendor@4.0.0-alpha.0` tarball and every embedded vendor `LICENSE` file.
4. Preserve and test inclusion of MPL, EPL, CC-BY, MIT, ISC, Apache and LGPL notices in each artifact where required. For Sharp/libvips, include the upstream third-party notice inventory and analyze AOM patent-license references separately.
5. For LGPL components, confirm the actual dynamic/static/linking model and applicable source/relinking/installation information from the exact artifact; do not assume a generic “LGPL allowed” answer.
6. Obtain a legal review for the actual intended distribution scenarios and jurisdiction before commercial delivery. This document is an engineering evidence record, not legal advice.

## Sources

Repository source at reviewed HEAD:
- [`infra/ci/DEPENDENCIES.md`](../infra/ci/DEPENDENCIES.md)
- [`infra/ci/dependencies.mjs`](../infra/ci/dependencies.mjs)
- [`pnpm-lock.yaml`](../pnpm-lock.yaml)
- [`apps/web/README.md`](../apps/web/README.md)
- [`packages/database-tooling/README.md`](../packages/database-tooling/README.md)

Exact upstream sources reviewed:
- [Lightning CSS v1.33.0](https://github.com/parcel-bundler/lightningcss/tree/v1.33.0) — [`LICENSE`](https://github.com/parcel-bundler/lightningcss/blob/v1.33.0/LICENSE), [`selectors/LICENSE`](https://github.com/parcel-bundler/lightningcss/blob/v1.33.0/selectors/LICENSE)
- [elkjs 0.11.1](https://github.com/kieler/elkjs/tree/0.11.1) — [`package.json`](https://github.com/kieler/elkjs/blob/0.11.1/package.json), [`LICENSE.md`](https://github.com/kieler/elkjs/blob/0.11.1/LICENSE.md)
- [caniuse-lite 1.0.30001826](https://github.com/browserslist/caniuse-lite/tree/1.0.30001826) — [`package.json`](https://github.com/browserslist/caniuse-lite/blob/1.0.30001826/package.json), [`LICENSE`](https://github.com/browserslist/caniuse-lite/blob/1.0.30001826/LICENSE)
- [visx upstream vendor implementation](https://github.com/airbnb/visx/tree/485c0359664ee8e612992defb16e1f035ed40b23/packages/visx-vendor) — implementation reference only, not byte-for-byte proof of the alpha.0 package archive
- [Sharp v0.35.5](https://github.com/lovell/sharp/tree/v0.35.5) — platform manifests under `npm/*/package.json`
- [sharp-libvips v1.3.4](https://github.com/lovell/sharp-libvips/tree/v1.3.4) — platform manifests under `npm/*/package.json`, [`THIRD-PARTY-NOTICES.md`](https://github.com/lovell/sharp-libvips/blob/v1.3.4/THIRD-PARTY-NOTICES.md)
- [MPL 2.0 FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/)
- [Eclipse Public License 2.0](https://www.eclipse.org/legal/epl-2.0/)
- [Creative Commons Attribution 4.0 legal code](https://creativecommons.org/licenses/by/4.0/legalcode)

## Final status

**F06: PARTIAL.** README and evidence review can be added to the repository, and exact dependency identities and key upstream license declarations are traceable. Do not close F06 until the `@visx/vendor` archive review and artifact-level SBOM/notice review are completed and the intended commercial distribution model is legally reviewed. No dependencies, versions, lockfile, CI policy or allowlist were changed by this review.
