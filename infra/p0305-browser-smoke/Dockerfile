# The local base is the already built, pinned matching proof image (see
# infra/browser-proof). `build-live.ps1` verifies the exact base ID; a different
# base is only accepted as an explicitly declared and verified parameter.
ARG PROOF_BASE=fixlevelup-browser-proof:p0111c
FROM ${PROOF_BASE}
WORKDIR /p0305
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml .npmrc tsconfig.json eslint.config.mjs vitest.config.mts ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
COPY apps/miniapp/package.json apps/miniapp/package.json
COPY packages/browser-tooling/package.json packages/browser-tooling/package.json
COPY packages/database-tooling/package.json packages/database-tooling/package.json
COPY packages/storage-tooling/package.json packages/storage-tooling/package.json
COPY packages/tooling/package.json packages/tooling/package.json
COPY packages/p03-contracts/package.json packages/p03-contracts/package.json
RUN --network=default corepack pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies --store-dir /workspace/node_modules/.cache/pnpm-store
WORKDIR /source-check
COPY apps/ apps/
COPY packages/ packages/
COPY prisma/ prisma/
COPY infra/linux-proof/source-check.mjs infra/linux-proof/source-check.mjs
COPY infra/p0305-browser-smoke/ infra/p0305-browser-smoke/
COPY infra/p0404-browser-smoke/ infra/p0404-browser-smoke/
COPY pnpm-workspace.yaml .
RUN --network=none node infra/linux-proof/source-check.mjs && cp -a apps packages prisma infra /p0305/
WORKDIR /p0305
# The frozen install suppresses lifecycle scripts, so Prisma's pinned engine is
# fetched here (the only step with network) rather than inside the workspace
# build. The workspace build below stays offline.
RUN corepack pnpm run db:generate
RUN --network=none corepack pnpm run build
CMD ["corepack", "pnpm", "--filter", "@fixlevelup/browser-tooling", "run", "test"]
