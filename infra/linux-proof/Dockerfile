# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS source
# Owner-approved Linux test prerequisites; no host package changes.
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    openssl=3.0.22-1~deb12u2 libssl3=3.0.22-1~deb12u2 ca-certificates=20250419~deb12u2
WORKDIR /workspace
ENV CI=1 NEXT_TELEMETRY_DISABLED=1 COREPACK_ENABLE_AUTO_PIN=0 COREPACK_DEFAULT_TO_LATEST=0 COREPACK_HOME=/opt/fixlevelup-corepack
COPY . .
# The source context must not contain any actual local credentials/artifacts.
RUN node infra/linux-proof/source-check.mjs
RUN corepack --version && node --version && corepack pnpm --version
# Dependency lifecycle hooks remain disabled; no npm/npx latest or package updates.
RUN corepack pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies
RUN corepack pnpm peers check
# Explicit reviewed command, NOT engines postinstall. Cache the exact Prisma
# 7.10.1 engine while build has network; runtime generation must work offline.
RUN corepack pnpm run db:generate

FROM source AS proof
# Runtime proof is invoked with Docker --network none. Its only host bind mount
# is the empty runner-temp directory dedicated to redacted JSON evidence output;
# no host source, credentials, Docker socket, service networks or ports are exposed.
CMD ["node", "infra/linux-proof/run.mjs"]
