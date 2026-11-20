# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Rebuild the accepted source-only prerequisite recipe from the same context.
FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    openssl=3.0.22-1~deb12u2 libssl3=3.0.22-1~deb12u2 ca-certificates=20250419~deb12u2
WORKDIR /workspace
ENV CI=1 NEXT_TELEMETRY_DISABLED=1 COREPACK_ENABLE_AUTO_PIN=0 COREPACK_DEFAULT_TO_LATEST=0 COREPACK_HOME=/opt/fixlevelup-corepack
COPY . .
RUN node infra/linux-proof/source-check.mjs
RUN node --version && corepack pnpm --version
RUN corepack pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies
RUN corepack pnpm peers check && corepack pnpm run db:generate
CMD ["node", "infra/linux-integration/run.mjs"]
