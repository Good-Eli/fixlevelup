# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS node24
FROM mcr.microsoft.com/playwright:v1.65.1-noble@sha256:1507cbfc550a63a6b7396791ca4f00df17beb56342d2447b3f106c306f525579
# Upstream browser image has Node26. Preserve its matching browsers/system libs,
# but use the exact selected Node24 distribution for builds/server/test runner.
COPY --from=node24 /usr/local/ /usr/local/
ENV PATH=/usr/local/bin:$PATH CI=1 NEXT_TELEMETRY_DISABLED=1 COREPACK_ENABLE_AUTO_PIN=0 COREPACK_DEFAULT_TO_LATEST=0 COREPACK_HOME=/opt/fixlevelup-corepack PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
WORKDIR /workspace
COPY . .
RUN node infra/linux-proof/source-check.mjs
RUN node --version && corepack pnpm --version
RUN corepack pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies
RUN corepack pnpm peers check && corepack pnpm run db:generate
CMD ["node", "infra/browser-proof/run.mjs"]
