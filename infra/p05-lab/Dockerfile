# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
# P05 lab runner image (task-1): source-only, no host credentials, no Docker
# socket, no host network. The runner shares only the PostgreSQL container's
# private network namespace (`--network container:<pg>`), where PostgreSQL
# listens on loopback 127.0.0.1:55432 — the fixed endpoint the reviewed test
# contracts expect. Nothing is published to the host, so the working dev
# PostgreSQL on host port 55432 is never reachable from here.
#
# The build context is NOT the live working tree: `infra/p05-lab/lab.mjs`
# exports a frozen tree (git archive of the gateway commit plus only the
# reviewed P05-02 overlay files) into an ignored staging directory and builds
# from there, so unfinished 024/bridge edits can never enter the gateway image.
FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54

LABEL dsh.owner="pg-lab" \
      dsh.task="task-1" \
      dsh.purpose="p05-lab-runner" \
      dsh.ephemeral="true"

# openssl CLI is required by the reviewed HTTPS loopback smoke in
# `apps/api/tests/form-session-http.test.ts` (self-signed cert generation);
# the slim base image ships libssl but not the binary.
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends openssl=3.0.22-1~deb12u2 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
ENV CI=1 \
    NEXT_TELEMETRY_DISABLED=1 \
    COREPACK_ENABLE_AUTO_PIN=0 \
    COREPACK_DEFAULT_TO_LATEST=0 \
    COREPACK_HOME=/opt/fixlevelup-corepack

# The frozen context is source-only (.dockerignore excludes .git, node_modules,
# dist, test-results, .env*, backups, dumps). No local credential is copied.
COPY . .

# Frozen install; lifecycle scripts are skipped and the only generated
# artifacts are produced explicitly below from reviewed sources.
RUN corepack pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies
RUN corepack pnpm run db:generate \
 && corepack pnpm run p03:contracts \
 && corepack pnpm --filter @fixlevelup/api run build

# Kept alive by `lab.mjs`; all commands are executed with `docker exec`.
CMD ["sleep", "infinity"]
