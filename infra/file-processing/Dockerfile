# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM node:24.22.3-alpine3.24@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS build
WORKDIR /workspace
ENV CI=1 COREPACK_ENABLE_AUTO_PIN=0 COREPACK_DEFAULT_TO_LATEST=0 COREPACK_HOME=/opt/corepack SHARP_IGNORE_GLOBAL_LIBVIPS=1
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/api/package.json apps/api/package.json
COPY apps/miniapp/package.json apps/miniapp/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/browser-tooling/package.json packages/browser-tooling/package.json
COPY packages/database-tooling/package.json packages/database-tooling/package.json
COPY packages/p03-contracts/package.json packages/p03-contracts/package.json
COPY packages/storage-tooling/package.json packages/storage-tooling/package.json
COPY packages/tooling/package.json packages/tooling/package.json
RUN test "$(node -v)" = v24.22.3 && test "$(corepack pnpm -v)" = 12.21.0 \
    && corepack pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies
COPY apps/api/src/files/file-processing/decoder-entry.ts apps/api/src/files/file-processing/protocol.ts apps/api/src/files/file-processing/image-structure.ts ./apps/api/src/files/file-processing/
RUN --network=none node node_modules/typescript/bin/tsc --ignoreConfig --module nodenext --target es2024 \
    --strict --noUncheckedIndexedAccess --exactOptionalPropertyTypes --skipLibCheck --types node \
    --outDir /worker apps/api/src/files/file-processing/decoder-entry.ts \
    && printf '{"private":true,"type":"module"}\n' > /worker/package.json

FROM scratch
WORKDIR /worker
ENV SHARP_IGNORE_GLOBAL_LIBVIPS=1
COPY --from=build /lib/ld-musl-x86_64.so.1 /lib/libc.musl-x86_64.so.1 /lib/
COPY --from=build /usr/lib/libstdc++.so.6 /usr/lib/libstdc++.so.6.0.34 /usr/lib/libgcc_s.so.1 /usr/lib/
COPY --from=build /usr/local/bin/node /usr/local/bin/node
COPY --from=build /worker/ /worker/
COPY --from=build /workspace/node_modules/.pnpm/sharp@0.35.5_@types+node@24.19.2/node_modules/sharp/ node_modules/sharp/
COPY --from=build /workspace/node_modules/.pnpm/@img+colour@1.1.0/node_modules/@img/colour/ node_modules/@img/colour/
COPY --from=build /workspace/node_modules/.pnpm/@img+sharp-linuxmusl-x64@0.35.5/node_modules/@img/sharp-linuxmusl-x64/ node_modules/@img/sharp-linuxmusl-x64/
COPY --from=build /workspace/node_modules/.pnpm/@img+sharp-libvips-linuxmusl-x64@1.3.4/node_modules/@img/sharp-libvips-linuxmusl-x64/ node_modules/@img/sharp-libvips-linuxmusl-x64/
COPY --from=build /workspace/node_modules/.pnpm/detect-libc@2.1.2/node_modules/detect-libc/ node_modules/detect-libc/
COPY --from=build /workspace/node_modules/.pnpm/semver@7.8.6/node_modules/semver/ node_modules/semver/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/node", "/worker/decoder-entry.js"]
