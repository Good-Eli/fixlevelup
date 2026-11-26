# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Synthetic candidate: published 3.5.9 plus exact reviewed maintenance patches.
FROM node:24.22.3-alpine3.24@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS crypto
# Reproduce the independently retained P03-04 OpenSSL build, not the current wall clock.
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
RUN test "$SOURCE_DATE_EPOCH" = "1795305328" \
    && apk add --no-cache gcc=15.2.0-r5 binutils=2.45.1-r1 make=4.4.1-r4 musl-dev=1.2.6-r3 \
    linux-headers=7.0.0-r1 perl=5.42.3-r0 patch=2.8.1-r0
WORKDIR /build
COPY openssl-inputs.sha256 /build/inputs/openssl-inputs.sha256
RUN --network=none --mount=type=bind,source=openssl-3.5.9.tar.gz,target=/build/inputs/openssl-3.5.9.tar.gz,readonly \
    --mount=type=bind,source=f3acb0a3328046741479482c51cec815839e1b05.patch,target=/build/inputs/f3acb0a3328046741479482c51cec815839e1b05.patch,readonly \
    --mount=type=bind,source=c8f6d04f8e6d40b1bf83334e4a2ec9daf5943a3d.patch,target=/build/inputs/c8f6d04f8e6d40b1bf83334e4a2ec9daf5943a3d.patch,readonly \
    --mount=type=bind,source=9491b0d9cc7950af1f3dc89499bd5433b9cd4f43.patch,target=/build/inputs/9491b0d9cc7950af1f3dc89499bd5433b9cd4f43.patch,readonly \
    --mount=type=bind,source=468c287cf451a834b370b69ab321b8ffdfac23aa.patch,target=/build/inputs/468c287cf451a834b370b69ab321b8ffdfac23aa.patch,readonly \
    --mount=type=bind,source=1c65edebefa0dd11aa41cb1a31078ecd9c79d472.patch,target=/build/inputs/1c65edebefa0dd11aa41cb1a31078ecd9c79d472.patch,readonly \
    cd /build/inputs && sha256sum -c openssl-inputs.sha256 \
    && tar -xzf openssl-3.5.9.tar.gz -C /build \
    && cd /build/openssl-3.5.9 \
    && for sha in c8f6d04f8e6d40b1bf83334e4a2ec9daf5943a3d 9491b0d9cc7950af1f3dc89499bd5433b9cd4f43 f3acb0a3328046741479482c51cec815839e1b05 468c287cf451a834b370b69ab321b8ffdfac23aa 1c65edebefa0dd11aa41cb1a31078ecd9c79d472; do \
         patch --batch --forward --fuzz=0 -p1 < "/build/inputs/$sha.patch" || exit 1; \
       done
WORKDIR /build/openssl-3.5.9
RUN --network=none ./Configure linux-x86_64 shared --prefix=/usr --openssldir=/etc/ssl --libdir=lib \
    && make -j8 build_sw \
    && make -j4 test TESTS='test_x509_check_cert_pkey test_cmsapi' \
    && sha256sum libcrypto.so.3 && ls -l libcrypto.so.3

FROM clamav/clamav:1.4.7_base@sha256:21622d96b8a7080af7974d99ca60a9e061eff5ff831ed6986d00953fc19ff67f AS scanner-source
RUN --network=none --mount=type=bind,source=libxml2-2.13.9-r3.apk,target=/run/libxml2-2.13.9-r3.apk,readonly \
    echo '8b37229c4761cf0eef5089045283526ef43bf335073050515010d34a313186ed  /run/libxml2-2.13.9-r3.apk' | sha256sum -c - \
    && apk verify /run/libxml2-2.13.9-r3.apk \
    && apk --repositories-file /dev/null add --no-network --no-cache /run/libxml2-2.13.9-r3.apk \
    && apk --repositories-file /dev/null info -v | grep -Fx libxml2-2.13.9-r3

# Never copy the original libcrypto; it is absent even from lower final layers.
FROM scratch
COPY --from=scanner-source /usr/bin/clamscan /usr/bin/sigtool /usr/bin/
COPY --from=scanner-source /lib/ld-musl-x86_64.so.1 /lib/libc.musl-x86_64.so.1 /lib/
COPY --from=scanner-source /usr/lib/libgcc_s.so.1 /usr/lib/libstdc++.so.6* /usr/lib/
COPY --from=scanner-source /usr/lib/libclamav.so* /usr/lib/libclammspack.so* /usr/lib/libclamunrar.so* /usr/lib/libclamunrar_iface.so* /usr/lib/
COPY --from=scanner-source /usr/lib/libbz2.so.1* /usr/lib/libjson-c.so.5* /usr/lib/liblzma.so.5* /usr/lib/libpcre2-8.so.0* /usr/lib/libxml2.so.2* /usr/lib/libz.so.1* /usr/lib/
COPY --from=crypto /build/openssl-3.5.9/libcrypto.so.3 /usr/lib/libcrypto.so.3
COPY --from=crypto /build/openssl-3.5.9/LICENSE.txt /usr/share/licenses/OpenSSL-3.5.9-LICENSE.txt
COPY --from=crypto /build/inputs/openssl-inputs.sha256 /usr/share/licenses/OpenSSL-3.5.9-fixlevelup-inputs.sha256
LABEL org.opencontainers.image.description="Synthetic ClamAV with OpenSSL 3.5.9 maintenance backports, exact source and patch hashes in image"
ENV LANG=C TZ=Etc/UTC
USER 65532:65532
ENTRYPOINT ["/usr/bin/clamscan"]
