# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Technical remediation candidate for CVE-2026-86144 only. Not a security approval.
FROM clamav/clamav:1.4.7_base@sha256:21622d96b8a7080af7974d99ca60a9e061eff5ff831ed6986d00953fc19ff67f AS patched
RUN --network=none --mount=type=bind,source=libxml2-2.13.9-r3.apk,target=/run/libxml2-2.13.9-r3.apk,readonly \
    echo '8b37229c4761cf0eef5089045283526ef43bf335073050515010d34a313186ed  /run/libxml2-2.13.9-r3.apk' | sha256sum -c - \
    && apk verify /run/libxml2-2.13.9-r3.apk \
    && apk --repositories-file /dev/null add --no-network --no-cache /run/libxml2-2.13.9-r3.apk \
    && apk --repositories-file /dev/null info -v | grep -Fx libxml2-2.13.9-r3 \
    && /usr/bin/clamscan --version
USER 65532:65532
HEALTHCHECK NONE
ENTRYPOINT ["/usr/bin/clamscan"]

# Scan-only sandbox. No BusyBox, apk, shell, FreshClam, curl or TLS library.
FROM scratch AS scan
COPY --from=patched /usr/bin/clamscan /usr/bin/sigtool /usr/bin/
COPY --from=patched /lib/ld-musl-x86_64.so.1 /lib/libc.musl-x86_64.so.1 /lib/
COPY --from=patched /usr/lib/libcrypto.so.3 /usr/lib/libgcc_s.so.1 /usr/lib/libstdc++.so.6* /usr/lib/
COPY --from=patched /usr/lib/libclamav.so* /usr/lib/libclammspack.so* /usr/lib/libclamunrar.so* /usr/lib/libclamunrar_iface.so* /usr/lib/
COPY --from=patched /usr/lib/libbz2.so.1* /usr/lib/libjson-c.so.5* /usr/lib/liblzma.so.5* /usr/lib/libpcre2-8.so.0* /usr/lib/libxml2.so.2* /usr/lib/libz.so.1* /usr/lib/
ENV LANG=C TZ=Etc/UTC
USER 65532:65532
ENTRYPOINT ["/usr/bin/clamscan"]
