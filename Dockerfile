# syntax=docker/dockerfile:1.7
# REQ: OPS-001 — multi-arch image: FROM scratch + one static musl binary + CA bundle + tzdata,
# running as 65532:65532 (spec/08 §2). The build stage runs on the build host's platform and
# cross-compiles with cargo-zigbuild, so arm64/armv7 images never compile under QEMU.
#
#   docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t telltale:dev .
#   docker buildx build --load -t telltale:dev .                       # host arch only
#   docker buildx build --build-arg PROFILE=bench-fast --load -t telltale:dev .   # quick local build

ARG RUST_VERSION=1.99.0
ARG NODE_VERSION=24

# REQ: API-005 — the web UI is built once (it's platform-independent) and embedded in the
# binary (ADR-009). No Node in the final image.
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-bookworm-slim AS ui
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/ ./
# The help glossary (API-011) is shared with the site and imported from docs/help/.
COPY docs/help/topics.json /docs/help/topics.json
RUN npm run build

FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-slim-bookworm AS build
ARG TARGETARCH
ARG TARGETVARIANT
ARG PROFILE=release
ARG ZIG_VERSION=0.15.2
ARG ZIGBUILD_VERSION=0.23.4

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils tzdata \
 && rm -rf /var/lib/apt/lists/*

# Pinned toolchain downloads, checksum-verified (supply chain: spec/08 §7).
RUN set -eu; \
    case "$(uname -m)" in \
      x86_64)  zig_sha=02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239 ;; \
      aarch64) zig_sha=958ed7d1e00d0ea76590d27666efbf7a932281b3d7ba0c6b01b0ff26498f667f ;; \
      *) echo "unsupported build host $(uname -m)"; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/zig.tar.xz "https://ziglang.org/download/${ZIG_VERSION}/zig-$(uname -m)-linux-${ZIG_VERSION}.tar.xz"; \
    echo "${zig_sha}  /tmp/zig.tar.xz" | sha256sum -c -; \
    mkdir /opt/zig && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 && rm /tmp/zig.tar.xz; \
    if [ "$(uname -m)" = x86_64 ]; then \
      curl -fsSLo /tmp/zb.tar.xz "https://github.com/rust-cross/cargo-zigbuild/releases/download/v${ZIGBUILD_VERSION}/cargo-zigbuild-x86_64-unknown-linux-musl.tar.xz"; \
      echo "9e3cf73485edbd45905c8aadbc0fdf869c7ddc3848f0c898229f2680db52e44b  /tmp/zb.tar.xz" | sha256sum -c -; \
      tar -xJf /tmp/zb.tar.xz -C /usr/local/cargo/bin --strip-components=1 \
        cargo-zigbuild-x86_64-unknown-linux-musl/cargo-zigbuild && rm /tmp/zb.tar.xz; \
    else \
      cargo install --locked cargo-zigbuild --version "${ZIGBUILD_VERSION}"; \
    fi
ENV PATH="/opt/zig:${PATH}"

RUN case "${TARGETARCH}${TARGETVARIANT}" in \
      amd64)  echo x86_64-unknown-linux-musl ;; \
      arm64)  echo aarch64-unknown-linux-musl ;; \
      armv7)  echo armv7-unknown-linux-musleabihf ;; \
      *) echo "unsupported target ${TARGETARCH}${TARGETVARIANT}" >&2; exit 1 ;; \
    esac > /rust-target \
 && rustup target add "$(cat /rust-target)"

WORKDIR /src
# REQ: OPS-004 (ADR-046) — the build identity CI stamps into every architecture alike.
ARG TELLTALE_BUILD_VERSION=dev
ARG TELLTALE_BUILD_COMMIT=
ARG TELLTALE_BUILD_DATE=
ARG TELLTALE_BUILD_CHANNEL=dev
COPY . .
COPY --from=ui /ui/dist /src/ui/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,id=telltale-target-${TARGETARCH}${TARGETVARIANT},sharing=locked \
    set -eu; t="$(cat /rust-target)"; \
    cargo zigbuild --locked --profile "${PROFILE}" -p telltale --target "$t"; \
    mkdir -p /out/usr/local/bin /out/etc/ssl/certs /out/var/lib/telltale /out/etc/telltale /out/usr/share; \
    cp "target/$t/${PROFILE}/telltale" /out/usr/local/bin/telltale; \
    cp /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/; \
    cp -r /usr/share/zoneinfo /out/usr/share/zoneinfo; \
    printf 'root:x:0:0:root:/:/sbin/nologin\ntelltale:x:65532:65532:telltale:/var/lib/telltale:/sbin/nologin\n' > /out/etc/passwd; \
    printf 'root:x:0:\ntelltale:x:65532:\n' > /out/etc/group

# REQ: OPS-004 — just the static binary, for release assets and native installs:
#   docker buildx build --platform linux/arm64 --target bin --output type=local,dest=out .
FROM scratch AS bin
COPY --from=build /out/usr/local/bin/telltale /telltale

FROM scratch
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="TelltaleDNS" \
      org.opencontainers.image.description="See every question. Answer on your terms. A filtering, encrypted, observable, clustered DNS resolver." \
      org.opencontainers.image.source="https://github.com/paimonsoror/telltaledns" \
      org.opencontainers.image.licenses="Apache-2.0 OR MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build /out/ /
COPY --from=build --chown=65532:65532 /out/var/lib/telltale /var/lib/telltale
# REQ: OPS-004 (ADR-046) — containers update by pulling a new image.
ENV TELLTALE_INSTALL=container
USER 65532:65532
# The only writable path; run with a read-only root filesystem (spec/08 §2).
VOLUME ["/var/lib/telltale"]
EXPOSE 53/udp 53/tcp 8053/tcp 9153/tcp
ENTRYPOINT ["/usr/local/bin/telltale"]
CMD ["run"]
