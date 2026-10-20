# 2Secret server + web vault in one small image (linux/amd64 and linux/arm64).
#
#   docker build -t 2secret .
#   docker run -p 8743:8743 -v 2secret-data:/data 2secret
#
#   # both architectures (needs QEMU for the final stage's RUN):
#   docker buildx build --platform linux/amd64,linux/arm64 -t 2secret .
#
# Put a TLS-terminating reverse proxy (Caddy, nginx, Traefik) in front of it.

# The web vault is WebAssembly and the same for every architecture: build it
# once, natively on the build machine.
FROM --platform=$BUILDPLATFORM rust:1-trixie AS web
# dx with the checksums of its release (change them with DX_VERSION).
ARG DX_VERSION=0.7.10
ARG DX_SHA256_X86_64=4363e4ed2a3f1eb7f4d38d2d59aed59ce43271c44c16b425e92c89a64761fbe7
ARG DX_SHA256_AARCH64=8f1a17d3218700ffbe15e6540d936a178b2556fc801121a31082e3ba4ab9ef55
RUN rustup target add wasm32-unknown-unknown \
 && arch="$(uname -m)" \
 && case "$arch" in x86_64) sum="$DX_SHA256_X86_64" ;; aarch64) sum="$DX_SHA256_AARCH64" ;; *) exit 1 ;; esac \
 && curl -sSfL -o /tmp/dx.tar.gz "https://github.com/DioxusLabs/dioxus/releases/download/v${DX_VERSION}/dx-${arch}-unknown-linux-gnu.tar.gz" \
 && echo "$sum  /tmp/dx.tar.gz" | sha256sum -c - \
 && tar xzf /tmp/dx.tar.gz -C /usr/local/cargo/bin && rm /tmp/dx.tar.gz
WORKDIR /src
COPY . .
RUN cd crates/app && dx bundle --platform web --release

# The server is cross-compiled on the build machine for the target architecture.
FROM --platform=$BUILDPLATFORM rust:1-trixie AS server
ARG BUILDARCH
ARG TARGETARCH
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu; gcc=x86-64-linux-gnu ;; \
      arm64) triple=aarch64-unknown-linux-gnu; gcc=aarch64-linux-gnu ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
      apt-get update && apt-get install -y --no-install-recommends "gcc-$gcc" "libc6-dev-$TARGETARCH-cross"; \
      rm -rf /var/lib/apt/lists/*; \
    fi; \
    rustup target add "$triple"; \
    echo "$triple" > /triple
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
    CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc
WORKDIR /src
COPY . .
RUN triple="$(cat /triple)" \
 && cargo build --release -p twosecret-server --target "$triple" \
 && cp "target/$triple/release/2secret-server" /2secret-server

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /data twosecret \
 && mkdir -p /data && chown twosecret /data
COPY --from=server /2secret-server /usr/local/bin/2secret-server
COPY --from=web /src/crates/app/dist/public /srv/2secret-web
ENV TWOSECRET_BIND=0.0.0.0:8743 \
    TWOSECRET_DATA_DIR=/data \
    TWOSECRET_WEB_DIR=/srv/2secret-web
USER twosecret
VOLUME ["/data"]
EXPOSE 8743
CMD ["2secret-server"]
