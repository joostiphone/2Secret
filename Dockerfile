# 2Secret server + web vault in one small image.
#
#   docker build -t 2secret .
#   docker run -p 8743:8743 -v 2secret-data:/data 2secret
#
# Put a TLS-terminating reverse proxy (Caddy, nginx, Traefik) in front of it.

FROM rust:1-trixie AS build
ARG DX_VERSION=0.7.10
RUN rustup target add wasm32-unknown-unknown \
 && curl -sSfL "https://github.com/DioxusLabs/dioxus/releases/download/v${DX_VERSION}/dx-x86_64-unknown-linux-gnu.tar.gz" \
    | tar xz -C /usr/local/cargo/bin
WORKDIR /src
COPY . .
RUN cargo build --release -p twosecret-server
RUN cd crates/app && dx bundle --platform web --release

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /data twosecret \
 && mkdir -p /data && chown twosecret /data
COPY --from=build /src/target/release/2secret-server /usr/local/bin/2secret-server
COPY --from=build /src/crates/app/dist/public /srv/2secret-web
ENV TWOSECRET_BIND=0.0.0.0:8743 \
    TWOSECRET_DATA_DIR=/data \
    TWOSECRET_WEB_DIR=/srv/2secret-web
USER twosecret
VOLUME ["/data"]
EXPOSE 8743
CMD ["2secret-server"]
