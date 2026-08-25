# syntax=docker/dockerfile:1

# La imagen contiene un binario y nada más: la consola va compilada dentro, así
# que no hay directorio de recursos que montar mal ni servidor de archivos que
# endurecer.

FROM rust:1.97-bookworm AS builder

WORKDIR /build

# Las dependencias cambian mucho menos que el código: se copian primero para
# que una edición del motor de detección no vuelva a compilar el árbol entero.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/rootcause-core/Cargo.toml crates/rootcause-core/
COPY crates/rootcause-server/Cargo.toml crates/rootcause-server/
COPY crates/rootcause-agent/Cargo.toml crates/rootcause-agent/
RUN mkdir -p crates/rootcause-core/src crates/rootcause-server/src crates/rootcause-agent/src \
    && echo 'fn main() {}' > crates/rootcause-server/src/main.rs \
    && echo 'fn main() {}' > crates/rootcause-agent/src/main.rs \
    && touch crates/rootcause-core/src/lib.rs \
    && cargo fetch --locked

COPY crates ./crates
COPY console ./console
RUN cargo build --release --locked -p rootcause-server \
    && strip target/release/rootcause-server

FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="RootCause Server" \
      org.opencontainers.image.description="Plano de control que defiende servidores y la red que los rodea" \
      org.opencontainers.image.source="https://github.com/vladimiracunadev-create/rootcause-server" \
      org.opencontainers.image.licenses="MIT"

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/rootcause rootcause \
    && install -d -o rootcause -g rootcause /var/lib/rootcause

COPY --from=builder /build/target/release/rootcause-server /usr/local/bin/rootcause-server

USER rootcause
WORKDIR /var/lib/rootcause

# Dentro de un contenedor, loopback significa "inalcanzable". El enlace abierto
# aquí lo compensa la red del contenedor y el proxy con TLS que va delante:
# `compose.yml` publica el puerto únicamente en 127.0.0.1 del anfitrión.
ENV ROOTCAUSE_BIND=0.0.0.0:8080 \
    ROOTCAUSE_DATABASE_URL=sqlite:///var/lib/rootcause/rootcause.db \
    ROOTCAUSE_JSON_LOGS=true

EXPOSE 8080
VOLUME ["/var/lib/rootcause"]

ENTRYPOINT ["rootcause-server", "serve"]
