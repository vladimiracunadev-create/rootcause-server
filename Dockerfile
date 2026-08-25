FROM rust:1.95-bookworm AS builder
WORKDIR /build
COPY Cargo.toml rust-toolchain.toml ./
COPY crates ./crates
COPY console ./console
RUN cargo build --release -p rootcause-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/rootcause rootcause \
    && install -d -o rootcause -g rootcause /var/lib/rootcause
COPY --from=builder /build/target/release/rootcause-server /usr/local/bin/rootcause-server
USER rootcause
WORKDIR /var/lib/rootcause
ENV ROOTCAUSE_BIND=0.0.0.0:8080
ENV ROOTCAUSE_DATABASE_URL=sqlite:///var/lib/rootcause/rootcause.db
EXPOSE 8080
VOLUME ["/var/lib/rootcause"]
ENTRYPOINT ["rootcause-server", "serve"]
