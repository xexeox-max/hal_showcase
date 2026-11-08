FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p hal-relay -p hal_node --example ws_tcp_bridge

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/hal-relay halrelay \
    && install -d -o halrelay -g halrelay /var/lib/hal-relay /run/secrets
COPY --from=builder /src/target/release/hal-relay /usr/local/bin/hal-relay
COPY --from=builder /src/target/release/examples/ws_tcp_bridge /usr/local/bin/hal-ws-bridge
USER halrelay
ENV HAL_DATA_DIR=/var/lib/hal-relay
EXPOSE 4001/tcp
ENTRYPOINT ["/usr/local/bin/hal-relay"]
