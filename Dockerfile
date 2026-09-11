# Oxide multi-host testnet Dockerfile.
#
# Builds a release binary of oxide-validator and exposes the
# devnet-node mode for docker-compose orchestration. Each container
# runs one validator node; the compose file wires them together with
# induced latency via the `tc` (traffic control) netem qdisc.
#
# Build:
#   docker build -t oxide-validator .
#
# Run (4-node testnet with 20ms latency):
#   docker compose up --abort-on-container-exit
#
# The image is based on debian:bookworm-slim for glibc compatibility
# and includes iproute2 for traffic shaping.

FROM rust:1.95-bookworm AS builder

WORKDIR /oxide

# Copy the workspace.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY modules/ modules/
COPY bin/ bin/
COPY sim/ sim/

# Build the validator binary in release mode.
RUN cargo build --release -p oxide-validator

# ── Runtime image ──────────────────────────────────────────────────

FROM debian:bookworm-slim

# Install iproute2 for traffic control (netem latency injection).
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy the release binary.
COPY --from=builder /oxide/target/release/oxide-validator /usr/local/bin/oxide-validator

# Default: run as devnet node 0 with 4 nodes.
# Override via docker-compose environment variables.
ENTRYPOINT ["oxide-validator"]
CMD ["--devnet-node", "0", "--num-nodes", "4", "--base-port", "22000"]
