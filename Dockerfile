# Oxide multi-host testnet Dockerfile.
#
# Builds a release binary of oxide-devnet (the development
# multi-validator launcher) for docker-compose orchestration. Each
# container runs one devnet node; the compose file wires them
# together with induced latency via the `tc` (traffic control)
# netem qdisc.
#
# Build:
#   docker build -t oxide-devnet .
#
# Run (4-node testnet with 20ms latency):
#   docker compose up --abort-on-container-exit
#
# The image is based on debian:bookworm-slim for glibc compatibility
# and includes iproute2 for traffic shaping.

# Builder toolchain: must match the `channel` in rust-toolchain.toml
# exactly (that file is not copied into the image, so the image's own
# rustc is what compiles). Bump both together — a drifted image builds
# the testnet with a compiler CI never tested.
FROM rust:1.98.1-bookworm AS builder

WORKDIR /oxide

# Copy the workspace.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY modules/ modules/
COPY bin/ bin/
COPY sim/ sim/

# Build the devnet binary in release mode. oxide-validator ships
# too — the TLS testnet's provision container runs its `tls-gen`
# against the generated genesis inside the cluster, so nothing
# depends on host-side tooling.
RUN cargo build --release -p oxide-devnet -p oxide-validator

# ── Runtime image ──────────────────────────────────────────────────

FROM debian:bookworm-slim

# Install iproute2 for traffic control (netem latency injection).
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy the release binaries.
COPY --from=builder /oxide/target/release/oxide-devnet /usr/local/bin/oxide-devnet
COPY --from=builder /oxide/target/release/oxide-validator /usr/local/bin/oxide-validator

# Default: run as devnet node 0 with 4 nodes.
# Override via docker-compose environment variables.
ENTRYPOINT ["oxide-devnet"]
CMD ["--node", "0", "--num-nodes", "4", "--base-port", "22000"]
