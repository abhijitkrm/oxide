#!/bin/bash
# inject-latency.sh — entrypoint for oxide-validator Docker containers.
#
# This script optionally injects network latency via `tc netem` and
# then runs the oxide-validator binary. The latency is applied to the
# container's eth0 interface, affecting all outbound traffic.
#
# Environment variables:
#   LATENCY_MS  — one-way latency in ms (default: 0, no latency)
#   JITTER_MS   — jitter in ms (default: 0)
#   LOSS_PERCENT — packet loss percentage (default: 0)
#
# After applying latency, the script execs oxide-validator with the
# command-line arguments passed via CMD.

set -e

LATENCY_MS="${LATENCY_MS:-0}"
JITTER_MS="${JITTER_MS:-0}"
LOSS_PERCENT="${LOSS_PERCENT:-0}"

# Apply traffic shaping if latency > 0.
if [ "$LATENCY_MS" -gt 0 ] 2>/dev/null; then
    echo "inject-latency: applying ${LATENCY_MS}ms latency, ${JITTER_MS}ms jitter, ${LOSS_PERCENT}% loss"
    tc qdisc add dev eth0 root netem delay "${LATENCY_MS}ms" "${JITTER_MS}ms" loss "${LOSS_PERCENT}%"
else
    echo "inject-latency: no latency injection (LATENCY_MS=0)"
fi

# Exec the validator with the provided arguments.
exec /usr/local/bin/oxide-validator "$@"
