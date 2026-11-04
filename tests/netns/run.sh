#!/usr/bin/env bash
# AEGIS X Milestone 1 — real enforcement test, OUTER half.
#
# Builds aegis-linux, then runs tests/netns/inner.sh inside a private
# user+network namespace (`unshare -Urn`), which is destroyed on exit.
# Nothing in this test can see or change the host firewall: the inner
# script never invokes nft outside its private namespace.
#
# Why unshare and not `ip netns`: this sandbox drops CAP_NET_ADMIN on
# the host, so `ip netns` and host nftables do not work here; inside a
# user namespace the test process holds the needed capabilities over its
# own private network namespace. See docs/VALIDATION.md.
#
# Usage: ./tests/netns/run.sh   (from the repository root; no sudo needed)

set -euo pipefail

# Rust may live in ~/.cargo/bin (rustup default) rather than on PATH.
export PATH="$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "== building aegis-linux =="
cargo build -q -p aegis-linux

echo "== running enforcement test inside unshare -Urn =="
unshare -Urn bash "$ROOT/tests/netns/inner.sh"

echo
echo "Outer shell: private namespace destroyed on unshare exit; host untouched."
