#!/usr/bin/env bash
# AEGIS X Milestone 1 — real enforcement test, INNER half.
#
# Runs INSIDE `unshare -Urn` (see run.sh): a private user+network
# namespace with its own nftables tables, destroyed on exit. Nothing here
# can see or change the host firewall.
#
# Topology (dictated by this sandbox, documented in docs/VALIDATION.md):
# the sandbox blocks client connections to non-loopback local addresses,
# so the test runs over loopback (127.0.0.1), which the sandbox permits.
# Loopback traffic IS filtered by nftables input/output hooks, so this is
# a real enforcement test — it is not a simulation. Two deliberate
# degradations, both explicit flags, both documented:
#   --no-conntrack: this kernel has no nf_conntrack module, so the
#     stateful base rules cannot be installed here. The test policy
#     therefore allows return traffic explicitly (src_port rule), the
#     way stateless firewalls must.
#   --no-loopback-accept: the shipped policy accepts loopback
#     unconditionally, which would bypass user rules on lo. The test
#     omits that base rule so user rules actually decide loopback traffic.
# On a normal distro kernel, drop --no-conntrack (and keep
# --no-loopback-accept only for the loopback test).

set -euo pipefail

INNER_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$INNER_DIR/../.." && pwd)"
BIN="$ROOT/target/debug/aegis-linux"
STATE_DIR="/tmp/aegis-test-state"

PID8080=""
PID9090=""
cleanup() {
    [ -n "$PID8080" ] && kill $PID8080 2>/dev/null || true
    [ -n "$PID9090" ] && kill $PID9090 2>/dev/null || true
}
trap cleanup EXIT

echo "-- private namespace: loopback up --"
ip link set lo up

echo "-- starting real listeners (8080 allowed, 9090 denied) --"
timeout 120 python3 -m http.server 8080 --bind 127.0.0.1 --directory /tmp >/dev/null 2>&1 &
PID8080=$!
timeout 120 python3 -m http.server 9090 --bind 127.0.0.1 --directory /tmp >/dev/null 2>&1 &
PID9090=$!
for _ in $(seq 1 20); do
    if ss -tln | grep -q ":8080" && ss -tln | grep -q ":9090"; then
        break
    fi
    sleep 0.5
done
ss -tln | grep -E ':(8080|9090)' || { echo "FAIL: listeners did not come up"; exit 1; }

echo "-- applying policy (inside this private namespace only) --"
"$BIN" apply --policy "$ROOT/tests/netns/policy.json" \
    --confirm-host-apply --no-conntrack --no-loopback-accept \
    --state-dir "$STATE_DIR"

echo "-- ruleset actually installed --"
nft list ruleset

echo "-- TEST 1: allowed port 8080 must answer --"
set +e
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:8080/)
CURL_RC=$?
set -e
echo "HTTP status on 8080: ${CODE:-<none>} (curl rc=$CURL_RC)"
if [ "${CODE:-}" != "200" ]; then
    echo "FAIL: allowed port did not answer (expected HTTP 200)"; exit 1
fi
echo "PASS: allowed port reachable"

echo "-- TEST 2: denied port 9090 must NOT answer (firewall drop -> timeout) --"
set +e
curl -s -o /dev/null --max-time 4 http://127.0.0.1:9090/ 2>/dev/null
CURL_RC=$?
set -e
echo "curl exit code on 9090: $CURL_RC (28 = timeout, i.e. packets dropped)"
if [ "$CURL_RC" -eq 0 ]; then
    echo "FAIL: denied port answered — firewall did not block"; exit 1
fi
echo "PASS: denied port blocked"

echo "-- TEST 3: nftables counters moved --"
INPUT_DUMP=$(nft list chain inet aegis input)
OUTPUT_DUMP=$(nft list chain inet aegis output)
echo "$INPUT_DUMP"
fwd() { echo "$1" | grep "$2" | grep -o 'packets [0-9]*' | awk '{print $2}' || true; }
ACCEPT_PKTS=$(fwd "$INPUT_DUMP" 'aegis: allow-test-web ')
RETURN_PKTS=$(fwd "$INPUT_DUMP" 'aegis: allow-test-web-return')
DENY_IN=$(fwd "$INPUT_DUMP" 'aegis: default deny')
DENY_OUT=$(fwd "$OUTPUT_DUMP" 'aegis: default deny')
echo "input counters: allow-dport=${ACCEPT_PKTS:-0} allow-sport=${RETURN_PKTS:-0} deny=${DENY_IN:-0}"
echo "output deny counter: ${DENY_OUT:-0}"
if [ "${ACCEPT_PKTS:-0}" -lt 1 ] || [ "${RETURN_PKTS:-0}" -lt 1 ]; then
    echo "FAIL: expected both allow counters >= 1"; exit 1
fi
if [ "${DENY_IN:-0}" -lt 1 ] && [ "${DENY_OUT:-0}" -lt 1 ]; then
    echo "FAIL: no default-deny counter moved"; exit 1
fi
echo "PASS: counters confirm real enforcement"

echo
echo "ALL LOOPBACK ENFORCEMENT TESTS PASSED"
