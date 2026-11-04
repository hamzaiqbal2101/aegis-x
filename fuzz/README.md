# AEGIS X policy-parser fuzzer (cargo-fuzz / libFuzzer)

Coverage-guided fuzzing for `Policy::from_json` (ITEM 4, Nov 3, 2026).
This is the real fuzzer counterpart to the deterministic property
tests in `crates/aegis-core/src/property_tests.rs`, which are
explicitly fuzz-lite (fixed-seed PRNG, no mutation, no coverage).

## Toolchain evidence (verified, not assumed)

- Base: stable Rust 1.99.1 via rustup (default PATH does NOT
  include cargo — prefix every command with
  `export PATH="$HOME/.cargo/bin:$PATH"`).
- `rustup toolchain install nightly` SUCCEEDED here:
  `nightly-x86_64-unknown-linux-gnu installed - rustc 1.101.0-nightly
  (1c3a65069 2026-11-02)`. No fallback was needed.
- `cargo install cargo-fuzz` installed `cargo-fuzz 0.13.2`.
- IMPORTANT: plain `cargo fuzz build` fails with
  "`Z` is only accepted on the nightly compiler" because the
  default toolchain is stable. Always run as
  `cargo +nightly fuzz ...`.

## Layout (file ownership: this directory only + property_tests.rs)

- `Cargo.toml` — detached crate (`[workspace]` empty), so the
  parent `~/workspace/aegis-x/Cargo.toml` is UNTOUCHED.
  Dependencies: `libfuzzer-sys 0.4`, `serde_json 1`,
  `aegis-core` (path `../crates/aegis-core`). Own `Cargo.lock`.
- `fuzz_targets/policy_parser.rs` — the only target. On each
  input it: (1) skips non-UTF-8 bytes (`Policy::from_json` takes
  `&str`, so invalid UTF-8 can never reach the parser — that
  boundary is a caller check, not a parser branch; see the
  property test for it); (2) skips inputs > 1 MiB (well above
  any real policy, keeps exec/s meaningful); (3) calls
  `Policy::from_json`; (4) if parsing succeeds, runs
  `matcher::evaluate` on 14 fixed packets (TCP/UDP/ICMP/Any ×
  New/Established/Invalid, plus an IPv6 packet and a port-less
  ICMP packet) and re-serializes the policy. Deliberately a
  no-panic oracle only — stronger invariants (round-trip
  equality, idempotent re-parse) stay in `property_tests.rs`,
  where a failure is a readable test failure, not a crash.
- `corpus/policy_parser/` — 4 hand-written seeds
  (`valid-minimal.json`, `valid-zones.json`, `truncated.json`,
  `bom.json`) plus libFuzzer-grown coverage inputs:
  2,334 files, 227 KB on disk at the end of this work.
  (libFuzzer deduplicates at load, so its tracked corpus count
  in run logs — 348 distinct at run-2 start, 1,130 at its crash —
  is smaller than the on-disk file count.)
- `artifacts/policy_parser/` — crash reproducers (see below).
- `target/` — fuzz build output (not part of the deliverable).

## Run

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cd ~/workspace/aegis-x
cargo +nightly fuzz run policy_parser -- -max_total_time=240
# reproduce a crash:
cargo +nightly fuzz run policy_parser fuzz/artifacts/policy_parser/<crash-file>
# single-input check (no mutation):
./fuzz/target/x86_64-unknown-linux-gnu/release/policy_parser fuzz/artifacts/policy_parser/<crash-file>
```

## Results: 1 finding, reproduced twice, THEN FIXED + clean rerun

Both time-boxed runs (`-max_total_time=240`) ended early with
the SAME panic — until the coordinator fixed it (see "Fix"
below). Post-fix clean run (Nov 3, 2026): `cargo +nightly
fuzz run policy_parser -- -max_total_time=180` → **Done
6,599,790 runs in 181 second(s), no crash**. The stale
pre-fix crash artifact is kept for reference only and no
longer reproduces.

### Fix (coordinator, Nov 3, 2026)

`Cidr::contains` in `crates/aegis-core/src/policy.rs` now
checks `same_family` BEFORE masking, and `mask()` uses
saturating shifts as a second line of defense. Regression
test: `cross_family_cidr_match_v6_prefix_above_32` in
`crates/aegis-core/src/property_tests.rs` (covers /48, /64,
/128 plus the exact reproducer policy at the `evaluate`
level). Original finding details preserved below.

| Run | Seed corpus | Executions at crash | Coverage at crash |
|-----|-------------|---------------------|-------------------|
| 1 (pre pentest edit) | 4 files | ~122,077 | cov 2393, ft 5325 |
| 2 (rebuilt, current code) | 906 files | ~389,110 | cov 2409, ft 5154 |

Total across both runs: ~511,000 executions. No other
panics/crashes were found; the only crash in both runs is
this one bug.

### Finding — SEVERITY: Medium (High if overflow-checks are on)

**Panic: `attempt to subtract with overflow` at
`crates/aegis-core/src/policy.rs:137:29`, in `mask()`:**

```rust
u32::MAX << (32 - prefix)   // V4 branch; prefix is a u8
```

**Root cause.** `Cidr::contains` (and `contains_network`)
calls `mask(ip, self.prefix)` BEFORE checking `same_family`:

```rust
mask(ip, self.prefix) == self.network && same_family(ip, self.network)
```

`Cidr::parse` validates a prefix against its OWN family
(V4 ≤ 32, V6 ≤ 128), but `contains` is called with a packet
of the OTHER family. A V4 packet checked against a V6 CIDR
with prefix 33–128 (i.e. any normal V6 prefix: /48, /64,
/128) computes `32 - prefix` → underflow. The reverse
direction (V6 packet vs V4 CIDR, prefix ≤ 32) cannot
underflow, which is why it was never seen before. The
existing property corpus only used V6 `/32` — exactly the
largest safe prefix — so it could never trigger this.

**Trigger (minimal, valid under current code).** Any policy
with a V6 zone/subnet of prefix > 32, evaluated against any
V4 packet, e.g.:

```json
{"version":1,"name":"t","default_action":"deny",
 "zones":[{"name":"lan","subnets":["2001:db8::/48"]}],
 "rules":[{"id":"web","priority":10,"action":"allow","protocol":"tcp",
           "dst_zone":"lan","dst_port":443}]}
```

with packet src `203.0.113.7` → dst `10.0.0.5`, TCP/443.
Verified outside the fuzzer with a standalone debug binary:
parses fine, then panics at `policy.rs:137`, exit 101.
It does NOT need a zone: a rule with a direct V6
`dst_addrs`/`src_addrs` entry of prefix > 32 triggers the
same way, and `contains_network` has the same flaw.

**Current reproducer (valid for current code):**
`fuzz/artifacts/policy_parser/crash-f5368f7eb905a2fbf88627efa34c8d0b0a2d1ff5`
— the same seed policy as `corpus/valid-zones.json` with
the second zone subnet mutated from `2001:db8::/32` to the
bare host `2001:db8::c32` (= `/128`). It reproduces
standalone with the fuzz binary (libFuzzer deadly signal).

**Superseded first reproducer.** Run 1's crash file
(`crash-d94874…`, zone subnet `2001:db8::032` plus a typo
field `dst_povt`) was DELETED, not kept: while run 1 was
running, the concurrent pentest agent edited `policy.rs`
(14:15:49, adding `deny_unknown_fields` to `RateLimit`,
`Rule`, `Zone` and `Policy`), so that input now fails
parsing with "unknown field `dst_povt`" before ever
reaching `mask()`. Keeping it would have looked like the
bug was fixed when it was not. Run 2's reproducer above
was generated against the current code and contains no
unknown fields.

**Impact, measured.**
- Debug builds (including `cargo test` and cargo-fuzz, which
  enables debug-assertions): the evaluating thread panics.
  Any debug/test harness evaluating a V4 packet against a
  rule referencing a V6 /48+/zone crashes — a local DoS
  for that process/thread.
- Default release builds (overflow-checks off, as verified
  with a standalone release binary): NO panic, and the
  verdict is accidentally correct (Deny) because the wrapped
  shift result can never equal the other family's network
  and `same_family` is false. So in default release this is
  a latent correctness bug, not a bypass (it cannot turn a
  deny into an allow: the comparison is against a different
  `IpAddr` variant and always fails).
- If a release build enables `overflow-checks = true`
  (or a future profile does), the release behaviour becomes
  the debug behaviour: a single V4 packet against a V6
  /48+ rule panics the evaluator. Treat the severity as
  High for any such build.

**Suggested fix (NOT applied — `policy.rs` is outside this
task's file ownership, and the task forbids editing it).**
Trivially safe, two reorderings, no redesign: in
`Cidr::contains`, check `same_family` first
(`same_family(ip, self.network) && mask(...) == ...`),
and likewise in `contains_network`. Alternatively make
`mask()` family-safe (return a sentinel / refuse a prefix
above the family's maximum). Either fix must be followed
by: re-running this fuzzer for a full 240 s (it should then
complete without crashing), and adding a regression test
for V4-vs-V6-/48 matching (the property test added here
pins only the safe /32 boundary — see below — because a
/48 test would go red until the fix lands).

### What the fuzzer did NOT find

No other panic, hang, ASan error, or wrong-verdict crash in
~511k executions. In particular: no serde_json recursion
crash (its 128-depth limit returns `Err`), no port-range
overflow (`PortSpec::subset_of` guards `hi - lo` with
`lo <= hi` first), and no CIDR-parse overflow (parse
validates prefix per family before calling `mask`).

## Property-test additions (same work, `property_tests.rs`)

Because nightly DID work, the step-3 fallback (substantial
corpus expansion instead of a fuzzer) was not required, but
two verified tests were added anyway, both probed against
the live parser first (see the test comments):

- `adversarial_inputs_never_panic_and_reject_as_expected`:
  40 table cases + huge inputs (2,000 rules; 100,000-char
  name) + the invalid-UTF-8 boundary. Covers empty/
  whitespace, wrong top-level types, duplicate JSON keys
  (serde rejects, does not take last), unknown fields
  (now a load error under `deny_unknown_fields`), unicode
  names/descriptions, BOM-inside-string vs double-BOM,
  u32/u16/u64 maxima and one-past maxima, float/string
  ports, inverted/1-/3-element/equal-ends ranges, CIDR
  /0, /128, leading-zero prefix, double-slash, empty
  string, rules-as-object/null, ICMPv6-with-ports,
  uppercase enums, duplicate zone names, case-distinct
  rule ids, empty rule id, 1,000 unclosed brackets, and a
  200-deep array as a port list.
- `cross_family_cidr_match_is_safe_at_prefix_32`: pins the
  safe boundary (V4 vs V6 /32, V6 vs V4 /16, both
  `contains` and `contains_network` return false). The
  /33+ case is deliberately NOT asserted — it is the fuzz
  finding above, and asserting it now would go red.

## Known limitations / what could not be done

- No full 240 s clean fuzz run: both runs crashed on the
  finding above (see table). Re-run after the `mask()`
  fix for a clean completion.
- `cargo fuzz tmin` on run 1's crash failed ("input did
  not crash") for the reason above (concurrent
  `deny_unknown_fields` edit made it unparseable); the
  minimal reproducer in this README (V6 /48 zone) was
  verified by hand instead, and run 2's artifact is the
  current minimised-equivalent reproducer.
- The fuzzer binary on disk was built against the
  `policy.rs` current at the end of this work; if the
  pentest agent edits `policy.rs` again, rebuild before
  re-running (`cargo +nightly fuzz build policy_parser`).
- No host firewall, WFP, or nftables state was touched.
  No other crate source, workspace `Cargo.toml`, `benches/`,
  `api/`, or other test files were edited.
