# aegis-windows — Windows adapter

Two halves:

* `src/translate.rs` — policy → WFP filter data (layers, weights,
  conditions, actions). Pure Rust, unit-tested on every platform,
  including Linux. This is the part that **is** verified.
* `src/engine.rs` — installs those filters into the live WFP engine
  via the `windows` crate. **Windows-only, compile-checked from Linux**
  via `cargo check -p aegis-windows --target x86_64-pc-windows-gnu
  --all-targets` (that check caught and fixed 30+ first-draft errors,
  including a missing `Win32_Security` feature and wrong struct
  shapes). What it does NOT prove is linking or runtime behavior —
  those still need a Windows host (see below).

## Build on Windows

From an Administrator PowerShell, in the `aegis-x` repo root:

```powershell
cargo build -p aegis-windows --bin aegis-win
cargo test -p aegis-windows
```

The code already type-checks against the Windows target (see above),
so the Windows build is expected to be clean apart from linking;
if it is not, send the errors back and they will be fixed. Do not
claim Windows enforcement until the build is clean AND the
verification below passes.

## Verify on Windows (M4)

```powershell
# From the repo root, Administrator PowerShell:
.\tools\windows\verify-m4.ps1
```

What it does (narrow scope, safe on a main PC, VM preferred):

1. Builds + unit-tests.
2. Installs a test policy: default **allow** (normal traffic untouched)
   plus one block rule for TCP port 18081 only.
3. Probes the machine's LAN IP (loopback is exempt from WFP ALE, so
   127.0.0.1 cannot prove anything): 18081 must be blocked, unlisted
   ports must stay reachable.
4. Always uninstalls the test policy at the end, even on failure.

To clean up manually at any time:

```powershell
.\tools\windows\cleanup-m4.ps1
```

## What "install" means (read before running on a main PC)

* AEGIS creates one provider and one sublayer (fixed GUIDs, see
  `engine.rs`) and installs its filters there. Install = one
  transaction: delete the sublayer (all previous AEGIS filters go
  with it — replace, never merge), re-add it, add the new filters,
  commit. Any error aborts and rolls back.
* The sublayer weight is max (0xFFFF): AEGIS filters win arbitration
  over other sublayers, including Windows Firewall's own. Installing
  AEGIS makes it the effective firewall. That is deliberate — a
  firewall that loses arbitration protects nothing — but say it
  plainly to anyone installing it.
* Filters persist across reboots until uninstalled (standard WFP
  behavior for a non-dynamic session; `aegis-win` opens the engine
  with a NULL session, i.e. the default non-dynamic session).
  Uninstall deletes the sublayer (filters with it) and then the
  provider — that is the complete cleanup. The verify script tests
  this implicitly: it installs (process exits) and only then probes —
  if filters were session-scoped, 18081 would stay reachable and the
  test would FAIL.
* If WFP rejects delete-then-recreate of the same sublayer key inside
  one transaction, split install into two transactions (delete +
  commit, then add + commit) and note the brief unfiltered window.
* App rules (`"app": "C:\\Path\\app.exe"`) resolve the executable to
  an ALE app id. A path that fails resolution fails the whole install
  (fail closed — a rule must never be installed without its app scope).

## M4 limits (fail closed, not silently weakened)

* Interface-scoped rules are refused on Windows (Windows interface
  naming differs from Linux names; the mapping is follow-up work).
* Rules matching only `invalid` state are refused (they can never fire).
* Port ranges ARE supported (via FWP_RANGE0) since the cross-target
  compile check verified the range API shapes.
* A default-**deny** allow-rule proof (showing an explicit allow is
  what lets traffic through) belongs in a VM, not on a main PC: with
  default deny installed, a mistake blocks all traffic. The
  `verify-m4.ps1` script deliberately uses default allow and proves
  the block direction plus non-interference.
* Filter enumeration (listing installed filters) is M4 follow-up;
  `aegis-win status` currently proves engine access only.
* The Windows service + installer packaging is separate M4 follow-up
  work; `aegis-win` is a CLI, not a service.
