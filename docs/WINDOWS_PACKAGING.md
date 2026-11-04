# Windows packaging — WiX MSI steps (documentation only)

> There is NO MSI in this repo and none is claimed. The steps below
> are what the operator runs ON A WINDOWS PC after the M4
> verification (`tools/windows/verify-m4.ps1`) passes. Do not fake an
> MSI, a signature, or a successful install.

## Prerequisites (on the Windows PC)

1. Rust toolchain (https://rustup.rs).
2. WiX Toolset v3 or v4 (https://wixtoolset.org) — `candle`/`light`
   (v3) or the `wix` CLI (v4).
3. A code-signing certificate the operator owns (for `signtool`).
   Without it, the MSI is unsigned — say so, do not work around it.

## Build

```powershell
# From the repo root, Administrator PowerShell:
cargo build --release -p aegis-windows --bin aegis-win --bin aegis-service
# Binaries: target\release\aegis-win.exe, target\release\aegis-service.exe
```

## WiX authoring (what the .wxs must contain)

* `Directory` layout: `ProgramFiles64Folder\AEGIS X\` for the two
  binaries, plus the docs (`crates\aegis-windows\README.md`,
  `docs\ADMIN_GUIDE.md`).
* `Component` entries for each binary (one file per component, with
  stable GUIDs — generate with `New-Guid`, do not reuse the WFP
  provider/sublayer GUIDs for MSI components).
* `ServiceInstall` for `aegis-service` (name `AEGIS X`, start type
  `auto`, account `LocalSystem` — note: LocalSystem is powerful;
  a dedicated service account is better and is follow-up work).
* `ServiceControl` to start the service on install and stop/remove
  it on uninstall.
* A custom action (or documented manual step) to run
  `aegis-win uninstall` on MSI uninstall, so WFP filters do not
  outlive the product. Test this: uninstall the MSI, then confirm
  no AEGIS sublayer remains (see `cleanup-m4.ps1`).

## Compile + sign (WiX v3 example; v4 differs in CLI only)

```powershell
candle.exe aegis-x.wxs -out aegis-x.wixobj
light.exe aegis-x.wixobj -out aegis-x.msi
# Sign with YOUR certificate (never a placeholder):
signtool sign /a /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 aegis-x.msi
```

## What is now authored (finish-up round 2, Nov 3, 2026)

* `packaging/windows/aegis-x.wxs` — WiX v4/v5 installer source
  (binaries + docs, ServiceInstall + ServiceControl for the
  `AEGIS X` service, deferred `aegis-win uninstall` custom action
  on MSI uninstall, MajorUpgrade). It parses as well-formed XML
  (verified on Linux); the real schema check is `wix build` on
  the PC via `packaging/windows/build-msi.ps1`.
* `packaging/windows/build-msi.ps1` — release build + `wix build`
  (x64) + SHA-256 record. It prints an explicit UNSIGNED warning
  and never signs: signing needs the operator's own certificate.
* Service-loop note, corrected: the service binary is no longer
  "SCM entry points only" — `aegis-service.rs` now holds the full
  loop structure (initial install, file-watch reinstall, uninstall
  on stop), cross-target compile-checked. It has still never RUN
  under the SCM; `tools/windows/verify-service.ps1` is the
  procedure for that run, and it is still pending.

## What is still missing (stated plainly)

* No `wix build` run yet (WiX is Windows-only) and no signed MSI
  artifact exists anywhere in this repo. No certificate is
  invented here; signing is a pending operator step.
* No MSI install/uninstall verification run on a real Windows
  host (including confirming no AEGIS WFP sublayer remains after
  uninstall).
* No upgrade story beyond MajorUpgrade (config migration).
* A dedicated service account instead of LocalSystem is still
  follow-up work.
