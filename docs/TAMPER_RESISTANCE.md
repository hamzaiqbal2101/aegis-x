# Tamper resistance — what AEGIS X does and does not protect

## What exists (M8)

* **Policy integrity hashing.** Every policy stored by the API carries
  a SHA-256 hash over its canonical JSON (see `aegis-core`'s
  `policy_hash`, replicated in `api/app.py`). The hash is recomputed
  on read for display; a stored policy whose content no longer
  matches its hash has been modified outside the API. The API's
  validate path additionally re-runs the Rust CLI `check`, so a
  tampered policy that fails validation cannot be applied through
  the API without an explicit error.
* **Append-only audit log.** The API's audit table has no update or
  delete endpoint. Every create, update, delete, validate, apply, and
  rollback writes a row (timestamp, actor, action, policy id, detail).
  Review it via `GET /audit`.
* **Replace-on-apply, not merge.** Applying a policy deletes the
  previous AEGIS table/sublayer and installs the new one, so stale
  rules cannot survive a policy change unnoticed. Rollback swaps
  current/previous state explicitly (Linux) instead of editing rules
  in place.
* **Release checksums.** `packaging/SHA256SUMS` lists SHA-256 hashes
  of the release artifacts built by `packaging/deb/build-deb.sh`.
  Verify before installing: `sha256sum -c SHA256SUMS`.

## What this does NOT protect against (honest limits)

* **Root compromise.** If an attacker gains root on the firewall host,
  they can edit the SQLite database, the audit log file, and the
  ruleset itself. Nothing in AEGIS X survives a root compromise on
  its own host — that is true of every host firewall.
* **Database tampering without external logging.** The audit log is
  append-only *through the API*, but the SQLite file itself can be
  edited by anyone with file access. For real tamper evidence, ship
  audit rows to an append-only remote log (syslog to a separate
  host, or a WORM store) — that integration is future work, not
  shipped here.
* **Unsigned packages.** The .deb built by `build-deb.sh` is
  UNSIGNED (signing needs the operator's GPG key). Do not treat an
  unsigned package as authenticated. The Windows MSI path
  (`docs/WINDOWS_PACKAGING.md`) likewise requires the operator's
  code-signing certificate; no signature is faked anywhere.
* **No secure boot / measured boot story.** AEGIS X does not verify
  the boot chain or the kernel. If the host itself is untrusted,
  firewall integrity claims do not hold.

## Operator checklist

1. Keep `/etc/aegis-x/api.env` (the API token) root-only, mode 0600.
2. Back up the API database + state dir; after a restore, compare
   each policy's stored hash against a fresh computation.
3. Review `GET /audit` regularly; investigate gaps in row ids
   (a gap means rows were deleted outside the API).
4. Verify `SHA256SUMS` before installing any release artifact.
