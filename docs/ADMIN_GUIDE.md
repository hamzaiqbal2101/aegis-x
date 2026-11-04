# AEGIS X Administrator Guide

> Status: Milestones M1–M8 are built, but AEGIS X is NOT release-ready.
> Windows enforcement is written but never compiled or run on Windows
> (see `docs/VALIDATION.md` §6). Suricata integration and live threat
> feeds are roadmap, not shipped. Read the honest limits before
> deploying anything.

## 1. Install

### From source (Linux)

```bash
# Rust (https://rustup.rs) + Python 3.12 + node/npm required.
export PATH="$HOME/.cargo/bin:$PATH"
cargo build --release                       # in the repo root
python3 -m venv api/.venv
api/.venv/bin/pip install fastapi uvicorn httpx
cd dashboard && npm install && npm run build && cd ..
```

### From the .deb skeleton

```bash
./packaging/deb/build-deb.sh                # produces packaging/deb/out/*.deb (UNSIGNED)
sudo dpkg -i packaging/deb/out/aegis-x_0.1.0_amd64.deb
```

The package installs to `/opt/aegis-x/` and the systemd unit to
`/etc/systemd/system/aegis-api.service`. The Python venv is NOT in
the package — create it on the target host (see above). Set the
token, then enable:

```bash
sudo useradd --system --home-dir /var/lib/aegis-x aegis   # if missing
sudo mkdir -p /etc/aegis-x
echo "AEGIS_API_TOKEN=<a long random token>" | sudo tee /etc/aegis-x/api.env
sudo chmod 600 /etc/aegis-x/api.env
sudo systemctl daemon-reload && sudo systemctl enable --now aegis-api
```

## 2. Configure

Environment variables for the API (see `api/README.md` for the full list):

| Variable | Default | Meaning |
|---|---|---|
| `AEGIS_API_TOKEN` | (generated, printed once) | Admin token; set it explicitly for a service. |
| `AEGIS_API_DB` | `api/aegis.db` | SQLite path. |
| `AEGIS_API_BIND` | `127.0.0.1` | Bind address. Never `0.0.0.0` without TLS + stronger auth in front. |
| `AEGIS_API_PORT` | `8000` | Port. |

Policies are JSON documents (see `examples/standard.json`). Rules
are priority-ordered, first-match-wins, default-deny unless the
policy says otherwise. Zone names in rules must be defined in the
policy's `zones` list.

## 3. Operate

### CLI (Linux)

```bash
aegis-linux render --policy policy.json [--no-conntrack]
aegis-linux check --policy policy.json [--no-conntrack]
aegis-linux apply --policy policy.json --netns <name> [--no-conntrack]
aegis-linux rollback --netns <name>
aegis-linux eval --policy policy.json --src 10.0.0.5 --dst 10.0.0.1 --dport 443
```

`apply` REFUSES to touch the host firewall unless `--netns` or
`--confirm-host-apply` is given. The same gate applies to the API's
`POST /apply`. There is no automatic apply on boot or on API start:
re-apply deliberately after verifying the policy.

### API

`GET /status` (no auth), `GET/POST /policies`,
`GET/PUT/DELETE /policies/{id}`, `POST /policies/{id}/validate`,
`POST /apply`, `POST /rollback`, `GET /audit` (all others need
`Authorization: Bearer <token>`).

### Dashboard

```bash
cd dashboard && npm run dev     # development
npm run build                   # production build in dist/
```

Set `VITE_API_URL` (default `http://127.0.0.1:8000`) and
`VITE_API_TOKEN` at build time, or enter the token in the app (kept
in memory only). If the API is offline, every page says so and
shows no data — the dashboard never invents statistics.

## 4. Uninstall

```bash
sudo systemctl disable --now aegis-api
sudo rm -rf /opt/aegis-x /etc/aegis-x /var/lib/aegis-x
sudo userdel aegis   # if you created it
```

Remove the firewall rules themselves (the package removal does NOT
do this automatically — deleting the binary must not silently leave
or silently drop enforcement; do it explicitly):

```bash
sudo nft delete table inet aegis        # Linux
# Windows: run tools/windows/cleanup-m4.ps1 from an Administrator
# PowerShell (deletes the AEGIS sublayer + provider from WFP).
```

## 5. Backup and restore

Back up: the API database (`AEGIS_API_DB`), the policy JSON files
you manage, and the CLI state dir (`/var/lib/aegis-x` by default).
Restore: copy them back, restart the API, then verify each stored
policy's hash and re-run `check` before any `apply`. See
`docs/TAMPER_RESISTANCE.md` for the integrity checklist.

## 6. Troubleshooting

* **`ct state` rules fail / "No such file or directory".** Your
  kernel lacks `nf_conntrack`. Use `--no-conntrack` (degraded,
  stateless mode) or a normal distro kernel. Same for `limit` rules
  if the kernel lacks `nft_limit`: userspace parses them, but the
  kernel cannot install them — see `docs/VALIDATION.md`.
* **"Operation not permitted (you must be root)" from nft.** The
  process lacks `CAP_NET_ADMIN`. Run the CLI/API with that
  capability (the systemd unit grants it) or test inside
  `unshare -Urn` (see `tests/netns/run.sh`).
* **Dashboard shows "API offline".** Start the API first
  (`uvicorn app:app --host 127.0.0.1 --port 8000` from `api/`);
  check `VITE_API_URL` matches.
* **Windows: "requires Windows" / build errors.** Expected on Linux
  (the engine is a stub there). On Windows, build from an
  Administrator PowerShell and fix `WINDOWS-BUILD-CHECK` items in
  `crates/aegis-windows/src/engine.rs`; then run
  `tools/windows/verify-m4.ps1`. Until that passes, no Windows
  enforcement claim is valid.
* **A rule with `app` fails on Linux.** Application control is
  Windows-only (WFP ALE). The Linux adapter refuses app-scoped
  rules rather than silently broadening them.
