#!/usr/bin/env bash
# Assemble a Linux .deb skeleton for AEGIS X (M8).
#
# HONEST SCOPE: this builds a REAL .deb from REAL files (release Rust
# binaries, the API tree, the dashboard build, the systemd unit) — but
# it is a skeleton package, not a release: it is UNSIGNED (signing
# needs the operator's GPG key; see the note at the end), the version
# is 0.1.0, and the maintainer field is a placeholder. Do not
# distribute it as a release.
#
# Usage: ./packaging/deb/build-deb.sh [output-dir]
# Requires: cargo, python3 -m venv + pip, node/npm, dpkg-deb.
# Produces: <output-dir>/aegis-x_0.1.0_amd64.deb
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-$ROOT/packaging/deb/out}"
PKG="$OUT/aegis-x_0.1.0_amd64"
rm -rf "$PKG"
mkdir -p "$PKG/DEBIAN" "$PKG/opt/aegis-x" "$PKG/etc/systemd/system" "$PKG/var/lib/aegis-x"

export PATH="$HOME/.cargo/bin:$PATH"
echo "== Rust release build =="
cargo build --release --manifest-path "$ROOT/Cargo.toml"
cp "$ROOT/target/release/aegis-linux" "$PKG/opt/aegis-x/"
cp "$ROOT/target/release/aegis-win" "$PKG/opt/aegis-x/" 2>/dev/null || true
# NOTE: aegis-win on Linux is the stub binary (reports "Windows only").
# It is included only so the file layout is complete; it enforces
# nothing on Linux. The Windows build produces the real binary.

echo "== API tree =="
mkdir -p "$PKG/opt/aegis-x/api"
cp "$ROOT/api/app.py" "$ROOT/api/README.md" "$PKG/opt/aegis-x/api/"
# The venv is NOT packaged: install it on the target host with
#   python3 -m venv /opt/aegis-x/api/.venv && /opt/aegis-x/api/.venv/bin/pip install fastapi uvicorn httpx
# (see docs/ADMIN_GUIDE.md). Packaging a venv would bake in absolute paths.

echo "== Dashboard build =="
if [ ! -d "$ROOT/dashboard/dist" ]; then
  (cd "$ROOT/dashboard" && npm install && npm run build)
fi
cp -r "$ROOT/dashboard/dist" "$PKG/opt/aegis-x/dashboard/"

echo "== systemd unit + docs =="
cp "$ROOT/packaging/systemd/aegis-api.service" "$PKG/etc/systemd/system/"
cp "$ROOT/docs/ADMIN_GUIDE.md" "$ROOT/docs/VALIDATION.md" "$PKG/opt/aegis-x/" 2>/dev/null || true
cp "$ROOT/packaging/deb/DEBIAN/control" "$PKG/DEBIAN/control"

echo "== Normalize permissions (sandbox umask produces 2770/660) =="
find "$PKG" -type d -exec chmod 755 {} +
find "$PKG" -type f -exec chmod 644 {} +
chmod 755 "$PKG/opt/aegis-x/aegis-linux" "$PKG/opt/aegis-x/aegis-win"

echo "== Build .deb (UNSIGNED — see below) =="
# dpkg-deb requires the control dir at 0755-0775; the sandbox umask
# can produce 2770, which it rejects.
chmod 755 "$PKG/DEBIAN"
dpkg-deb --build "$PKG" "$OUT/aegis-x_0.1.0_amd64.deb"
dpkg-deb --info "$OUT/aegis-x_0.1.0_amd64.deb"
echo "Built: $OUT/aegis-x_0.1.0_amd64.deb"
echo "SIGNING: this package is unsigned. To sign it, use your own GPG key:"
echo "  dpkg-sig --sign builder $OUT/aegis-x_0.1.0_amd64.deb"
echo "Never fake a signature or a maintainer identity."
