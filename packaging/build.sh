#!/bin/bash
# Builds dist/unbraid_<version>-1_amd64.deb (Debian 13+, Ubuntu 24.04+ and their derivatives) and dist/arch/ (a
# PKGBUILD and the tree it packages, for Arch and its derivatives). The app is one native program (app/); the engine is
# built by engine/build.sh. Both packages hold the same files.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' app/Cargo.toml | head -1)
DIST=$ROOT/dist
[ -x engine/out/unbraid-engine ] || engine/build.sh
command -v cargo >/dev/null || export PATH="$HOME/.cargo/bin:$PATH"
for t in cargo-audit cargo-auditable; do
  command -v $t >/dev/null || { echo "needs $t: cargo install --locked cargo-audit@0.23.0 cargo-auditable@0.7.7"; exit 1; }
done
# Every crate in Cargo.lock against the RustSec database: an advisory not reviewed in app/.cargo/audit.toml stops the
# build, as govulncheck does for the engine. The binary then carries its crate list, for audits of what shipped.
(cd app && cargo audit --deny warnings -q && cargo auditable build --release --locked -q)
# The files both packages install, under $1.
stage() {
  local r=$1
  rm -rf "$r" && mkdir -p "$r/usr/lib/unbraid/bin" "$r/usr/bin"
  # The app is one native program; the engine recognises it by this path, so it stays where the launcher was.
  install -m755 "${CARGO_TARGET_DIR:-app/target}/release/unbraid" "$r/usr/lib/unbraid/bin/unbraid"
  install -m755 engine/out/unbraid-engine "$r/usr/lib/unbraid/unbraid-engine"
  ln -s ../lib/unbraid/bin/unbraid "$r/usr/bin/unbraid"
  install -Dm644 packaging/files/unbraid-engine.service "$r/usr/lib/systemd/system/unbraid-engine.service"
  install -Dm644 packaging/files/app.unbraid.engine.policy "$r/usr/share/polkit-1/actions/app.unbraid.engine.policy"
  install -Dm644 packaging/files/unbraid.desktop "$r/usr/share/applications/unbraid.desktop"
  install -Dm644 app/ui/unbraid.svg "$r/usr/share/icons/hicolor/scalable/apps/unbraid.svg"
  install -Dm644 app/assets/intro/intro.webm "$r/usr/share/unbraid/intro.webm"
}

rm -rf "$DIST" && mkdir -p "$DIST"

D=$DIST/deb
stage "$D"
install -Dm644 packaging/debian/copyright "$D/usr/share/doc/unbraid/copyright"
mkdir -p "$D/DEBIAN"
sed -e "s/@VERSION@/$VERSION/" -e "s/@SIZE@/$(du -sk "$D" | cut -f1)/" packaging/debian/control > "$D/DEBIAN/control"
install -m755 packaging/debian/postinst packaging/debian/prerm packaging/debian/postrm "$D/DEBIAN/"
fakeroot dpkg-deb -Zxz --build --root-owner-group "$D" "$DIST/unbraid_${VERSION}-1_amd64.deb" >/dev/null
rm -rf "$D"

A=$DIST/arch
stage "$A/stage"
install -Dm644 LICENSE "$A/stage/usr/share/licenses/unbraid/LICENSE"
tar -C "$A/stage" --owner=0 --group=0 -czf "$A/unbraid-$VERSION-x86_64.tar.gz" usr
rm -rf "$A/stage"
sed -e "s/@VERSION@/$VERSION/" -e "s/@SHA256@/$(cd "$A" && sha256sum "unbraid-$VERSION-x86_64.tar.gz" | cut -d' ' -f1)/" packaging/arch/PKGBUILD > "$A/PKGBUILD"
cp packaging/arch/unbraid.install "$A/"
(cd "$DIST" && ls -l ./*.deb arch/)
