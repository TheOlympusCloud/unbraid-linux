#!/bin/bash
# Builds dist/unbraid_<version>-1_amd64.deb (Debian 13+, Ubuntu 24.04+ and their derivatives) and dist/arch/ (a
# PKGBUILD and the tree it packages, for Arch and its derivatives). The app runs on the distribution's own Java (17 or
# later); the engine is built by engine/build.sh. Both packages hold the same files.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VERSION=$(sed -n 's/^val versionName = "\(.*\)"/\1/p' app/build.gradle.kts)
DIST=$ROOT/dist
IMAGE=app/build/compose/binaries/main/app/unbraid
[ -x engine/out/unbraid-engine ] || engine/build.sh
./gradlew -q :app:createDistributable

# The files both packages install, under $1; the app's Java is the distribution's, at $2.
stage() {
  local r=$1
  rm -rf "$r" && mkdir -p "$r/usr/lib/unbraid" "$r/usr/bin"
  cp -a "$IMAGE/bin" "$IMAGE/lib" "$r/usr/lib/unbraid/"
  rm -rf "$r/usr/lib/unbraid/lib/runtime"
  ln -s "$2" "$r/usr/lib/unbraid/lib/runtime"
  # Native code for other systems and processors, and gRPC's TLS (the engine's socket is local): about 16 MB.
  python3 -I - "$r"/usr/lib/unbraid/lib/app/{sqlite-jdbc,grpc-netty-shaded}-*.jar <<'PY'
import re, sys, zipfile
drop = re.compile(r"org/sqlite/native/(?!Linux/x86_64/).+|META-INF/native/.*(tcnative|aarch_64).*")
for jar in sys.argv[1:]:
    entries = [(i, zipfile.ZipFile(jar).read(i)) for i in zipfile.ZipFile(jar).infolist() if not drop.fullmatch(i.filename)]
    with zipfile.ZipFile(jar, "w", zipfile.ZIP_DEFLATED) as out:
        for i, data in entries: out.writestr(i, data)
PY
  install -m755 engine/out/unbraid-engine "$r/usr/lib/unbraid/unbraid-engine"
  ln -s ../lib/unbraid/bin/unbraid "$r/usr/bin/unbraid"
  install -Dm644 packaging/files/unbraid-engine.service "$r/usr/lib/systemd/system/unbraid-engine.service"
  install -Dm644 packaging/files/app.unbraid.engine.policy "$r/usr/share/polkit-1/actions/app.unbraid.engine.policy"
  install -Dm644 packaging/files/unbraid.desktop "$r/usr/share/applications/unbraid.desktop"
  install -Dm644 app/src/main/resources/unbraid.svg "$r/usr/share/icons/hicolor/scalable/apps/unbraid.svg"
}

rm -rf "$DIST" && mkdir -p "$DIST"

D=$DIST/deb
stage "$D" /usr/lib/jvm/default-java
install -Dm644 packaging/debian/copyright "$D/usr/share/doc/unbraid/copyright"
mkdir -p "$D/DEBIAN"
sed -e "s/@VERSION@/$VERSION/" -e "s/@SIZE@/$(du -sk "$D" | cut -f1)/" packaging/debian/control > "$D/DEBIAN/control"
install -m755 packaging/debian/postinst packaging/debian/prerm packaging/debian/postrm "$D/DEBIAN/"
fakeroot dpkg-deb -Zxz --build --root-owner-group "$D" "$DIST/unbraid_${VERSION}-1_amd64.deb" >/dev/null
rm -rf "$D"

A=$DIST/arch
stage "$A/stage" /usr/lib/jvm/java-21-openjdk
install -Dm644 LICENSE "$A/stage/usr/share/licenses/unbraid/LICENSE"
tar -C "$A/stage" --owner=0 --group=0 -czf "$A/unbraid-$VERSION-x86_64.tar.gz" usr
rm -rf "$A/stage"
sed -e "s/@VERSION@/$VERSION/" -e "s/@SHA256@/$(cd "$A" && sha256sum "unbraid-$VERSION-x86_64.tar.gz" | cut -d' ' -f1)/" packaging/arch/PKGBUILD > "$A/PKGBUILD"
cp packaging/arch/unbraid.install "$A/"
(cd "$DIST" && ls -l ./*.deb arch/)
