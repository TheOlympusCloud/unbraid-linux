#!/bin/bash
# Reproducible build of engine/out/unbraid-engine: sing-box v1.14.4's Linux daemon (experimental/boxdd) with unbraid's
# patches, the same build tags as the Android engine, and the daemon renamed so it never collides with a stock one.
# `engine/build.sh test` also runs the tests the patches bring, and builds the CLI the upstream unit tests check configs with.
# `engine/build.sh source FILE.tar.xz` writes the engine's complete source for a release instead (below).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# The source tarball's path, as given from where the script started.
[ "${1:-}" != source ] || OUT=$(realpath -m "${2:?usage: engine/build.sh source FILE.tar.xz}")
WORK=${WORK:-$HOME/.cache/unbraid-engine}
ARCH=${GOARCH:-amd64}
mkdir -p "$WORK" && cd "$WORK"
[ -d sing-box ] || git clone -q --depth 1 --branch v1.14.4 https://github.com/SagerNet/sing-box.git
cd sing-box
# Pinned: v1.14.4 = c005f35300ce76427dc285481ec5695f5b179cd2. A checkout left by an older pin moves to it.
PIN=c005f35300ce76427dc285481ec5695f5b179cd2
[ "$(git rev-parse HEAD)" = $PIN ] || git fetch -q --depth 1 origin tag v1.14.4
git checkout -q -f $PIN && git clean -qfd
[ "$(git rev-parse HEAD)" = $PIN ] || { echo "sing-box checkout is not v1.14.4"; exit 1; }
git apply "$ROOT"/engine/patches/sing-box-*.patch
# go1.26.11: upstream builds 1.14.4 with go1.26.10; .11 carries the standard library's fix for GO-2026-6859 (net/http).
export GOTOOLCHAIN=go1.26.11 CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH
TAGS=with_gvisor,with_wireguard,with_utls,with_tailscale,ts_omit_logtail,ts_omit_cachenetmap,ts_omit_ssh,ts_omit_drive,ts_omit_taildrop,ts_omit_webclient,ts_omit_doctor,ts_omit_capture,ts_omit_kube,ts_omit_aws,ts_omit_synology,ts_omit_bird,with_openvpn,badlinkname,tfogo_checklinkname0
LDFLAGS="-X github.com/sagernet/sing-box/constant.Version=1.14.4 -X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0 -s -w -buildid="
if [ "${1:-}" = source ]; then
  # The patched tree with every Go module it builds with (`go mod vendor`), so a release's source builds without
  # SagerNet's GitHub or the Go module proxy. Made apart from this checkout: a vendor/ here would change its builds.
  NAME=$(basename "$OUT" .tar.xz)
  S=$WORK/source/$NAME
  rm -rf "$WORK/source" && mkdir -p "$S/unbraid-patches"
  git archive $PIN | tar -xf - -C "$S"
  # Left out: cronet-go, Chromium's network stack as prebuilt libraries for 29 platforms (1.6 GB), which only the naive
  # outbound uses. The engine is built without it, and the check below fails if that changes.
  (cd "$S" && git apply "$ROOT"/engine/patches/sing-box-*.patch && go mod vendor && rm -r vendor/github.com/sagernet/cronet-go)
  cp "$ROOT"/engine/patches/sing-box-*.patch "$S/unbraid-patches/"
  cat > "$S/UNBRAID.md" <<END
# unbraid's engine, its complete source

The source of \`unbraid-engine\`, the system service of unbraid for Linux
(https://github.com/TheOlympusCloud/unbraid-linux), from that repository's commit
$(git -C "$ROOT" rev-parse HEAD).

It is sing-box v1.14.4 (https://github.com/SagerNet/sing-box, commit $PIN), modified by
unbraid on $(git -C "$ROOT" log -1 --format=%cs): the patches in \`unbraid-patches/\` are applied here.
\`vendor/\` holds every Go module it builds with, so it builds without a network. It leaves out cronet-go, prebuilt
libraries that only sing-box's naive outbound uses: this engine is built without that outbound. With Go 1.26.11:

    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-mod=vendor go build -trimpath -buildvcs=false \\
      -tags "$TAGS" \\
      -ldflags "$LDFLAGS" \\
      -o unbraid-engine ./experimental/boxdd

That engine links the same modules, at the same versions, as the released one, but isn't byte-identical to it: in
vendor mode Go leaves the modules' checksums (\`h1:\`) out of the build info it embeds, so the file is about 8 KB smaller.

sing-box is licensed under the GNU General Public License, version 3 or later (\`LICENSE\`). Each module in
\`vendor/\` comes with its own licence.
END
  tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$(git -C "$ROOT" log -1 --format=%ct)" \
    -C "$WORK/source" -cf - "$NAME" | xz -T1 > "$OUT.new"
  # The check: unpacked, it builds offline, with the same module versions as the engine in engine/out.
  mkdir "$WORK/source/check" && tar -xJf "$OUT.new" -C "$WORK/source/check"
  (cd "$WORK/source/check/$NAME" && GOFLAGS=-mod=vendor GOPROXY=off go build -o "$WORK/source/engine" -trimpath \
    -buildvcs=false -tags "$TAGS" -ldflags "$LDFLAGS" ./experimental/boxdd)
  mods() { go version -m "$1" | awk '$1 == "dep" || $1 == "=>" { print $2, $3 }'; }
  [ ! -x "$ROOT/engine/out/unbraid-engine" ] || diff <(mods "$ROOT/engine/out/unbraid-engine") <(mods "$WORK/source/engine")
  mv "$OUT.new" "$OUT" && rm -rf "$WORK/source"
  ls -l "$OUT"
  exit 0
fi
if [ "${1:-}" = test ]; then
  go test -tags "$TAGS" -ldflags "-checklinkname=0" ./daemon/ ./protocol/openvpn/ ./protocol/tailscale/ ./experimental/boxdd/ ./dns/transport/local/ -run 'STUN|Resolver|Fallback|Unbraid|LinuxPeer'
  # The upstream unit tests' own `sing-box check` (KeyProvidersTest): the same patched engine as a plain CLI, never shipped.
  go build -o "$ROOT/engine/out/sing-box-cli" -trimpath -buildvcs=false -tags "$TAGS" -ldflags "-checklinkname=0 -s -w" ./cmd/sing-box
fi
mkdir -p "$ROOT/engine/out"
# Built beside the real binary and swapped only on success.
go build -o "$ROOT/engine/out/unbraid-engine.new" -trimpath -buildvcs=false -tags "$TAGS" -ldflags "$LDFLAGS" \
  ./experimental/boxdd
# No known vulnerability the engine's code can reach (Go's own database): the build stops on one. Source mode, which
# follows calls; binary mode also flags packages the engine doesn't link (x/crypto's openpgp).
GOBIN="$WORK/bin" GOOS='' GOARCH='' go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
"$WORK/bin/govulncheck" -tags "$TAGS" ./experimental/boxdd
mv "$ROOT/engine/out/unbraid-engine.new" "$ROOT/engine/out/unbraid-engine"
(cd "$ROOT/engine/out" && sha256sum unbraid-engine > unbraid-engine.sha256 && cat unbraid-engine.sha256)
"$ROOT/engine/notices.sh"
