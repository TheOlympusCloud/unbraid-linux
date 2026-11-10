#!/bin/bash
# Reproducible build of engine/out/unbraid-engine: sing-box v1.14.4's Linux daemon (experimental/boxdd) with unbraid's
# patches, the same build tags as the Android engine, and the daemon renamed so it never collides with a stock one.
# `engine/build.sh test` also runs the tests the patches bring, and builds the CLI the upstream unit tests check configs with.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
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
# go1.26.10: the toolchain sing-box builds 1.14.4 with upstream (and the Android engine uses).
export GOTOOLCHAIN=go1.26.10 CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH
TAGS=with_gvisor,with_wireguard,with_utls,with_tailscale,ts_omit_logtail,ts_omit_cachenetmap,ts_omit_ssh,ts_omit_drive,ts_omit_taildrop,ts_omit_webclient,ts_omit_doctor,ts_omit_capture,ts_omit_kube,ts_omit_aws,ts_omit_synology,ts_omit_bird,with_openvpn,badlinkname,tfogo_checklinkname0
if [ "${1:-}" = test ]; then
  go test -tags "$TAGS" -ldflags "-checklinkname=0" ./daemon/ ./protocol/openvpn/ ./protocol/tailscale/ -run 'STUN|Resolver|Fallback|Taildrop'
  # The upstream unit tests' own `sing-box check` (KeyProvidersTest): the same patched engine as a plain CLI, never shipped.
  go build -o "$ROOT/engine/out/sing-box-cli" -trimpath -buildvcs=false -tags "$TAGS" -ldflags "-checklinkname=0 -s -w" ./cmd/sing-box
fi
mkdir -p "$ROOT/engine/out"
# Built beside the real binary and swapped only on success.
go build -o "$ROOT/engine/out/unbraid-engine.new" -trimpath -buildvcs=false -tags "$TAGS" \
  -ldflags "-X github.com/sagernet/sing-box/constant.Version=1.14.4 -X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0 -s -w -buildid=" \
  ./experimental/boxdd
mv "$ROOT/engine/out/unbraid-engine.new" "$ROOT/engine/out/unbraid-engine"
(cd "$ROOT/engine/out" && sha256sum unbraid-engine > unbraid-engine.sha256 && cat unbraid-engine.sha256)
"$ROOT/engine/notices.sh"
