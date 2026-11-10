#!/bin/bash
# Writes app/src/main/resources/notices.txt: every licence the app must carry. Run after engine/build.sh (it does).
# Go modules are the ones actually linked into the engine, for the same build tags.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SB=${WORK:-$HOME/.cache/unbraid-engine}/sing-box
TAGS=$(sed -n 's/^TAGS=\(.*\)/\1/p' "$ROOT/engine/build.sh")
export GOTOOLCHAIN=go1.26.10 GOFLAGS=-mod=mod
OUT="$ROOT/app/src/main/resources/notices.txt"
licence() { find "$1" -maxdepth 1 -type f -iregex '.*/\(licen[cs]e\|copying\)[^/]*' -printf '%f\n' | sort | head -1; }
# A plain Apache-2.0 text is printed once, at the end; a longer file (extra licences appended) is kept whole.
show() { if grep -q "Version 2.0, January 2004" "$1" && [ "$(wc -c < "$1")" -lt 11800 ]; then echo "Licensed under the Apache License, Version 2.0 (full text at the end)."; else cat "$1"; fi; }
deps() { (cd "$SB" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go list -tags "$TAGS" -deps -f "$1" ./experimental/boxdd) | sort -u; }
PKGS=$(mktemp); trap 'rm -f "$PKGS"' EXIT
deps '{{.Dir}}' > "$PKGS" # folders of the packages actually linked
{
  echo "=== unbraid"
  echo "Copyright (C) 2026 the unbraid authors. GNU General Public License v3.0 or later:"
  cat "$ROOT/LICENSE"
  for f in "$ROOT"/engine/notices/*.txt; do [ "${f##*/}" = apache-2.0.txt ] || { echo; cat "$f"; }; done
  echo; echo "=== Go standard library and runtime"; cat "$(cd "$SB" && go env GOROOT)/LICENSE"
  deps '{{with .Module}}{{.Path}} {{or .Version "-"}} {{.Dir}}{{end}}' | while read -r p v d; do
      [ "$v" = - ] && v= # the main module (sing-box) has no version
      echo; echo "=== $p${v:+ $v}"
      show "$d/$(licence "$d")"
      # NOTICE/COPYRIGHT files, and the licences in subfolders that hold (or sit above) linked code.
      { find "$d" -maxdepth 1 -type f \( -iname 'NOTICE*' -o -iname 'COPYRIGHT*' \)
        find "$d" -mindepth 2 -type f \( -iname 'LICEN[CS]E*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) ! -name '*.go' ! -path '*/.github/*' ! -path '*/testdata/*'
      } | sort | while read -r n; do grep -q "^${n%/*}\(/\|$\)" "$PKGS" || continue; echo; echo "--- ${n#"$d"/}"; show "$n"; done
    done
  echo; echo "=== Apache License 2.0"; cat "$ROOT/engine/notices/apache-2.0.txt"
} > "$OUT"
echo "$(grep -c '^=== ' "$OUT") notices, $(wc -c < "$OUT") bytes in ${OUT#"$ROOT"/}"
