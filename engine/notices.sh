#!/bin/bash
# Writes app/notices.txt: every licence the app and its engine must carry. Run after engine/build.sh (it does).
# Go modules are the ones actually linked into the engine, for the same build tags; Rust crates the ones linked into
# the app (not build tools, proc macros or test crates).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SB=${WORK:-$HOME/.cache/unbraid-engine}/sing-box
TAGS=$(sed -n 's/^TAGS=\(.*\)/\1/p' "$ROOT/engine/build.sh")
export GOTOOLCHAIN=go1.26.11 GOFLAGS=-mod=mod
command -v cargo >/dev/null || export PATH="$HOME/.cargo/bin:$PATH"
OUT="$ROOT/app/notices.txt"
licence() { find "$1" -maxdepth 1 -type f -iregex '.*/\(licen[cs]e\|copying\)[^/]*' -printf '%f\n' | sort | head -1; }
# A plain Apache-2.0 text is printed once, at the end; a longer file (extra licences appended) is kept whole.
show() { if grep -q "Version 2.0, January 2004" "$1" && [ "$(wc -c < "$1")" -lt 11800 ]; then echo "Licensed under the Apache License, Version 2.0 (full text at the end)."; else cat "$1"; fi; }
deps() { (cd "$SB" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go list -tags "$TAGS" -deps -f "$1" ./experimental/boxdd) | sort -u; }
PKGS=$(mktemp); META=$(mktemp); CRATES=$(mktemp); trap 'rm -f "$PKGS" "$META" "$CRATES"' EXIT
deps '{{.Dir}}' > "$PKGS" # folders of the packages actually linked
rust() {
  local doc; doc="$(rustc --print sysroot)/share/doc/rust/licenses"
  echo; echo "=== Rust standard library $(rustc --version | cut -d' ' -f2)"
  echo "Copyright The Rust Project Developers. Licensed under the Apache License, Version 2.0 (full text at the end) or the MIT License:"
  cat "$doc/MIT.txt"; echo; echo "--- Its Unicode tables"; cat "$doc/Unicode-3.0.txt"
  (cd "$ROOT/app" && cargo metadata -q --format-version 1 --locked --offline --filter-platform x86_64-unknown-linux-gnu > "$META" &&
    cargo tree -q --locked --offline -e normal,no-proc-macro --target x86_64-unknown-linux-gnu --prefix none -f '{p}' | sed 's/ (.*//' | sort -u > "$CRATES")
  python3 -I - "$META" "$CRATES" <<'PY'
import json, os, re, sys
packages = {(p["name"], "v" + p["version"]): p for p in json.load(open(sys.argv[1]))["packages"]}
def show(f):
    t = open(f, encoding="utf-8", errors="replace").read().rstrip()
    return "Licensed under the Apache License, Version 2.0 (full text at the end)." if "Version 2.0, January 2004" in t and len(t) < 11800 else t
for name, version in sorted(tuple(l.split()) for l in open(sys.argv[2]) if l.strip()):
    p = packages[(name, version)]
    if p["source"] is None:
        continue  # the app itself, at the start
    lic, d = p.get("license") or "see below", os.path.dirname(p["manifest_path"])
    files = sorted(f for f in os.listdir(d) if re.match(r"(?i)(licen[cs]e|copying|notice|copyright)", f) and os.path.isfile(os.path.join(d, f)))
    print(f"\n=== {name} {version[1:]}")
    if "GPL-3.0" in lic:
        print(f"{lic}: used under the GNU GPL v3.0, as unbraid (its text is at the start).")
        continue
    print(f"Licence: {lic}" + ("" if files else " (the crate carries no licence file)."))
    for f in files:
        if len(files) > 1:
            print(f"--- {f}")
        print(show(os.path.join(d, f)))
PY
}
{
  echo "=== unbraid"
  echo "Copyright (C) 2026 the unbraid authors. GNU General Public License v3.0 or later:"
  cat "$ROOT/LICENSE"
  for f in "$ROOT"/engine/notices/*.txt; do [ "${f##*/}" = apache-2.0.txt ] || { echo; cat "$f"; }; done
  rust
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
