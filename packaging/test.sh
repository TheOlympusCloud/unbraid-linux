#!/bin/bash
# Installs, runs and removes the packages packaging/build.sh made, in clean Debian 13, Ubuntu 24.04 and Arch root
# filesystems (official images, packaging/rootfs.py), with each distribution's own tools and repositories. Unprivileged:
# bubblewrap gives a fake root. The window is shown on the X display $DISPLAY (an Xvfb is fine) and screenshotted into
# dist/test/. A live tunnel needs a real machine (no TUN device here); everything up to it is checked. The Arch package
# makepkg builds there is kept in dist/.
#
# Debian 12 must refuse the package: its C library is older than the app needs (glibc 2.39).
#
# usage: packaging/test.sh [debian-12|debian-13|ubuntu-24.04|archlinux]...    (default: all four)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DIST=$ROOT/dist
CACHE=${CACHE:-$HOME/.cache/unbraid-rootfs}
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/app/Cargo.toml" | head -1)
PKGREL=$(sed -n 's/^PKGREL=//p' "$ROOT/packaging/build.sh")
OUT=$DIST/test
mkdir -p "$OUT" "$CACHE"
: "${DISPLAY:?set DISPLAY to an X server (e.g. Xvfb :99) for the window check}"
X11=/tmp/.X11-unix

# A fresh copy of the image's root filesystem for each run.
fresh() {
    local name=$1 image=$2
    [ -d "$CACHE/$name.orig" ] || python3 -I "$ROOT/packaging/rootfs.py" "$image" "$CACHE/$name.orig" >/dev/null
    rm -rf "${CACHE:?}/$name" && cp -a "$CACHE/$name.orig" "$CACHE/$name"
    rm -f "$CACHE/$name/etc/resolv.conf" && touch "$CACHE/$name/etc/resolv.conf"
}

# Runs a shell command in the root filesystem $1 as root (or as uid $UID_IN), sharing this computer's network.
run() {
    local root=$1; shift
    bwrap --bind "$root" / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /run --ro-bind /etc/resolv.conf /etc/resolv.conf \
        --bind "$DIST" /dist --bind "$X11" "$X11" --unshare-user --uid "${UID_IN:-0}" --gid "${UID_IN:-0}" --unshare-pid --unshare-ipc \
        --die-with-parent --clearenv --setenv HOME "${HOME_IN:-/root}" --setenv DISPLAY "$DISPLAY" --setenv DEBIAN_FRONTEND noninteractive \
        --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /bin/bash -ec "$*"
}

# What every installed package must hold and do. The engine runs as root in the sandbox and makes its socket; the window
# opens and is screenshotted.
check() {
    local name=$1 root=$CACHE/$1
    # shellcheck disable=SC2016 # expanded inside the sandbox
    run "$root" '
        for f in /usr/bin/unbraid /usr/lib/unbraid/unbraid-engine /usr/lib/systemd/system/unbraid-engine.service \
                 /usr/share/polkit-1/actions/app.unbraid.engine.policy /usr/share/applications/unbraid.desktop \
                 /usr/share/icons/hicolor/scalable/apps/unbraid.svg /usr/share/unbraid/intro.webm; do test -e "$f" || { echo "missing $f"; exit 1; }; done
        # Every library the app links is installed: the dependencies of the package cover it.
        ! ldd /usr/lib/unbraid/bin/unbraid | grep "not found" || { echo "the app misses a library"; exit 1; }
        echo "libraries: complete"
        unbraid --version
        /usr/lib/unbraid/unbraid-engine version | head -1
        mkdir -p /var/lib/unbraid-engine /run/unbraid-engine && chmod 700 /var/lib/unbraid-engine
        /usr/lib/unbraid/unbraid-engine run --working-directory /var/lib/unbraid-engine --socket /run/unbraid-engine/engine.sock >/tmp/engine.log 2>&1 &
        for _ in $(seq 50); do [ -S /run/unbraid-engine/engine.sock ] && break; sleep 0.2; done
        test -S /run/unbraid-engine/engine.sock || { cat /tmp/engine.log; exit 1; }
        echo "engine: listening"
        mkdir -p /tmp/run && chmod 700 /tmp/run
        XDG_RUNTIME_DIR=/tmp/run timeout 40 unbraid >/tmp/app.log 2>&1 &
        app=$!
        for _ in $(seq 60); do [ -S /tmp/run/unbraid/app.sock ] && break; sleep 0.5; done
        test -S /tmp/run/unbraid/app.sock || { cat /tmp/app.log; exit 1; }
        # The engine sends the app itself direct by its program: that must be the app itself, never a shared interpreter.
        exe=$(readlink "/proc/$(cut -d" " -f1 "/proc/$app/task/$app/children")/exe")
        [ "$exe" = /usr/lib/unbraid/bin/unbraid ] || { echo "the app runs as $exe"; exit 1; }
        echo "app: $exe"
        sleep 8
        XDG_RUNTIME_DIR=/tmp/run unbraid status
        echo "window: up"
        touch /dist/test/'"$name"'.up
        sleep 25
    ' > "$OUT/$name.log" 2>&1 &
    local pid=$!
    for _ in $(seq 240); do [ -e "$OUT/$name.up" ] && break; kill -0 $pid 2>/dev/null || break; sleep 1; done
    if [ -e "$OUT/$name.up" ]; then import -window root "$OUT/$name.png"; fi
    wait $pid || { echo "FAIL $name"; cat "$OUT/$name.log"; return 1; }
    rm -f "$OUT/$name.up"
}

debian() {
    local name=$1 image=$2 root=$CACHE/$1
    fresh "$name" "$image"
    # One mapped id only: apt fetches as root, and file owners other than root can't be set, which dpkg-statoverride
    # does for dbus (a dependency of the desktop libraries). In this throwaway root it does nothing; unbraid sets none.
    run "$root" "dpkg-divert --local --rename --add /usr/bin/dpkg-statoverride >/dev/null 2>&1; printf '#!/bin/sh\\nexit 0\\n' > /usr/bin/dpkg-statoverride; chmod 755 /usr/bin/dpkg-statoverride
        apt-get -o APT::Sandbox::User=root -qq update
        # Other scripts that give files to a non-root group (fontconfig's /usr/local/share/fonts) fail here once: configured
        # again, every package must end up configured, which dpkg --audit checks.
        apt-get -o APT::Sandbox::User=root -y -qq install --no-install-recommends /dist/unbraid_${VERSION}-${PKGREL}_amd64.deb >/tmp/apt.log 2>&1 \\
            || { grep -h 'Invalid argument' /tmp/apt.log | sed 's/^/sandbox: /'; dpkg --configure -a >>/tmp/apt.log 2>&1 || true; }
        test -z \"\$(dpkg --audit)\" || { dpkg --audit; tail -40 /tmp/apt.log; exit 1; }
        dpkg -s unbraid | grep -E '^(Status|Version)'
        # The recommended packages exist there (installed on a desktop anyway).
        for p in libsecret-tools libnotify-bin; do apt-cache show \$p >/dev/null || { echo \"no \$p\"; exit 1; }; done
        apt-cache show polkitd >/dev/null || apt-cache show policykit-1 >/dev/null" > "$OUT/$name-install.log" 2>&1 || { cat "$OUT/$name-install.log"; return 1; }
    check "$name"
    run "$root" "apt-get -o APT::Sandbox::User=root -y -qq purge unbraid >/dev/null && ! test -e /usr/lib/unbraid && ! test -e /usr/bin/unbraid && ! test -e /var/lib/unbraid-engine && ! dpkg -s unbraid >/dev/null 2>&1 && echo removed" > "$OUT/$name-remove.log" 2>&1 \
        || { cat "$OUT/$name-remove.log"; return 1; }
    echo "PASS $name: $(grep -h -E '^(Version|libraries|unbraid|engine|app|window|removed)' "$OUT/$name-install.log" "$OUT/$name.log" "$OUT/$name-remove.log" | tr '\n' ';')"
}

# A release too old for the app: apt must refuse the package over its C library, never install a broken one.
refused() {
    local name=$1 image=$2 root=$CACHE/$1
    fresh "$name" "$image"
    if ! run "$root" "apt-get -o APT::Sandbox::User=root -qq update && ! apt-get -o APT::Sandbox::User=root -y install --no-install-recommends /dist/unbraid_${VERSION}-${PKGREL}_amd64.deb >/tmp/apt.log 2>&1
        grep -h 'libc6 (>= 2.39)' /tmp/apt.log | head -1; ! dpkg -s unbraid >/dev/null 2>&1" > "$OUT/$name-install.log" 2>&1 \
        || ! grep -q 'libc6' "$OUT/$name-install.log"; then
        echo "FAIL $name: not refused"; cat "$OUT/$name-install.log"; return 1
    fi
    echo "PASS $name: refused ($(head -1 "$OUT/$name-install.log" | sed 's/^ *//'))"
}

arch() {
    local name=archlinux root=$CACHE/archlinux
    fresh "$name" archlinux:latest
    # pacman's download user and sandbox need more than one mapped id.
    sed -i 's/^DownloadUser/#DownloadUser/; s/^#DisableSandbox/DisableSandbox/' "$root/etc/pacman.conf"
    grep -q '^DisableSandbox' "$root/etc/pacman.conf" || sed -i 's/^\[options\]/[options]\nDisableSandbox/' "$root/etc/pacman.conf"
    echo 'builder:x:1000:1000::/build:/bin/bash' >> "$root/etc/passwd"
    rm -rf "$root/build" && cp -a "$DIST/arch" "$root/build"
    run "$root" "pacman-key --init >/dev/null 2>&1; pacman-key --populate archlinux >/dev/null 2>&1; pacman -Sy --noconfirm --needed fakeroot >/tmp/p.log 2>&1 || { tail -20 /tmp/p.log; exit 1; }" > "$OUT/$name-install.log" 2>&1 \
        || { cat "$OUT/$name-install.log"; return 1; }
    # makepkg as an ordinary user, then pacman installs the package and pulls its dependencies from the repositories.
    UID_IN=1000 HOME_IN=/build run "$root" "cd /build && makepkg -d --noconfirm >/tmp/makepkg.log 2>&1 || { tail -30 /tmp/makepkg.log; exit 1; }; ls /build/*.pkg.tar.zst" >> "$OUT/$name-install.log" 2>&1 \
        || { cat "$OUT/$name-install.log"; return 1; }
    cp "$root/build/unbraid-${VERSION}-${PKGREL}-x86_64.pkg.tar.zst" "$DIST/"
    run "$root" "pacman -U --noconfirm /build/unbraid-${VERSION}-${PKGREL}-x86_64.pkg.tar.zst >/tmp/u.log 2>&1 || { tail -30 /tmp/u.log; exit 1; }; grep -A1 -i 'post_install\|unbraid connects' /tmp/u.log | head -3; pacman -Q unbraid" >> "$OUT/$name-install.log" 2>&1 \
        || { cat "$OUT/$name-install.log"; return 1; }
    check "$name"
    run "$root" "pacman -R --noconfirm unbraid >/dev/null 2>&1 && ! test -e /usr/lib/unbraid && ! test -e /usr/bin/unbraid && ! pacman -Q unbraid >/dev/null 2>&1 && echo removed" > "$OUT/$name-remove.log" 2>&1 \
        || { cat "$OUT/$name-remove.log"; return 1; }
    echo "PASS $name: $(grep -h -E '^(unbraid [0-9]|libraries|engine|app|window|removed)' "$OUT/$name-install.log" "$OUT/$name.log" "$OUT/$name-remove.log" | tr '\n' ';')"
}

for target in "${@:-debian-12 debian-13 ubuntu-24.04 archlinux}"; do
    for t in $target; do
        case $t in
            debian-12) refused debian-12 debian:12 ;;
            debian-13) debian debian-13 debian:13 ;;
            ubuntu-24.04) debian ubuntu-24.04 ubuntu:24.04 ;;
            archlinux) arch ;;
            *) echo "unknown target $t"; exit 2 ;;
        esac
    done
done
