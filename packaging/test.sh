#!/bin/bash
# Installs, runs and removes the packages packaging/build.sh made, in clean Debian 13, Ubuntu 24.04 and Arch root
# filesystems (official images, packaging/rootfs.py), with each distribution's own tools and repositories. Unprivileged:
# bubblewrap gives a fake root. The window is shown on the X display $DISPLAY (an Xvfb is fine) and screenshotted into
# dist/test/. A live tunnel needs a real machine (no TUN device here); everything up to it is checked.
#
# usage: packaging/test.sh [debian-13|ubuntu-24.04|archlinux]...    (default: all three)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
DIST=$ROOT/dist
CACHE=${CACHE:-$HOME/.cache/unbraid-rootfs}
VERSION=$(sed -n 's/^val versionName = "\(.*\)"/\1/p' "$ROOT/app/build.gradle.kts")
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
# opens on the distribution's own Java and is screenshotted.
check() {
    local name=$1 root=$CACHE/$1
    # shellcheck disable=SC2016 # expanded inside the sandbox
    run "$root" '
        for f in /usr/bin/unbraid /usr/lib/unbraid/unbraid-engine /usr/lib/systemd/system/unbraid-engine.service \
                 /usr/share/polkit-1/actions/app.unbraid.engine.policy /usr/share/applications/unbraid.desktop \
                 /usr/share/icons/hicolor/scalable/apps/unbraid.svg; do test -e "$f" || { echo "missing $f"; exit 1; }; done
        test -x "$(readlink -f /usr/lib/unbraid/lib/runtime)/bin/java" || { echo "no Java behind the app"; exit 1; }
        echo "java: $(readlink -f /usr/lib/unbraid/lib/runtime)"
        unbraid --version
        /usr/lib/unbraid/unbraid-engine version | head -1
        mkdir -p /var/lib/unbraid-engine /run/unbraid-engine && chmod 700 /var/lib/unbraid-engine
        /usr/lib/unbraid/unbraid-engine run --working-directory /var/lib/unbraid-engine --socket /run/unbraid-engine/engine.sock >/tmp/engine.log 2>&1 &
        for _ in $(seq 50); do [ -S /run/unbraid-engine/engine.sock ] && break; sleep 0.2; done
        test -S /run/unbraid-engine/engine.sock || { cat /tmp/engine.log; exit 1; }
        echo "engine: listening"
        mkdir -p /tmp/run && chmod 700 /tmp/run
        XDG_RUNTIME_DIR=/tmp/run timeout 40 unbraid >/tmp/app.log 2>&1 &
        for _ in $(seq 60); do [ -S /tmp/run/unbraid/app.sock ] && break; sleep 0.5; done
        test -S /tmp/run/unbraid/app.sock || { cat /tmp/app.log; exit 1; }
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
    # does for dbus (a dependency of Java's desktop half). In this throwaway root it does nothing; unbraid sets none.
    run "$root" "dpkg-divert --local --rename --add /usr/bin/dpkg-statoverride >/dev/null 2>&1; printf '#!/bin/sh\\nexit 0\\n' > /usr/bin/dpkg-statoverride; chmod 755 /usr/bin/dpkg-statoverride
        apt-get -o APT::Sandbox::User=root -qq update
        # Other scripts that give files to a non-root group (fontconfig's /usr/local/share/fonts) fail here once: configured
        # again, every package must end up configured, which dpkg --audit checks.
        apt-get -o APT::Sandbox::User=root -y -qq install --no-install-recommends /dist/unbraid_${VERSION}-1_amd64.deb >/tmp/apt.log 2>&1 \\
            || { grep -h 'Invalid argument' /tmp/apt.log | sed 's/^/sandbox: /'; dpkg --configure -a >>/tmp/apt.log 2>&1 || true; }
        test -z \"\$(dpkg --audit)\" || { dpkg --audit; tail -40 /tmp/apt.log; exit 1; }
        dpkg -s unbraid | grep -E '^(Status|Version)'
        # The recommended packages exist there (installed on a desktop anyway).
        for p in libsecret-tools libnotify-bin; do apt-cache show \$p >/dev/null || { echo \"no \$p\"; exit 1; }; done
        apt-cache show polkitd >/dev/null || apt-cache show policykit-1 >/dev/null" > "$OUT/$name-install.log" 2>&1 || { cat "$OUT/$name-install.log"; return 1; }
    check "$name"
    run "$root" "apt-get -o APT::Sandbox::User=root -y -qq purge unbraid >/dev/null && ! test -e /usr/lib/unbraid && ! test -e /usr/bin/unbraid && ! test -e /var/lib/unbraid-engine && ! dpkg -s unbraid >/dev/null 2>&1 && echo removed" > "$OUT/$name-remove.log" 2>&1 \
        || { cat "$OUT/$name-remove.log"; return 1; }
    echo "PASS $name: $(grep -h -E '^(Version|java|unbraid|engine|window|removed)' "$OUT/$name-install.log" "$OUT/$name.log" "$OUT/$name-remove.log" | tr '\n' ';')"
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
    run "$root" "pacman -U --noconfirm /build/unbraid-${VERSION}-1-x86_64.pkg.tar.zst >/tmp/u.log 2>&1 || { tail -30 /tmp/u.log; exit 1; }; grep -A1 -i 'post_install\|unbraid connects' /tmp/u.log | head -3; pacman -Q unbraid" >> "$OUT/$name-install.log" 2>&1 \
        || { cat "$OUT/$name-install.log"; return 1; }
    check "$name"
    run "$root" "pacman -R --noconfirm unbraid >/dev/null 2>&1 && ! test -e /usr/lib/unbraid && ! test -e /usr/bin/unbraid && ! pacman -Q unbraid >/dev/null 2>&1 && echo removed" > "$OUT/$name-remove.log" 2>&1 \
        || { cat "$OUT/$name-remove.log"; return 1; }
    echo "PASS $name: $(grep -h -E '^(unbraid [0-9]|java|engine|window|removed)' "$OUT/$name-install.log" "$OUT/$name.log" "$OUT/$name-remove.log" | tr '\n' ';')"
}

for target in "${@:-debian-13 ubuntu-24.04 archlinux}"; do
    for t in $target; do
        case $t in
            debian-13) debian debian-13 debian:13 ;;
            ubuntu-24.04) debian ubuntu-24.04 ubuntu:24.04 ;;
            archlinux) arch ;;
            *) echo "unknown target $t"; exit 2 ;;
        esac
    done
done
