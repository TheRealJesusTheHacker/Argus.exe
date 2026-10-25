#!/usr/bin/env bash
# Build Argus.deb — the Linux edition's installer (v1.2.0+).
#
# The .deb IS the installer on Debian-based systems (Kali Linux,
# Parrot OS, Debian, Ubuntu): it carries the PyInstaller-built
# program, the systemd unit, the desktop entry and icon, and the
# maintainer scripts (packaging/linux/debian/) that create the
# data tree, record the program's fingerprint, and enable +
# start the protection service.
#
# Run from anywhere:  bash packaging/linux/build-deb.sh
# Requires: python3, PyInstaller (installed hash-verified from
# packaging/requirements-ci-linux.lock.txt), dpkg-deb.
# Output: dist/Argus.deb
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG_DIR="$ROOT/packaging/linux"
cd "$ROOT"

command -v dpkg-deb >/dev/null 2>&1 || {
    echo "build-deb: dpkg-deb not found (install the dpkg-dev package)." >&2
    exit 1
}
command -v pyinstaller >/dev/null 2>&1 || {
    echo "build-deb: pyinstaller not found" \
         "(pip install --require-hashes -r packaging/requirements-ci-linux.lock.txt)." >&2
    exit 1
}

VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' argus/__init__.py)"
if [ -z "$VERSION" ]; then
    echo "build-deb: could not read __version__ from argus/__init__.py." >&2
    exit 1
fi
echo "build-deb: building Argus $VERSION for Linux (amd64)"

# 1. The program: one PyInstaller file, the whole product.
pyinstaller packaging/linux/Argus-linux.spec --noconfirm \
    --workpath build/linux-work
test -x dist/argus || {
    echo "build-deb: PyInstaller did not produce dist/argus." >&2
    exit 1
}

# 2. Stage the package tree (FHS layout).
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
install -d "$STAGE/usr/lib/argus"
install -d "$STAGE/usr/bin"
install -d "$STAGE/usr/lib/systemd/system"
install -d "$STAGE/usr/share/applications"
install -d "$STAGE/usr/share/icons/hicolor/256x256/apps"
install -d "$STAGE/etc/argus"
install -d -m 0755 "$STAGE/var/lib/argus"
install -d -m 0700 "$STAGE/var/lib/argus/quarantine"
install -d -m 1733 "$STAGE/var/lib/argus/requests"
install -d -m 0755 "$STAGE/var/lib/argus/results"
install -d -m 0755 "$STAGE/var/lib/argus/shared"
install -d -m 0755 "$STAGE/var/lib/argus/trusted"
install -d -m 0755 "$STAGE/var/log/argus"
install -d "$STAGE/DEBIAN"

install -m 0755 dist/argus "$STAGE/usr/lib/argus/argus"
ln -s ../lib/argus/argus "$STAGE/usr/bin/argus"
install -m 0644 "$PKG_DIR/argus-protection.service" \
    "$STAGE/usr/lib/systemd/system/argus-protection.service"
install -m 0644 "$PKG_DIR/argus.desktop" \
    "$STAGE/usr/share/applications/argus.desktop"
install -m 0644 "$PKG_DIR/argus.png" \
    "$STAGE/usr/share/icons/hicolor/256x256/apps/argus.png"

# 3. Control + maintainer scripts (version substituted here —
#    the checked-in control carries @VERSION@, never a literal,
#    so it cannot drift from argus.__version__).
sed "s/@VERSION@/$VERSION/" "$PKG_DIR/debian/control" \
    > "$STAGE/DEBIAN/control"
for script in postinst prerm postrm; do
    install -m 0755 "$PKG_DIR/debian/$script" "$STAGE/DEBIAN/$script"
done

# 4. Build.
mkdir -p dist
dpkg-deb --build --root-owner-group "$STAGE" dist/Argus.deb

echo "build-deb: wrote dist/Argus.deb"
dpkg-deb -I dist/Argus.deb | sed -n '1,12p'
