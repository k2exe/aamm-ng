#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <aredn-target> <package-arch>" >&2
    exit 2
fi

TARGET="$1"
ARCH="$2"

case "${TARGET}:${ARCH}" in
    ath79-generic:mips_24kc | \
    ipq40xx-mikrotik:arm_cortex-a7_neon-vfpv4 | \
    ramips-mt7621:mipsel_24kc | \
    mediatek-filogic:aarch64_cortex-a53 | \
    x86-64:x86_64)
        ;;
    *)
        echo "unsupported AREDN target/architecture pair: ${TARGET}:${ARCH}" >&2
        exit 2
        ;;
esac

AREDN_REF="${AREDN_REF:-4.26.7.0}"
AREDN_COMMIT="${AREDN_COMMIT:-93ad9ea94fb2c0edd829c513305ffbaa90c07858}"

REPO_ROOT="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.."
    pwd
)"

BUILD_ROOT="${RUNNER_TEMP:-/tmp}/aamm-ng-aredn-${ARCH}"
AREDN_ROOT="${BUILD_ROOT}/aredn"
EXTRACT_ROOT="${BUILD_ROOT}/extract"
DIST_DIR="${DIST_DIR:-${REPO_ROOT}/dist}"

PACKAGE_MAKEFILE="${REPO_ROOT}/packaging/openwrt/Makefile"

PKG_VERSION="$(
    sed -n 's/^PKG_VERSION:=//p' "$PACKAGE_MAKEFILE"
)"
PKG_RELEASE="$(
    sed -n 's/^PKG_RELEASE:=//p' "$PACKAGE_MAKEFILE"
)"
PKG_SOURCE_VERSION="$(
    sed -n 's/^PKG_SOURCE_VERSION:=//p' "$PACKAGE_MAKEFILE"
)"

if [[ -z "$PKG_VERSION" ||
      -z "$PKG_RELEASE" ||
      -z "$PKG_SOURCE_VERSION" ]]; then
    echo "unable to read package metadata" >&2
    exit 1
fi

echo "=== AAMM-NG release build ==="
echo "AREDN baseline:      ${AREDN_REF}"
echo "AREDN commit:        ${AREDN_COMMIT}"
echo "AREDN target:        ${TARGET}"
echo "Package architecture:${ARCH}"
echo "Package version:     ${PKG_VERSION}-r${PKG_RELEASE}"
echo "Package source:      ${PKG_SOURCE_VERSION}"

rm -rf "$BUILD_ROOT"
mkdir -p "$BUILD_ROOT" "$DIST_DIR"

echo
echo "=== clone AREDN ${AREDN_REF} ==="
git clone \
    --depth 1 \
    --branch "$AREDN_REF" \
    https://github.com/aredn/aredn.git \
    "$AREDN_ROOT"

if [[ ! "$AREDN_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    echo "AREDN_COMMIT must be a full Git commit SHA" >&2
    exit 1
fi

actual_aredn_commit="$(
    git -C "$AREDN_ROOT" rev-parse HEAD
)"

if [[ "$actual_aredn_commit" != "$AREDN_COMMIT" ]]; then
    echo \
        "AREDN ${AREDN_REF} resolved to ${actual_aredn_commit}, expected ${AREDN_COMMIT}" \
        >&2
    exit 1
fi

echo "AREDN source identity verified."

echo
echo "=== prepare AREDN target ${TARGET} ==="
make \
    -C "$AREDN_ROOT" \
    TARGET="$TARGET" \
    prepare

echo
echo "=== stage AAMM-NG package ==="
rm -rf "$AREDN_ROOT/openwrt/package/aamm-ng"
mkdir -p "$AREDN_ROOT/openwrt/package/aamm-ng"

cp -a \
    "$REPO_ROOT/packaging/openwrt/." \
    "$AREDN_ROOT/openwrt/package/aamm-ng/"

echo
echo "=== staged package metadata ==="
grep -E \
    '^PKG_(VERSION|RELEASE|SOURCE_VERSION):=' \
    "$AREDN_ROOT/openwrt/package/aamm-ng/Makefile"

echo
echo "=== clear version-keyed AAMM-NG source cache ==="
rm -f \
    "$AREDN_ROOT/openwrt/dl/aamm-ng-${PKG_VERSION}.tar.zst"

echo
echo "=== build AAMM-NG ==="
make \
    -C "$AREDN_ROOT/openwrt" \
    package/aamm-ng/clean \
    package/aamm-ng/compile \
    V=s

APK_DIR="$AREDN_ROOT/openwrt/bin/packages/${ARCH}/base"
APK="$APK_DIR/aamm-ng-${PKG_VERSION}-r${PKG_RELEASE}.apk"

if [[ ! -f "$APK" ]]; then
    echo "expected APK not found: $APK" >&2
    find \
        "$AREDN_ROOT/openwrt/bin/packages" \
        -type f \
        -name 'aamm-ng-*.apk' \
        -print 2>/dev/null || true
    exit 1
fi

HOST_APK="$AREDN_ROOT/openwrt/staging_dir/host/bin/apk"

echo
echo "=== verify APK ==="
"$HOST_APK" \
    --allow-untrusted \
    verify \
    "$APK"

echo
echo "=== extract APK ==="
rm -rf "$EXTRACT_ROOT"
mkdir -p "$EXTRACT_ROOT"

"$HOST_APK" \
    --allow-untrusted \
    extract \
    --no-chown \
    --destination "$EXTRACT_ROOT" \
    "$APK"

echo
echo "=== verify packaged runtime ==="

test -x "$EXTRACT_ROOT/usr/sbin/aamm-ng"
test -x "$EXTRACT_ROOT/usr/sbin/aamm-ng-web"
test -x "$EXTRACT_ROOT/www/cgi-bin/apps/AAMM-NG/admin"

grep -Fq \
    'exec /usr/sbin/aamm-ng-web --cgi' \
    "$EXTRACT_ROOT/www/cgi-bin/apps/AAMM-NG/admin"

STRINGS_FILE="$BUILD_ROOT/aamm-ng-web.strings"

strings \
    "$EXTRACT_ROOT/usr/sbin/aamm-ng-web" \
    > "$STRINGS_FILE"

grep -Fq \
    'Create AAMM-NG Alert' \
    "$STRINGS_FILE"

grep -Fq \
    'id="ctrl-modal"' \
    "$STRINGS_FILE"

grep -Fq \
    'id="aamm-create-form"' \
    "$STRINGS_FILE"

if grep -Fq \
    '\tid="ctrl-modal"' \
    "$STRINGS_FILE"; then
    echo "literal escaped modal attribute found" >&2
    exit 1
fi

OUTPUT="$DIST_DIR/aamm-ng-${PKG_VERSION}-r${PKG_RELEASE}-${ARCH}.apk"

cp "$APK" "$OUTPUT"

echo
echo "=== release artifact ==="
ls -lh "$OUTPUT"
sha256sum "$OUTPUT"

echo
echo "=== build complete ==="
