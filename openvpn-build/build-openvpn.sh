#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build a statically-linked OpenVPN 2.7.0 binary for arm64 macOS
# with OpenSSL 3.5.5 (LTS), pkcs11-helper, lzo, and lz4.
#
# The resulting binary depends only on macOS system dylibs.
#
# Usage:
#   ./build-openvpn.sh
#
# Required environment variables:
#   CODESIGN_IDENTITY  - binary codesign identity (e.g. "Developer ID Application: ...")
#   INSTALLER_IDENTITY - pkg signing identity (e.g. "Developer ID Installer: ...")
#
# Optional environment variables:
#   MACOSX_DEPLOYMENT_TARGET - minimum macOS version (default: 13.0)
#   JOBS               - parallel make jobs (default: $(sysctl -n hw.ncpu))

set -euo pipefail

# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------
OPENSSL_VERSION="3.5.5"
LZO_VERSION="2.10"
LZ4_VERSION="1.10.0"
PKCS11_HELPER_VERSION="1.30.0"
OPENVPN_VERSION="2.7.0"

# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
LZO_URL="https://www.oberhumer.com/opensource/lzo/download/lzo-${LZO_VERSION}.tar.gz"
LZ4_URL="https://github.com/lz4/lz4/releases/download/v${LZ4_VERSION}/lz4-${LZ4_VERSION}.tar.gz"
PKCS11_HELPER_URL="https://github.com/OpenSC/pkcs11-helper/releases/download/pkcs11-helper-${PKCS11_HELPER_VERSION}/pkcs11-helper-${PKCS11_HELPER_VERSION}.tar.bz2"
OPENVPN_URL="https://github.com/OpenVPN/openvpn/releases/download/v${OPENVPN_VERSION}/openvpn-${OPENVPN_VERSION}.tar.gz"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOPDIR="${SCRIPT_DIR}/_work"
SOURCES_DIR="${TOPDIR}/sources"
BUILD_DIR="${TOPDIR}/build"
STAGING_DIR="${TOPDIR}/staging"
OUTPUT_DIR="${SCRIPT_DIR}/output"

ARCH="arm64"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
JOBS="${JOBS:-$(sysctl -n hw.ncpu)}"

if [ -z "${CODESIGN_IDENTITY:-}" ]; then
    echo "ERROR: CODESIGN_IDENTITY is required"
    exit 1
fi
if [ -z "${INSTALLER_IDENTITY:-}" ]; then
    echo "ERROR: INSTALLER_IDENTITY is required"
    exit 1
fi

SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
CC="$(xcrun --find clang)"
export CC

BASE_CFLAGS="-isysroot ${SDKROOT} -arch ${ARCH} -mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET} -Os"
BASE_LDFLAGS="-isysroot ${SDKROOT} -arch ${ARCH} -mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}"

OPENSSL_STAGING="${STAGING_DIR}/openssl-${OPENSSL_VERSION}"
LZO_STAGING="${STAGING_DIR}/lzo-${LZO_VERSION}"
LZ4_STAGING="${STAGING_DIR}/lz4-${LZ4_VERSION}"
PKCS11_STAGING="${STAGING_DIR}/pkcs11-helper-${PKCS11_HELPER_VERSION}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { printf '\n==> %s\n' "$*"; }

download() {
    local url="$1" dest="$2"
    if [ -f "$dest" ]; then
        echo "  Already downloaded: $(basename "$dest")"
        return
    fi
    echo "  Downloading $(basename "$dest")..."
    curl -fSL --retry 3 -o "$dest" "$url"
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
log "Setting up directories"
mkdir -p "$SOURCES_DIR" "$BUILD_DIR" "$STAGING_DIR" "$OUTPUT_DIR"

echo "  ARCH:       ${ARCH}"
echo "  SDK:        ${SDKROOT}"
echo "  CC:         ${CC}"
echo "  DEPLOY_TGT: ${MACOSX_DEPLOYMENT_TARGET}"
echo "  JOBS:       ${JOBS}"
echo "  CODESIGN:   ${CODESIGN_IDENTITY}"

# ---------------------------------------------------------------------------
# Download sources
# ---------------------------------------------------------------------------
log "Downloading sources"
download "$OPENSSL_URL"        "${SOURCES_DIR}/openssl-${OPENSSL_VERSION}.tar.gz"
download "$LZO_URL"            "${SOURCES_DIR}/lzo-${LZO_VERSION}.tar.gz"
download "$LZ4_URL"            "${SOURCES_DIR}/lz4-${LZ4_VERSION}.tar.gz"
download "$PKCS11_HELPER_URL"  "${SOURCES_DIR}/pkcs11-helper-${PKCS11_HELPER_VERSION}.tar.bz2"
download "$OPENVPN_URL"        "${SOURCES_DIR}/openvpn-${OPENVPN_VERSION}.tar.gz"

# ---------------------------------------------------------------------------
# 1. OpenSSL 3.0.16
# ---------------------------------------------------------------------------
if [ ! -f "${OPENSSL_STAGING}/lib/libssl.a" ]; then
    log "Building OpenSSL ${OPENSSL_VERSION}"
    rm -rf "${BUILD_DIR}/openssl-${OPENSSL_VERSION}"
    tar xzf "${SOURCES_DIR}/openssl-${OPENSSL_VERSION}.tar.gz" -C "$BUILD_DIR"
    cd "${BUILD_DIR}/openssl-${OPENSSL_VERSION}"

    ./Configure darwin64-arm64-cc \
        no-shared \
        no-tests \
        no-ui-console \
        --prefix="${OPENSSL_STAGING}" \
        --openssldir="${OPENSSL_STAGING}/etc/openssl" \
        -isysroot "${SDKROOT}" \
        -mmacosx-version-min="${MACOSX_DEPLOYMENT_TARGET}"

    make -j"${JOBS}"
    make install_sw
    echo "  Installed to ${OPENSSL_STAGING}"
else
    log "OpenSSL ${OPENSSL_VERSION} already built"
fi

# ---------------------------------------------------------------------------
# 2. LZO 2.10
# ---------------------------------------------------------------------------
if [ ! -f "${LZO_STAGING}/lib/liblzo2.a" ]; then
    log "Building lzo ${LZO_VERSION}"
    rm -rf "${BUILD_DIR}/lzo-${LZO_VERSION}"
    tar xzf "${SOURCES_DIR}/lzo-${LZO_VERSION}.tar.gz" -C "$BUILD_DIR"
    cd "${BUILD_DIR}/lzo-${LZO_VERSION}"

    CFLAGS="${BASE_CFLAGS}" \
    LDFLAGS="${BASE_LDFLAGS}" \
    ./configure \
        --build=arm-apple-darwin \
        --host=arm-apple-darwin \
        --prefix="${LZO_STAGING}" \
        --enable-static \
        --disable-shared \
        --disable-dependency-tracking

    make -j"${JOBS}"
    make install
    echo "  Installed to ${LZO_STAGING}"
else
    log "lzo ${LZO_VERSION} already built"
fi

# ---------------------------------------------------------------------------
# 3. LZ4 1.10.0
# ---------------------------------------------------------------------------
if [ ! -f "${LZ4_STAGING}/lib/liblz4.a" ]; then
    log "Building lz4 ${LZ4_VERSION}"
    rm -rf "${BUILD_DIR}/lz4-${LZ4_VERSION}"
    tar xzf "${SOURCES_DIR}/lz4-${LZ4_VERSION}.tar.gz" -C "$BUILD_DIR"
    cd "${BUILD_DIR}/lz4-${LZ4_VERSION}"

    make -j"${JOBS}" -C lib \
        CC="${CC}" \
        CFLAGS="${BASE_CFLAGS}" \
        BUILD_SHARED=no \
        PREFIX="${LZ4_STAGING}"

    mkdir -p "${LZ4_STAGING}/lib" "${LZ4_STAGING}/include"
    cp lib/liblz4.a "${LZ4_STAGING}/lib/"
    cp lib/lz4.h lib/lz4hc.h lib/lz4frame.h "${LZ4_STAGING}/include/"
    # pkg-config file so OpenVPN's configure can find lz4
    mkdir -p "${LZ4_STAGING}/lib/pkgconfig"
    cat > "${LZ4_STAGING}/lib/pkgconfig/liblz4.pc" <<PKGEOF
prefix=${LZ4_STAGING}
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: lz4
Description: LZ4 compression library
Version: ${LZ4_VERSION}
Libs: -L\${libdir} -llz4
Cflags: -I\${includedir}
PKGEOF
    echo "  Installed to ${LZ4_STAGING}"
else
    log "lz4 ${LZ4_VERSION} already built"
fi

# ---------------------------------------------------------------------------
# 4. pkcs11-helper 1.30.0
# ---------------------------------------------------------------------------
if [ ! -f "${PKCS11_STAGING}/lib/libpkcs11-helper.a" ]; then
    log "Building pkcs11-helper ${PKCS11_HELPER_VERSION}"
    rm -rf "${BUILD_DIR}/pkcs11-helper-${PKCS11_HELPER_VERSION}"
    tar xjf "${SOURCES_DIR}/pkcs11-helper-${PKCS11_HELPER_VERSION}.tar.bz2" -C "$BUILD_DIR"
    cd "${BUILD_DIR}/pkcs11-helper-${PKCS11_HELPER_VERSION}"

    CFLAGS="${BASE_CFLAGS}" \
    LDFLAGS="${BASE_LDFLAGS}" \
    OPENSSL_CFLAGS="-I${OPENSSL_STAGING}/include" \
    OPENSSL_LIBS="-L${OPENSSL_STAGING}/lib -lssl -lcrypto" \
    ./configure \
        --build=arm-apple-darwin \
        --host=arm-apple-darwin \
        --prefix="${PKCS11_STAGING}" \
        --enable-static \
        --enable-shared=no \
        --enable-slotevent=no \
        --enable-threading=no \
        --disable-crypto-engine-gnutls \
        --disable-crypto-engine-nss \
        --disable-crypto-engine-mbedtls \
        --disable-dependency-tracking

    make -j"${JOBS}"
    make install
    echo "  Installed to ${PKCS11_STAGING}"
else
    log "pkcs11-helper ${PKCS11_HELPER_VERSION} already built"
fi

# ---------------------------------------------------------------------------
# 5. OpenVPN 2.7.0
# ---------------------------------------------------------------------------
log "Building OpenVPN ${OPENVPN_VERSION}"
rm -rf "${BUILD_DIR}/openvpn-${OPENVPN_VERSION}"
tar xzf "${SOURCES_DIR}/openvpn-${OPENVPN_VERSION}.tar.gz" -C "$BUILD_DIR"
cd "${BUILD_DIR}/openvpn-${OPENVPN_VERSION}"

CC="${CC}" \
CFLAGS="${BASE_CFLAGS} -I. -Wno-deprecated-declarations -D __APPLE_USE_RFC_3542" \
LDFLAGS="${BASE_LDFLAGS}" \
LZO_CFLAGS="-I${LZO_STAGING}/include" \
LZO_LIBS="-L${LZO_STAGING}/lib -llzo2" \
LZ4_CFLAGS="-I${LZ4_STAGING}/include" \
LZ4_LIBS="-L${LZ4_STAGING}/lib -llz4" \
OPENSSL_CFLAGS="-I${OPENSSL_STAGING}/include" \
OPENSSL_SSL_CFLAGS="-I${OPENSSL_STAGING}/include" \
OPENSSL_CRYPTO_CFLAGS="-I${OPENSSL_STAGING}/include" \
OPENSSL_LIBS="${OPENSSL_STAGING}/lib/libssl.a -lz ${OPENSSL_STAGING}/lib/libcrypto.a -lz" \
OPENSSL_SSL_LIBS="${OPENSSL_STAGING}/lib/libssl.a" \
OPENSSL_CRYPTO_LIBS="${OPENSSL_STAGING}/lib/libcrypto.a -lz" \
PKCS11_HELPER_CFLAGS="-I${PKCS11_STAGING}/include/" \
PKCS11_HELPER_LIBS="-L${PKCS11_STAGING}/lib -lpkcs11-helper" \
./configure \
    --build=arm-apple-darwin \
    --host=arm-apple-darwin \
    --enable-pkcs11 \
    --enable-lzo \
    --enable-lz4 \
    --disable-plugin-auth-pam \
    --disable-unit-tests \
    --disable-debug \
    --disable-dependency-tracking

make -j"${JOBS}"

OPENVPN_BIN="${BUILD_DIR}/openvpn-${OPENVPN_VERSION}/src/openvpn/openvpn"
if [ ! -f "$OPENVPN_BIN" ]; then
    echo "ERROR: openvpn binary not found at ${OPENVPN_BIN}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Verify, strip, sign, output
# ---------------------------------------------------------------------------
log "Verifying dynamic dependencies"
DYLIBS="$(otool -L "$OPENVPN_BIN" | tail -n +2 | awk '{print $1}')"
BAD_DEPS=""
while IFS= read -r lib; do
    case "$lib" in
        /usr/lib/*) ;;   # system libraries are fine
        *) BAD_DEPS="${BAD_DEPS}  ${lib}\n" ;;
    esac
done <<< "$DYLIBS"

if [ -n "$BAD_DEPS" ]; then
    echo "WARNING: Non-system dynamic dependencies found:"
    printf "%b" "$BAD_DEPS"
    echo "The binary may not be portable. Continuing anyway."
fi

echo "  Dynamic dependencies (all should be /usr/lib/*):"
otool -L "$OPENVPN_BIN" | tail -n +2

log "Stripping binary"
strip "$OPENVPN_BIN"
ls -lh "$OPENVPN_BIN"

log "Codesigning (hardened runtime)"
echo "  Signing with: ${CODESIGN_IDENTITY}"
codesign -s "${CODESIGN_IDENTITY}" --options runtime --timestamp --force "$OPENVPN_BIN"

log "Copying to output"
cp "$OPENVPN_BIN" "${OUTPUT_DIR}/openvpn"
echo "  Binary: ${OUTPUT_DIR}/openvpn"

# ---------------------------------------------------------------------------
# Build installer .pkg
# ---------------------------------------------------------------------------
PKG_IDENTIFIER="${PKG_IDENTIFIER:-com.nailed.openvpn}"
TB_OPENVPN_DIR="openvpn-${OPENVPN_VERSION}-openssl-${OPENSSL_VERSION}_nailed"

log "Building installer package"
PKG_ROOT="${TOPDIR}/pkg-root"
rm -rf "$PKG_ROOT"
mkdir -p "${PKG_ROOT}/${TB_OPENVPN_DIR}"
cp "${OUTPUT_DIR}/openvpn" "${PKG_ROOT}/${TB_OPENVPN_DIR}/openvpn"
chmod 0755 "${PKG_ROOT}/${TB_OPENVPN_DIR}/openvpn"
chmod 0755 "${PKG_ROOT}/${TB_OPENVPN_DIR}"

PKG_UNSIGNED="${OUTPUT_DIR}/openvpn-${OPENVPN_VERSION}-openssl-${OPENSSL_VERSION}.unsigned.pkg"
PKG_SIGNED="${OUTPUT_DIR}/openvpn-${OPENVPN_VERSION}-openssl-${OPENSSL_VERSION}.pkg"

pkgbuild \
    --root "$PKG_ROOT" \
    --identifier "$PKG_IDENTIFIER" \
    --version "${OPENVPN_VERSION}" \
    --install-location "/Library/Application Support/Tunnelblick/Openvpn" \
    --ownership recommended \
    "$PKG_UNSIGNED"

echo "  Signing package with: ${INSTALLER_IDENTITY}"
productsign --sign "${INSTALLER_IDENTITY}" --timestamp "$PKG_UNSIGNED" "$PKG_SIGNED"
rm "$PKG_UNSIGNED"
echo "  Package: ${PKG_SIGNED}"

log "Final binary info"
file "${OUTPUT_DIR}/openvpn"
otool -L "${OUTPUT_DIR}/openvpn"
codesign -dvvv "${OUTPUT_DIR}/openvpn" 2>&1 || true
"${OUTPUT_DIR}/openvpn" --version || true

log "Done."
echo "  Binary:  ${OUTPUT_DIR}/openvpn"
echo "  Package: ${PKG_SIGNED}"
echo ""
echo "  Install with: sudo installer -pkg \"${PKG_SIGNED}\" -target /"
echo "  Installs to:  /Library/Application Support/Tunnelblick/Openvpn/${TB_OPENVPN_DIR}/openvpn"
