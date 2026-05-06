#!/bin/bash
# 04-patch-and-rebuild-ipa-kdb.sh - Patch FreeIPA's ipa-kdb module to add
# trust-level as Extra SID in MS-PAC, then rebuild and install.
# Must be run AFTER FreeIPA server is installed.
# Run as root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Patching and Rebuilding ipa-kdb for trust-level Extra SID ==="

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root!"
    exit 1
fi

FREEIPA_VERSION="4.12.2"
FREEIPA_TAR="freeipa-${FREEIPA_VERSION}.tar.gz"
FREEIPA_URL="https://github.com/freeipa/freeipa/archive/refs/tags/v${FREEIPA_VERSION}.tar.gz"
BUILD_DIR="/tmp/freeipa-build"

echo "[1/7] Installing build dependencies..."
if command -v dnf &>/dev/null; then
    dnf install -y \
        @development-tools gcc make autoconf automake libtool \
        krb5-devel libselinux-devel libtalloc-devel libtevent-devel \
        samba-devel openldap-devel popt-devel nspr-devel nss-devel \
        389-ds-base-devel libsss_idmap-devel libunistring-devel \
        python3-devel python3-ldap python3-netaddr
elif command -v apt-get &>/dev/null; then
    apt-get install -y \
        build-essential gcc make autoconf automake libtool \
        libkrb5-dev libselinux1-dev libtalloc-dev libtevent-dev \
        samba-dev libldap2-dev libpopt-dev libnspr4-dev libnss3-dev \
        python3-dev
elif command -v pacman &>/dev/null; then
    pacman -S --noconfirm --needed \
        base-devel gcc make autoconf automake libtool \
        krb5 libtalloc libtevent samba openldap popt nspr nss \
        python python-ldap
fi

echo "[2/7] Downloading FreeIPA source..."
mkdir -p "$BUILD_DIR"
if [ ! -f "$BUILD_DIR/$FREEIPA_TAR" ]; then
    curl -L -o "$BUILD_DIR/$FREEIPA_TAR" "$FREEIPA_URL"
fi

echo "[3/7] Extracting source..."
cd "$BUILD_DIR"
if [ ! -d "freeipa-${FREEIPA_VERSION}" ]; then
    tar xzf "$FREEIPA_TAR"
fi

echo "[4/7] Applying trust-level patch..."
IPA_KDB_SRC="freeipa-${FREEIPA_VERSION}/daemons/ipa-kdb"

if [ ! -f "$IPA_KDB_SRC/ipa_kdb_mspac.c" ]; then
    echo "Error: Source file not found: $IPA_KDB_SRC/ipa_kdb_mspac.c"
    exit 1
fi

patch -p1 --dry-run -d "$BUILD_DIR/freeipa-${FREEIPA_VERSION}" < "$PROJECT_DIR/patches/ipa-kdb-trust-level.patch"
if [ $? -ne 0 ]; then
    echo "Patch dry-run failed. Trying with fuzz..."
    patch -p1 -F3 --dry-run -d "$BUILD_DIR/freeipa-${FREEIPA_VERSION}" < "$PROJECT_DIR/patches/ipa-kdb-trust-level.patch"
    if [ $? -ne 0 ]; then
        echo "ERROR: Patch could not be applied automatically."
        echo "The FreeIPA version may differ. Applying manually..."
        echo ""
        echo "Manual patch instructions:"
        echo "1. Add '#define TRUST_LEVEL_RID_BASE 1000000' near top of ipa_kdb_mspac.c"
        echo "2. Add '#define TRUST_LEVEL_MAX 127' after it"
        echo "3. Add 'trustLevel' to user_pac_attrs[] array"
        echo "4. Add ipadb_add_trust_level_sid() function (see patches/ directory)"
        echo "5. Call it from ipadb_fill_info3() after ipadb_add_asserted_identity()"
        echo ""
        echo "Applying patch with force..."
        patch -p1 -F5 -d "$BUILD_DIR/freeipa-${FREEIPA_VERSION}" < "$PROJECT_DIR/patches/ipa-kdb-trust-level.patch" || true
    fi
fi

patch -p1 -F3 -d "$BUILD_DIR/freeipa-${FREEIPA_VERSION}" < "$PROJECT_DIR/patches/ipa-kdb-trust-level.patch"
echo "Patch applied successfully."

echo "[5/7] Building ipa-kdb module..."
cd "$BUILD_DIR/freeipa-${FREEIPA_VERSION}"

if [ -f autogen.sh ]; then
    ./autogen.sh 2>/dev/null || true
fi

if [ -f configure ]; then
    ./configure --prefix=/usr --sysconfdir=/etc 2>/dev/null || true
fi

cd daemons/ipa-kdb
make -j"$(nproc)" 2>&1 | tail -20

echo "[6/7] Installing patched ipa-kdb module..."
IPA_KDB_SO=$(find /usr/lib*/krb5/plugins/kdb/ -name "ipa_kdb.so" 2>/dev/null | head -1)
if [ -z "$IPA_KDB_SO" ]; then
    IPA_KDB_SO=$(find /usr/lib/ -name "ipa_kdb.so" 2>/dev/null | head -1)
fi

if [ -n "$IPA_KDB_SO" ]; then
    echo "Backing up original: $IPA_KDB_SO -> ${IPA_KDB_SO}.orig"
    cp "$IPA_KDB_SO" "${IPA_KDB_SO}.orig"

    echo "Installing patched module..."
    cp .libs/ipa_kdb.so "$IPA_KDB_SO"
    chmod 755 "$IPA_KDB_SO"
else
    echo "Installing to standard location..."
    make install
fi

echo "[7/7] Restarting Kerberos KDC..."
systemctl restart krb5kdc
sleep 2

echo ""
echo "=== ipa-kdb patched and rebuilt successfully ==="
echo "The trust-level value from LDAP will now be added as an Extra SID"
echo "in the MS-PAC of TGT tickets."
echo ""
echo "Next: Run 05-verify.sh"
