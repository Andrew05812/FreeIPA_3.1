#!/bin/bash
# setup-inside-container.sh - Run inside the FreeIPA Docker container
# to apply the trust-level patch and configure everything.
# Run AFTER the container is running and FreeIPA is initialized.

set -euo pipefail

DOMAIN="${1:-example.com}"
REALM=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')

echo "=== FreeIPA Trust-Level Setup Inside Container ==="
echo "Domain: $DOMAIN  Realm: $REALM"

echo "[1/6] Waiting for FreeIPA services..."
timeout 120 bash -c 'while ! ipa user-show admin 2>/dev/null; do sleep 5; done' || true

echo "[2/6] Getting admin ticket..."
echo "Secret123" | kinit admin 2>/dev/null || true

echo "[3/6] Adding LDAP schema..."
DS_INSTANCE=$(ls /etc/dirsrv/ | grep slapd- | head -1)
SCHEMA_DIR="/etc/dirsrv/$DS_INSTANCE/schema"
cp /tmp/99trust-level.ldif "$SCHEMA_DIR/"
chmod 644 "$SCHEMA_DIR/99trust-level.ldif"
systemctl restart "dirsrv@$DS_INSTANCE"
sleep 5

echo "[4/6] Downloading and patching FreeIPA source..."
FREEIPA_VERSION="4.12.2"
BUILD_DIR="/tmp/freeipa-build"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [ ! -d "freeipa-${FREEIPA_VERSION}" ]; then
    curl -L -o "freeipa-${FREEIPA_VERSION}.tar.gz" \
        "https://github.com/freeipa/freeipa/archive/refs/tags/v${FREEIPA_VERSION}.tar.gz"
    tar xzf "freeipa-${FREEIPA_VERSION}.tar.gz"
fi

cd "freeipa-${FREEIPA_VERSION}"
patch -p1 -F3 < /tmp/ipa-kdb-trust-level.patch || {
    echo "Patch failed. Applying manually..."
    cd daemons/ipa-kdb
    sed -i '/"ipaNTHomeDirectoryDrive",/a\    "trustLevel",' ipa_kdb_mspac.c
    echo "Manual patch applied (attribute list only). Full rebuild required for complete functionality."
    echo "See README.md for complete manual patch instructions."
    exit 0
}

echo "[5/6] Building patched ipa-kdb..."
cd daemons/ipa-kdb

# Find existing build flags from installed module
PKG_CFG=$(pkg-config --cflags krb5 libtalloc samba-util tdb tevent 2>/dev/null || echo "")
PKG_LIBS=$(pkg-config --libs krb5 libtalloc samba-util tdb tevent 2>/dev/null || echo "")

# Try using the existing Makefile if configure has been run
if [ -f Makefile ]; then
    make -j"$(nproc)" 2>&1 | tail -5
else
    # Manual compilation fallback
    INC="-I/usr/include -I/usr/include/samba-4 -I.. -I. $(pkg-config --cflags krb5 talloc tevent samba-util 2>/dev/null)"
    LIB="$(pkg-config --libs krb5 talloc tevent samba-util 2>/dev/null) -lldap -lpopt -lsss_idmap -lunistring"
    
    gcc -shared -fPIC -o ipa_kdb.so \
        ipa_kdb.c ipa_kdb_mspac.c ipa_kdb_principals.c ipa_kdb_passwords.c \
        ipa_kdb_pwdpolicy.c ipa_kdb_mspac_v6.c ipa_kdb_mspac_v9.c \
        ipa_kdb_delegation.c ipa_kdb_auditas.c \
        $INC $LIB 2>&1 | tail -10 || {
        echo "Build failed. See README for manual build instructions."
        exit 1
    }
fi

echo "[6/6] Installing patched module..."
IPA_KDB_SO=$(find /usr/lib*/krb5/plugins/kdb/ -name "ipa_kdb.so" 2>/dev/null | head -1)
if [ -z "$IPA_KDB_SO" ]; then
    IPA_KDB_SO=$(find /usr/lib/ -name "ipa_kdb.so" 2>/dev/null | head -1)
fi

if [ -n "$IPA_KDB_SO" ] && [ -f .libs/ipa_kdb.so ]; then
    cp "$IPA_KDB_SO" "${IPA_KDB_SO}.orig"
    cp .libs/ipa_kdb.so "$IPA_KDB_SO"
    chmod 755 "$IPA_KDB_SO"
    echo "Replaced: $IPA_KDB_SO"
elif [ -f ipa_kdb.so ]; then
    KDB_DIR=$(dirname "$IPA_KDB_SO")
    cp "$IPA_KDB_SO" "${IPA_KDB_SO}.orig"
    cp ipa_kdb.so "$IPA_KDB_SO"
    chmod 755 "$IPA_KDB_SO"
    echo "Replaced: $IPA_KDB_SO"
else
    make install 2>/dev/null || true
fi

# Install Python plugin
IPA_PLUGIN_DIR=$(python3 -c "import ipaserver; import os; print(os.path.dirname(ipaserver.__file__))" 2>/dev/null || echo "/usr/lib/python3/site-packages/ipaserver")
if [ -d "$IPA_PLUGIN_DIR/plugins" ]; then
    cp /tmp/trustlevel.py "$IPA_PLUGIN_DIR/plugins/"
    echo "Python plugin installed: $IPA_PLUGIN_DIR/plugins/trustlevel.py"
fi

# Restart KDC
systemctl restart krb5kdc
sleep 2

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Quick test:"
echo "  1. kinit admin"
echo "  2. ipa user-add testuser --first=Test --last=User --password"
echo "  3. ldapmodify -Y GSSAPI <<EOF"
echo "     dn: uid=testuser,cn=users,cn=accounts,dc=$DOMAIN"
echo "     changetype: modify"
echo "     add: objectClass"
echo "     objectClass: ipaTrustLevelObject"
echo "     -"
echo "     add: trustLevel"
echo "     trustLevel: 42"
echo "     EOF"
echo "  4. kinit testuser"
echo "  5. Use Wireshark to verify Extra SID in TGT PAC"
