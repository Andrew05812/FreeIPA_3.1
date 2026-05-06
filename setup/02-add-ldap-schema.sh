#!/bin/bash
# 02-add-ldap-schema.sh - Add trust-level LDAP schema to 389 DS
# Must be run AFTER FreeIPA server is installed and running.
# Run as root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Adding trust-level LDAP Schema ==="

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root!"
    exit 1
fi

DS_INSTANCE=$(ls /etc/dirsrv/ 2>/dev/null | grep slapd- | head -1)
if [ -z "$DS_INSTANCE" ]; then
    echo "Error: 389 Directory Server instance not found."
    echo "Make sure FreeIPA is installed and running."
    exit 1
fi

SCHEMA_DIR="/etc/dirsrv/$DS_INSTANCE/schema"
echo "Schema directory: $SCHEMA_DIR"

if [ ! -d "$SCHEMA_DIR" ]; then
    echo "Error: Schema directory not found: $SCHEMA_DIR"
    exit 1
fi

echo "[1/3] Copying schema file..."
cp "$PROJECT_DIR/schema/99trust-level.ldif" "$SCHEMA_DIR/"
chmod 644 "$SCHEMA_DIR/99trust-level.ldif"
echo "Schema file installed: $SCHEMA_DIR/99trust-level.ldif"

echo "[2/3] Restarting 389 DS to load new schema..."
systemctl restart dirsrv@"$DS_INSTANCE"
sleep 5

echo "[3/3] Verifying schema is loaded..."
LDAP_BASE=$(ipa domain 2>/dev/null | sed 's/\./,dc=/g; s/^/dc=/')
ADMIN_DN="cn=Directory Manager"

if ldapsearch -x -D "$ADMIN_DN" -w 'Secret123' \
    -b "cn=schema" \
    "(objectClass=*)" attributeTypes 2>/dev/null | grep -q "trustLevel"; then
    echo "SUCCESS: trustLevel attribute is present in LDAP schema"
else
    echo "WARNING: trustLevel attribute not immediately visible (may need longer restart)"
    echo "Try: ldapsearch -Y GSSAPI -b cn=schema '(objectClass=*)' attributeTypes | grep trustLevel"
fi

echo ""
echo "=== Schema installation complete ==="
echo "Next: Run 03-install-plugin.sh (optional) or 04-patch-and-rebuild-ipa-kdb.sh"
