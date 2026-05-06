#!/bin/bash
# 03-install-plugin.sh - Install FreeIPA Python plugin for trust-level attribute
# Must be run AFTER 02-add-ldap-schema.sh
# Run as root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Installing FreeIPA trust-level Plugin ==="

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root!"
    exit 1
fi

IPA_PLUGIN_DIR=$(python3 -c "import ipaserver; import os; print(os.path.dirname(ipaserver.__file__))" 2>/dev/null || echo "")
if [ -z "$IPA_PLUGIN_DIR" ]; then
    IPA_PLUGIN_DIR="/usr/lib/python3/dist-packages/ipaserver"
fi

PLUGIN_DIR="$IPA_PLUGIN_DIR/plugins"

if [ ! -d "$PLUGIN_DIR" ]; then
    echo "Error: FreeIPA plugin directory not found: $PLUGIN_DIR"
    echo "Make sure FreeIPA server is installed."
    exit 1
fi

echo "Plugin directory: $PLUGIN_DIR"

echo "[1/3] Installing trustlevel plugin..."
cp "$PROJECT_DIR/freeipa-plugin/trustlevel.py" "$PLUGIN_DIR/"
chmod 644 "$PLUGIN_DIR/trustlevel.py"
echo "Plugin installed: $PLUGIN_DIR/trustlevel.py"

echo "[2/3] Restarting FreeIPA services..."
ipactl restart
sleep 5

echo "[3/3] Testing plugin..."
if ipa user-show admin --all 2>/dev/null | grep -qi trust; then
    echo "SUCCESS: trustlevel parameter is available in ipa user commands"
else
    echo "Plugin may need restart. Testing with addattr method instead:"
    echo "  ipa user-mod testuser --addattr=trustLevel=5"
    echo "  ldapsearch -Y GSSAPI -b uid=testuser,cn=users,cn=accounts,... trustLevel"
fi

echo ""
echo "Usage:"
echo "  ipa user-mod <username> --trustlevel=<0-127>"
echo "  ipa user-show <username> --all | grep trust"
echo "  Or use: ipa user-mod <username> --addattr=trustLevel=5"
echo ""
echo "Next: Run 04-patch-and-rebuild-ipa-kdb.sh"
