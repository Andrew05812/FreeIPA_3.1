#!/bin/bash
# 01-setup-freeipa.sh - Install and configure FreeIPA server
# Run as root. Replace EXAMPLE.COM and ipa.example.com with your domain.

set -euo pipefail

echo "=== FreeIPA Server Setup ==="

DOMAIN="${1:-example.com}"
REALM=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')
HOSTNAME="ipa.$DOMAIN"

echo "Domain: $DOMAIN"
echo "Realm:  $REALM"
echo "Host:   $HOSTNAME"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root!"
    exit 1
fi

echo "[1/4] Setting hostname..."
hostnamectl set-hostname "$HOSTNAME"

echo "[2/4] Adding /etc/hosts entry..."
if ! grep -q "$HOSTNAME" /etc/hosts; then
    echo "127.0.0.1   $HOSTNAME $HOSTNAME" >> /etc/hosts
fi

echo "[3/4] Installing FreeIPA server..."
if command -v dnf &>/dev/null; then
    dnf install -y freeipa-server freeipa-server-dns freeipa-server-trust-ad
elif command -v apt-get &>/dev/null; then
    apt-get install -y freeipa-server
elif command -v pacman &>/dev/null; then
    if ! pacman -Qi freeipa &>/dev/null; then
        echo "FreeIPA is not in official Arch repos."
        echo "Install from AUR: yay -S freeipa"
        echo "Or use the Docker approach (see docker/ directory)."
        exit 1
    fi
fi

echo "[4/4] Running FreeIPA server installer..."
ipa-server-install \
    --domain="$DOMAIN" \
    --realm="$REALM" \
    --hostname="$HOSTNAME" \
    --admin-password='Secret123' \
    --ds-password='Secret123' \
    --no-ntp \
    --unattended

echo ""
echo "=== FreeIPA server installed ==="
echo "Admin password: Secret123"
echo "Directory Manager password: Secret123"
echo ""
echo "Authenticate: kinit admin"
echo "Next: Run 02-add-ldap-schema.sh"
