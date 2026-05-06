#!/bin/bash
# 00-prerequisites-arch.sh - Install prerequisites on Arch Linux
# Run as root or with sudo

set -euo pipefail

echo "=== FreeIPA Trust Level Extension - Arch Linux Prerequisites ==="

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Use sudo."
    exit 1
fi

echo "[1/5] Updating system packages..."
pacman -Syu --noconfirm

echo "[2/5] Installing base build tools..."
pacman -S --noconfirm --needed \
    base-devel git cmake autoconf automake libtool pkgconf \
    python3 python-pip python-setuptools python-wheel

echo "[3/5] Installing FreeIPA dependencies..."
# Kerberos
pacman -S --noconfirm --needed \
    krb5 mit-krb5

# LDAP (389-ds-base is available on AUR)
pacman -S --noconfirm --needed \
    openldap

# Samba (needed for MS-PAC generation in ipa-kdb)
pacman -S --noconfirm --needed \
    samba samba-idl-headers cifs-utils

# FreeIPA core deps
pacman -S --noconfirm --needed \
    popt nspr nss svrcore cyrus-sasl libsss_sudo \
    bind bind-utils chrony httpd mod_nss \
    python-ldap python-netaddr python-gssapi \
    python-cryptography python-dnspython python-qrcode \
    python-yubico python-requests python-six \
    ss sd python-sssdconfig

echo "[4/5] Installing AUR packages (requires yay or paru)..."
echo "You may need to install these from AUR manually:"
echo "  - freeipa (AUR)"
echo "  - 389-ds-base (AUR)"
echo "  - python-ipaddress (AUR)"
echo "  - python-pyusb (AUR)"
echo ""
echo "If you have yay installed:"
echo "  yay -S freeipa 389-ds-base"
echo ""
echo "Alternatively, use the Docker approach (see docker/ directory)."

echo "[5/5] Installing Kerberos client config..."
if [ ! -f /etc/krb5.conf ] || [ ! -s /etc/krb5.conf ]; then
    cat > /etc/krb5.conf <<'KRB5EOF'
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = true
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false

[realms]
    EXAMPLE.COM = {
        kdc = ipa.example.com
        admin_server = ipa.example.com
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM
KRB5EOF
    echo "Created default /etc/krb5.conf - customize for your realm!"
fi

echo ""
echo "=== Prerequisites installation complete ==="
echo "Next: Run 01-setup-freeipa.sh"
