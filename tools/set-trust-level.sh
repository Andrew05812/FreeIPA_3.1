#!/bin/bash
# Set trust-level attribute for a FreeIPA user
# Usage: ./set-trust-level.sh <username> <level>
# level must be 0-127

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <username> <level(0-127)>"
    exit 1
fi

USERNAME="$1"
LEVEL="$2"

if ! [[ "$LEVEL" =~ ^[0-9]+$ ]] || [ "$LEVEL" -lt 0 ] || [ "$LEVEL" -gt 127 ]; then
    echo "Error: trust-level must be an integer between 0 and 127"
    exit 1
fi

echo "Setting trust-level=$LEVEL for user $USERNAME"

EXISTING=$(ipa user-show "$USERNAME" --all 2>/dev/null | grep "trustLevel:" || true)

if [ -n "$EXISTING" ]; then
    echo "Updating existing trustLevel attribute..."
    ldapmodify -Y GSSAPI <<EOF
dn: uid=$USERNAME,cn=users,cn=accounts,$(ipa domain 2>/dev/null | sed 's/\./,dc=/g; s/^/dc=/')
changetype: modify
replace: trustLevel
trustLevel: $LEVEL
EOF
else
    echo "Adding trustLevel attribute (may need objectclass first)..."
    ldapmodify -Y GSSAPI <<EOF
dn: uid=$USERNAME,cn=users,cn=accounts,$(ipa domain 2>/dev/null | sed 's/\./,dc=/g; s/^/dc=/')
changetype: modify
add: objectClass
objectClass: ipaTrustLevelObject
-
add: trustLevel
trustLevel: $LEVEL
EOF
fi

echo "Verifying..."
ipa user-show "$USERNAME" --all | grep -i trust
echo "Done. trust-level=$LEVEL set for $USERNAME"
