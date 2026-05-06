#!/bin/bash
# Get trust-level attribute for a FreeIPA user
# Usage: ./get-trust-level.sh <username>

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <username>"
    exit 1
fi

USERNAME="$1"

echo "Querying trust-level for user $USERNAME..."

RESULT=$(ldapsearch -Y GSSAPI \
    -b "uid=$USERNAME,cn=users,cn=accounts,$(ipa domain 2>/dev/null | sed 's/\./,dc=/g; s/^/dc=/')" \
    "(objectClass=*)" trustLevel 2>/dev/null | grep "^trustLevel:" || true)

if [ -z "$RESULT" ]; then
    echo "trustLevel: not set"
else
    echo "$RESULT"
fi
