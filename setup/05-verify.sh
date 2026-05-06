#!/bin/bash
# 05-verify.sh - Full verification of trust-level implementation
# Run after all setup scripts.
# Can be run as any user with Kerberos admin credentials.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Verifying Trust-Level Implementation ==="
echo ""

REALM="${1:-}"
if [ -z "$REALM" ]; then
    REALM=$(krb5-config --realm 2>/dev/null || echo "EXAMPLE.COM")
fi

echo "Realm: $REALM"
echo ""

PASS=0
FAIL=0

check() {
    local desc="$1"
    local result="$2"
    if [ "$result" = "0" ]; then
        echo "  [PASS] $desc"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo "--- Test 1: LDAP Schema ---"
if ldapsearch -Y GSSAPI -b cn=schema '(objectClass=*)' attributeTypes 2>/dev/null | grep -q "trustLevel"; then
    check "trustLevel attribute in LDAP schema" 0
else
    check "trustLevel attribute in LDAP schema" 1
fi

echo ""
echo "--- Test 2: Object Class ---"
if ldapsearch -Y GSSAPI -b cn=schema '(objectClass=*)' objectClasses 2>/dev/null | grep -q "ipaTrustLevelObject"; then
    check "ipaTrustLevelObject auxiliary class in schema" 0
else
    check "ipaTrustLevelObject auxiliary class in schema" 1
fi

echo ""
echo "--- Test 3: Create test user and set trust-level ---"
TEST_USER="testtrust$(date +%s)"
IPA_DOMAIN=$(ipa domain 2>/dev/null || echo "example.com")
LDAP_BASE=$(echo "$IPA_DOMAIN" | sed 's/\./,dc=/g; s/^/dc=/')
USER_DN="uid=$TEST_USER,cn=users,cn=accounts,$LDAP_BASE"

echo "Creating test user: $TEST_USER"
ipa user-add "$TEST_USER" --first=Test --last=Trust --password <<< $'Secret123\nSecret123' 2>/dev/null || true

echo "Adding ipaTrustLevelObject objectclass and trustLevel=42..."
ldapmodify -Y GSSAPI <<EOF 2>/dev/null || true
dn: $USER_DN
changetype: modify
add: objectClass
objectClass: ipaTrustLevelObject
-
add: trustLevel
trustLevel: 42
EOF

TL_VALUE=$(ldapsearch -Y GSSAPI -b "$USER_DN" "(objectClass=*)" trustLevel 2>/dev/null | grep "^trustLevel:" | awk '{print $2}')
if [ "$TL_VALUE" = "42" ]; then
    check "trustLevel=42 stored in LDAP" 0
else
    check "trustLevel=42 stored in LDAP (got: $TL_VALUE)" 1
fi

echo ""
echo "--- Test 4: Kerberos TGT with trust-level Extra SID ---"
echo "Getting TGT for $TEST_USER..."
kinit "$TEST_USER" <<< 'Secret123' 2>/dev/null || kinit "$TEST_USER@$REALM" <<< 'Secret123' 2>/dev/null || true

echo "Getting service ticket (to verify TGT)..."
kvno "krbtgt/$REALM@$REALM" 2>/dev/null || true

echo ""
echo "To manually verify the Extra SID in the PAC:"
echo "  1. Capture Kerberos traffic with Wireshark"
echo "  2. Decode the AS-REP (TGT) response"
echo "  3. Look in Authorization-Data -> PAC -> Logon Info -> Extra SIDs"
echo "  4. Find SID with RID in range 1000000-1000127"
echo "  5. trust-level = RID - 1000000"
echo ""
echo "Expected Extra SID for trust-level=42:"
DOMAIN_SID=$(ipa trustconfig-show 2>/dev/null | grep "IPANTSID" | awk '{print $2}' || echo "S-1-5-21-UNKNOWN")
echo "  $DOMAIN_SID-1000042"
echo ""
echo "Quick check using KDC log:"
if journalctl -u krb5kdc --since "5 min ago" 2>/dev/null | grep -q "trust-level"; then
    check "KDC log shows trust-level Extra SID addition" 0
else
    check "KDC log shows trust-level Extra SID addition (check manually)" 1
    echo "  Check: journalctl -u krb5kdc | grep trust-level"
fi

echo ""
echo "--- Test 5: Range validation ---"
echo "Testing trust-level=0..."
ldapmodify -Y GSSAPI <<EOF 2>/dev/null
dn: $USER_DN
changetype: modify
replace: trustLevel
trustLevel: 0
EOF

TL0=$(ldapsearch -Y GSSAPI -b "$USER_DN" "(objectClass=*)" trustLevel 2>/dev/null | grep "^trustLevel:" | awk '{print $2}')
check "trust-level=0 stored correctly" "$([ "$TL0" = "0" ] && echo 0 || echo 1)"

echo "Testing trust-level=127..."
ldapmodify -Y GSSAPI <<EOF 2>/dev/null
dn: $USER_DN
changetype: modify
replace: trustLevel
trustLevel: 127
EOF

TL127=$(ldapsearch -Y GSSAPI -b "$USER_DN" "(objectClass=*)" trustLevel 2>/dev/null | grep "^trustLevel:" | awk '{print $2}')
check "trust-level=127 stored correctly" "$([ "$TL127" = "127" ] && echo 0 || echo 1)"

echo ""
echo "--- Cleanup ---"
echo "Removing test user $TEST_USER..."
ipa user-del "$TEST_USER" 2>/dev/null || true
kdestroy 2>/dev/null || true

echo ""
echo "========================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "========================================"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
