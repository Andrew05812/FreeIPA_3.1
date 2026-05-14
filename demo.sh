#!/bin/bash
# demo.sh — Создание пользователя + демонстрация (шаги 5-6)
# Запуск: sudo bash demo.sh

set -e
ADMIN_PW="Secret123"

echo "$ADMIN_PW" | kinit admin

echo "[1] Создание пользователя testuser..."
USER_DN="uid=testuser,cn=users,cn=accounts,dc=example,dc=com"
if ! ldapsearch -Y GSSAPI -b "$USER_DN" -s base uid 2>/dev/null | grep -q "^uid:"; then
  ipa user-add testuser --first=Test --last=User || { echo "FAIL: ipa user-add"; exit 1; }
fi
ldappasswd -Y GSSAPI -s "NewPass123" "$USER_DN"

echo "[2] Добавление objectClass + trustLevel=42..."
HAS_OC=$(ldapsearch -Y GSSAPI -b "$USER_DN" -s base objectClass 2>/dev/null | grep -c "ipaTrustLevelObject" || true)
if [ "$HAS_OC" -ge 1 ]; then
  ldapmodify -Y GSSAPI << EOF
dn: $USER_DN
changetype: modify
replace: trustLevel
trustLevel: 42
EOF
else
  ldapmodify -Y GSSAPI << 'EOF'
dn: uid=testuser,cn=users,cn=accounts,dc=example,dc=com
changetype: modify
add: objectClass
objectClass: ipaTrustLevelObject
-
add: trustLevel
trustLevel: 42
EOF
fi

echo "[3] Установка krbPasswordExpiration..."
ldapmodify -Y GSSAPI << 'EOF'
dn: uid=testuser,cn=users,cn=accounts,dc=example,dc=com
changetype: modify
replace: krbPasswordExpiration
krbPasswordExpiration: 20380101000000Z
EOF

echo "[4] kinit testuser..."
echo NewPass123 | kinit testuser@EXAMPLE.COM

echo "[5] Проверка Extra SID в логе KDC..."
RESULT=$(grep "trust-level" /var/log/krb5kdc.log | tail -1)
echo "  $RESULT"

if echo "$RESULT" | grep -q "trust-level: added Extra SID for level 42"; then
  echo ""
  echo "========================================="
  echo "  УСПЕХ! Extra SID добавлен в TGT"
  echo "========================================="
else
  echo ""
  echo "  FAIL: Extra SID не найден в логе"
fi

echo ""
echo "[6] Доменный SID:"
DOMAIN_SID=$(ipa trustconfig-show --all 2>/dev/null | grep "Идентификатор безопасности" | awk '{print $NF}')
if [ -n "$DOMAIN_SID" ]; then
  echo "  $DOMAIN_SID"
  echo "  trust-level=42 → Extra SID: ${DOMAIN_SID}-1000042"
fi
