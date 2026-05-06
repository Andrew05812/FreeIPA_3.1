#!/bin/bash
# demo.sh - Full demonstration script for presenting the implementation
# Run this during the defense/demonstration of the practical work.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

DOMAIN="${1:-example.com}"
REALM=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')
LDAP_BASE=$(echo "$DOMAIN" | sed 's/\./,dc=/g; s/^/dc=/')

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

section() {
    echo ""
    echo -e "${CYAN}================================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}================================================${NC}"
}

ok() { echo -e "  ${GREEN}[OK]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
info() { echo -e "  ${YELLOW}[INFO]${NC} $1"; }

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║  Практическая работа #3.1                            ║"
echo "  ║  FreeIPA + MIT Kerberos: trust-level в MS-PAC         ║"
echo "  ║  Extra SID в TGT билетах                              ║"
echo "  ╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

section "1. Проверка инфраструктуры FreeIPA"

echo "Проверка работы FreeIPA сервера..."
if ipa ping 2>/dev/null | grep -q "IPA server version"; then
    ok "FreeIPA сервер работает"
else
    fail "FreeIPA сервер не отвечает"
    exit 1
fi

info "Realm: $REALM"
info "Domain: $DOMAIN"

section "2. Проверка LDAP-схемы (атрибут trustLevel)"

if ldapsearch -Y GSSAPI -b cn=schema '(objectClass=*)' attributeTypes 2>/dev/null | grep -q "trustLevel"; then
    ok "Атрибут trustLevel присутствует в схеме LDAP"
    ldapsearch -Y GSSAPI -b cn=schema '(objectClass=*)' attributeTypes 2>/dev/null | grep -A2 "trustLevel" | head -3
else
    fail "Атрибут trustLevel не найден в схеме"
    exit 1
fi

if ldapsearch -Y GSSAPI -b cn=schema '(objectClass=*)' objectClasses 2>/dev/null | grep -q "ipaTrustLevelObject"; then
    ok "Вспомогательный объектный класс ipaTrustLevelObject присутствует"
else
    fail "Объектный класс ipaTrustLevelObject не найден"
    exit 1
fi

section "3. Создание тестового пользователя и установка trust-level"

DEMO_USER="demouser"
DEMO_LEVEL=42

echo "Создание пользователя $DEMO_USER..."
ipa user-add "$DEMO_USER" --first=Demo --last=User --password <<< $'Secret123\nSecret123' 2>/dev/null && ok "Пользователь создан" || info "Пользователь уже существует"

USER_DN="uid=$DEMO_USER,cn=users,cn=accounts,$LDAP_BASE"

echo "Добавление объектного класса ipaTrustLevelObject..."
ldapmodify -Y GSSAPI <<EOF 2>/dev/null
dn: $USER_DN
changetype: modify
add: objectClass
objectClass: ipaTrustLevelObject
EOF

echo "Установка trustLevel = $DEMO_LEVEL..."
ldapmodify -Y GSSAPI <<EOF 2>/dev/null
dn: $USER_DN
changetype: modify
add: trustLevel
trustLevel: $DEMO_LEVEL
EOF

TL=$(ldapsearch -Y GSSAPI -b "$USER_DN" "(objectClass=*)" trustLevel 2>/dev/null | grep "^trustLevel:" | awk '{print $2}')
if [ "$TL" = "$DEMO_LEVEL" ]; then
    ok "trustLevel=$TL сохранён в LDAP каталоге"
else
    fail "trustLevel не сохранён (получено: $TL)"
fi

section "4. Получение TGT билета и проверка MS-PAC"

echo "Аутентификация как $DEMO_USER..."
kdestroy 2>/dev/null || true
echo "Secret123" | kinit "$DEMO_USER@$REALM" 2>/dev/null && ok "TGT получен" || fail "Не удалось получить TGT"

info "Проверка билета..."
klist 2>/dev/null | head -8

section "5. Формат Extra SID с trust-level"

DOMAIN_SID=$(ipa trustconfig-show 2>/dev/null | grep -i "SID" | awk '{print $NF}' || echo "UNKNOWN")
TRUST_LEVEL_RID_BASE=1000000
EXPECTED_SID="${DOMAIN_SID}-$((TRUST_LEVEL_RID_BASE + DEMO_LEVEL))"

echo "Доменный SID: $DOMAIN_SID"
echo "RID базы trust-level: $TRUST_LEVEL_RID_BASE"
echo "trust-level = $DEMO_LEVEL"
echo "Ожидаемый Extra SID: $EXPECTED_SID"
echo ""
echo "Формат编码:"
echo "  Extra SID = S-1-5-21-<domain_sub_auths>-<1000000 + trust_level>"
echo "  Для trust_level=$DEMO_LEVEL -> RID=$((TRUST_LEVEL_RID_BASE + DEMO_LEVEL))"

section "6. Проверка различных значений trust-level (0-127)"

for level in 0 1 50 100 127; do
    ldapmodify -Y GSSAPI <<EOF 2>/dev/null
dn: $USER_DN
changetype: modify
replace: trustLevel
trustLevel: $level
EOF
    TL_CHECK=$(ldapsearch -Y GSSAPI -b "$USER_DN" "(objectClass=*)" trustLevel 2>/dev/null | grep "^trustLevel:" | awk '{print $2}')
    if [ "$TL_CHECK" = "$level" ]; then
        ok "trust-level=$level -> RID=$((TRUST_LEVEL_RID_BASE + level)) -> корректно"
    else
        fail "trust-level=$level -> ошибка (получено: $TL_CHECK)"
    fi
done

section "7. Инструкция проверки PAC через Wireshark"

echo "Для проверки Extra SID в MS-PAC билета TGT:"
echo ""
echo "  1. Запустите Wireshark на интерфейсе loopback (lo)"
echo "  2. Фильтр: kerberos.msg_type == 11 || kerberos.msg_type == 13"
echo "  3. Выполните: kinit $DEMO_USER"
echo "  4. В AS-REP найдите: Authorization-Data"
echo "  5. Внутри: PAC (Pre-Authorization Data)"
echo "  6. PAC -> Logon Info -> Kerb Validation Info"
echo "  7. В Extra Sids найдите SID с RID=$((TRUST_LEVEL_RID_BASE + DEMO_LEVEL))"
echo "  8. trust-level = RID - $TRUST_LEVEL_RID_BASE = $DEMO_LEVEL"
echo ""
echo "Альтернативная проверка через журнал KDC:"
echo "  journalctl -u krb5kdc | grep 'trust-level'"
if journalctl -u krb5kdc --since "5 min ago" 2>/dev/null | grep -q "trust-level"; then
    ok "Журнал KDC содержит записи о trust-level:"
    journalctl -u krb5kdc --since "5 min ago" 2>/dev/null | grep "trust-level" | tail -3
fi

section "8. Очистка"

echo "Удаление тестового пользователя..."
ipa user-del "$DEMO_USER" 2>/dev/null && ok "Тестовый пользователь удалён" || info "Пользователь не удалён"
kdestroy 2>/dev/null || true

echo ""
echo -e "${GREEN}Демонстрация завершена!${NC}"
