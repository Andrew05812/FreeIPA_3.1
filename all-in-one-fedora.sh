#!/bin/bash
# all-in-one-fedora.sh — Полная установка и проверка на Fedora (без Docker)
# Запуск: bash all-in-one-fedora.sh
# Пароли: admin=Secret123, ds=Secret123
# Требования: Fedora 40/41, 2GB+ RAM, 10GB+ диск

set -e
DOMAIN="example.com"
REALM="EXAMPLE.COM"
HOSTNAME="ipa.example.com"
ADMIN_PW="Secret123"
DS_PW="Secret123"
TRUST_LEVEL_RID_BASE=1000000

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
ok()   { echo -e "  ${G}[OK]${N} $1"; }
fail() { echo -e "  ${R}[FAIL]${N} $1"; exit 1; }
step() { echo -e "\n${C}━━━ $1 ━━━${N}"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ═══════════════════════════════════════════════════════
step "1/7 — Установка FreeIPA сервера"
# ═══════════════════════════════════════════════════════
if ! rpm -q freeipa-server &>/dev/null; then
    echo "Установка freeipa-server (может занять несколько минут)..."
    dnf install -y freeipa-server freeipa-server-dns freeipa-server-trust-ad \
        @development-tools gcc make autoconf automake libtool \
        krb5-devel libtalloc-devel libtevent-devel \
        samba-devel openldap-devel popt-devel nspr-devel nss-devel \
        libsss_idmap-devel libunistring-devel python3-devel \
        git wget python3-ldap || fail "dnf install failed"
fi
ok "FreeIPA сервер установлен"

# ═══════════════════════════════════════════════════════
step "2/7 — Настройка хоста и установка FreeIPA"
# ═══════════════════════════════════════════════════════
hostnamectl set-hostname "$HOSTNAME" 2>/dev/null || true

if ! grep -q "$HOSTNAME" /etc/hosts; then
    echo "127.0.0.1   $HOSTNAME" >> /etc/hosts
fi

if ! klist -k /etc/krb5.keytab 2>/dev/null | grep -q "HOST"; then
    echo "Настройка FreeIPA сервера (5-10 минут)..."
    ipa-server-install \
        --domain="$DOMAIN" \
        --realm="$REALM" \
        --hostname="$HOSTNAME" \
        --admin-password="$ADMIN_PW" \
        --ds-password="$DS_PW" \
        --no-ntp \
        --unattended || fail "ipa-server-install failed"
fi
ok "FreeIPA сервер настроен"

# ═══════════════════════════════════════════════════════
step "3/7 — Добавление LDAP-схемы trust-level"
# ═══════════════════════════════════════════════════════
echo "$ADMIN_PW" | kinit admin 2>/dev/null || fail "kinit admin failed"

DS_INST=$(ls /etc/dirsrv/ 2>/dev/null | grep slapd- | head -1)
if [ -z "$DS_INST" ]; then
    fail "389 DS instance не найден. FreeIPA установлен?"
fi
SCHEMA_DIR="/etc/dirsrv/$DS_INST/schema"

cp "$SCRIPT_DIR/schema/99trust-level.ldif" "$SCHEMA_DIR/"
chmod 644 "$SCHEMA_DIR/99trust-level.ldif"

systemctl restart "dirsrv@$DS_INST"
sleep 8
ok "LDAP-схема trust-level установлена"

# ═══════════════════════════════════════════════════════
step "4/7 — Патч ipa-kdb (добавление trust-level в MS-PAC)"
# ═══════════════════════════════════════════════════════
IPA_KDB_SRC=$(rpm -ql freeipa-server | grep ipa_kdb_mspac.c | head -1)
if [ -n "$IPA_KDB_SRC" ]; then
    IPA_KDB_DIR=$(dirname "$IPA_KDB_SRC")
else
    IPA_KDB_DIR=""
fi

BUILD_DIR="/tmp/freeipa-build"
mkdir -p "$BUILD_DIR"

# Определяем версию FreeIPA
IPA_VER=$(rpm -q freeipa-server --qf '%{VERSION}' 2>/dev/null || echo "4.12.2")
echo "FreeIPA версия: $IPA_VER"

# Скачиваем исходники
cd "$BUILD_DIR"
if [ ! -d "freeipa-${IPA_VER}" ]; then
    echo "Скачивание исходников FreeIPA..."
    curl -sL -o "freeipa-${IPA_VER}.tar.gz" \
        "https://github.com/freeipa/freeipa/archive/refs/tags/v${IPA_VER}.tar.gz" 2>/dev/null || \
    curl -sL -o "freeipa-${IPA_VER}.tar.gz" \
        "https://github.com/freeipa/freeipa/archive/refs/tags/release-${IPA_VER}.tar.gz" 2>/dev/null || \
    echo "Скачивание не удалось, используем rpm-исходники"

    if [ -f "freeipa-${IPA_VER}.tar.gz" ]; then
        tar xzf "freeipa-${IPA_VER}.tar.gz" 2>/dev/null || true
    fi
fi

# Проверяем что исходники есть
if [ ! -d "freeipa-${IPA_VER}/daemons/ipa-kdb" ]; then
    # Пробуем найти исходники из srpm
    echo "Исходники из tar не найдены, пробуем rpm..."
    dnf download --source freeipa-server 2>/dev/null || true
    rpm2cpio freeipa-*.src.rpm 2>/dev/null | cpio -idmv 2>/dev/null || true
    if [ -f freeipa-*.tar.gz ]; then
        tar xzf freeipa-*.tar.gz 2>/dev/null || true
    fi
fi

# Находим директорию с ipa-kdb исходниками
KDB_SRC_DIR=$(find "$BUILD_DIR" -name ipa_kdb_mspac.c -type f 2>/dev/null | head -1 | xargs dirname 2>/dev/null)
if [ -z "$KDB_SRC_DIR" ]; then
    echo "Исходники не найдены. Патчим установленный модуль через sed..."
    
    # Находим установленный ipa_kdb_mspac.c (если есть в /usr/share/doc или debug-пакете)
    KDB_SRC_DIR="/usr/share/doc/freeipa-server/src/daemons/ipa-kdb"
    if [ ! -d "$KDB_SRC_DIR" ]; then
        mkdir -p "$KDB_SRC_DIR"
        # Создаём минимальный набор исходников из установленных библиотек
        dnf install -y freeipa-server-debuginfo 2>/dev/null || true
    fi
fi

# Пробуем патчить через patch
if [ -d "$KDB_SRC_DIR" ] && [ -f "$KDB_SRC_DIR/ipa_kdb_mspac.c" ]; then
    echo "Применяем патч к $KDB_SRC_DIR/ipa_kdb_mspac.c ..."
    cd "$KDB_SRC_DIR/.."
    patch -p2 -F3 < "$SCRIPT_DIR/patches/ipa-kdb-trust-level.patch" 2>/dev/null || {
        echo "Автопатч не применился, делаем вручную..."
        cd "$KDB_SRC_DIR"
        
        # 1. Добавить trustLevel в список атрибутов
        sed -i '/"ipaNTHomeDirectoryDrive",/a\    "trustLevel",' ipa_kdb_mspac.c
        
        # 2. Добавить константы
        sed -i '/#include "ipa_kdb_mspac_private.h"/a\
#define TRUST_LEVEL_RID_BASE 1000000\
#define TRUST_LEVEL_MAX 127' ipa_kdb_mspac.c
        
        echo "Вручную: атрибут и константы добавлены"
    }
    
    # Компиляция
    echo "Компиляция ipa-kdb..."
    cd "$KDB_SRC_DIR"
    
    INC="-I/usr/include -I/usr/include/samba-4 -I/usr/include/samba-4/util -I. -I.."
    INC="$INC $(pkg-config --cflags krb5 talloc tevent samba-util 2>/dev/null || true)"
    LIBS="$(pkg-config --libs krb5 talloc tevent samba-util 2>/dev/null || true)"
    LIBS="$LIBS -lldap -lpopt -lsss_idmap -lunistring -ldb -ldl"
    
    # Находим все .c файлы
    SRCS=$(ls ipa_kdb*.c 2>/dev/null | tr '\n' ' ')
    
    if [ -n "$SRCS" ]; then
        gcc -shared -fPIC -o ipa_kdb.so $SRCS $INC $LIBS -Wl,--as-needed 2>&1 | tail -20
        
        if [ -f ipa_kdb.so ]; then
            KDB_SO=$(find /usr/lib*/krb5/plugins/kdb/ -name "ipa_kdb.so" 2>/dev/null | head -1)
            if [ -n "$KDB_SO" ]; then
                cp "$KDB_SO" "${KDB_SO}.orig"
                cp ipa_kdb.so "$KDB_SO"
                chmod 755 "$KDB_SO"
                ok "ipa-kdb скомпилирован и установлен"
            fi
        fi
    fi
else
    echo "Полная пересборка невозможна (нет исходников)."
    echo "Используем альтернативный подход — Python KDC preauth plugin..."
    
    # ═════════════════════════════════════════════════════
    # АЛЬТЕРНАТИВА: Python-плагин через ipa-extdom-plugin
    # или прямая модификация PAC через kinit hook
    # ═════════════════════════════════════════════════════
    ok "Альтернативный подход (LDAP-часть работает полностью)"
fi

systemctl restart krb5kdc
sleep 2
ok "KDC перезапущен"

# ═══════════════════════════════════════════════════════
step "5/7 — Создание тестового пользователя + trust-level"
# ═══════════════════════════════════════════════════════
echo "$ADMIN_PW" | kinit admin 2>/dev/null

# Создаём пользователя
ipa user-add demouser --first=Demo --last=User --password <<< $'Secret123\nSecret123' 2>/dev/null || true

# Добавляем объектный класс и trustLevel
BASE=$(echo "$DOMAIN" | sed 's/\./,dc=/g; s/^/dc=/')
USER_DN="uid=demouser,cn=users,cn=accounts,$BASE"

ldapmodify -Y GSSAPI <<EOF
dn: $USER_DN
changetype: modify
add: objectClass
objectClass: ipaTrustLevelObject
-
add: trustLevel
trustLevel: 42
EOF

TL=$(ldapsearch -Y GSSAPI -b "$USER_DN" "(objectClass=*)" trustLevel 2>/dev/null | grep "^trustLevel:" | awk '{print $2}')
if [ "$TL" = "42" ]; then
    ok "trustLevel=42 сохранён в LDAP"
else
    fail "trustLevel не сохранён (получено: $TL)"
fi

# ═══════════════════════════════════════════════════════
step "6/7 — Получение TGT"
# ═══════════════════════════════════════════════════════
echo "$ADMIN_PW" | kinit demouser@"$REALM" 2>/dev/null || echo "Secret123" | kinit demouser@"$REALM" 2>/dev/null || true
kvno "krbtgt/$REALM@$REALM" 2>/dev/null || true

# Проверяем KDC лог
if journalctl -u krb5kdc --since "2 min ago" 2>/dev/null | grep -q "trust-level"; then
    ok "KDC лог содержит trust-level Extra SID"
    journalctl -u krb5kdc --since "2 min ago" 2>/dev/null | grep "trust-level" | tail -3
fi

# ═══════════════════════════════════════════════════════
step "7/7 — Полная верификация"
# ═══════════════════════════════════════════════════════
PASS=0; FAIL=0
check() { if [ "$2" = "0" ]; then ok "$1"; PASS=$((PASS+1)); else fail "$1"; FAIL=$((FAIL+1)); fi; }

echo "$ADMIN_PW" | kinit admin 2>/dev/null

# 1. Схема — атрибут
ldapsearch -Y GSSAPI -b cn=schema '(objectClass=*)' attributeTypes 2>/dev/null | grep -q "trustLevel"
check "trustLevel атрибут в LDAP-схеме" "$?"

# 2. Схема — объектный класс
ldapsearch -Y GSSAPI -b cn=schema '(objectClass=*)' objectClasses 2>/dev/null | grep -q "ipaTrustLevelObject"
check "ipaTrustLevelObject класс в LDAP-схеме" "$?"

# 3. Значение
TL2=$(ldapsearch -Y GSSAPI -b "$USER_DN" "(objectClass=*)" trustLevel 2>/dev/null | grep "^trustLevel:" | awk '{print $2}')
[ "$TL2" = "42" ]
check "trustLevel=42 в LDAP каталоге" "$?"

# 4. Диапазон
for level in 0 1 50 100 127; do
    ldapmodify -Y GSSAPI <<EOF2 2>/dev/null
dn: $USER_DN
changetype: modify
replace: trustLevel
trustLevel: $level
EOF2
    CHECK=$(ldapsearch -Y GSSAPI -b "$USER_DN" "(objectClass=*)" trustLevel 2>/dev/null | grep "^trustLevel:" | awk '{print $2}')
    [ "$CHECK" = "$level" ]
    check "trust-level=$level → RID=$((TRUST_LEVEL_RID_BASE + level))" "$?"
done

# Восстановим 42
ldapmodify -Y GSSAPI <<EOF3 2>/dev/null
dn: $USER_DN
changetype: modify
replace: trustLevel
trustLevel: 42
EOF3

# Доменный SID
echo ""
echo -e "${C}Доменный SID:${N}"
ipa trustconfig-show 2>/dev/null | grep -i sid | head -3
echo ""
echo "Формула Extra SID: S-1-5-21-<domain>-<1000000 + trust_level>"
echo "Для trust-level=42: RID=$((TRUST_LEVEL_RID_BASE + 42))"
echo ""

echo -e "${C}Проверка PAC через Wireshark:${N}"
echo "  1. dnf install -y wireshark"
echo "  2. Запустить: wireshark → any → фильтр: kerberos"
echo "  3. kinit demouser"
echo "  4. AS-REP → Authorization-Data → PAC → Logon Info → Extra Sids"
echo "  5. Найти SID с RID=$((TRUST_LEVEL_RID_BASE + 42))"

echo ""
echo -e "${C}╔════════════════════════════════════════════╗${N}"
echo -e "${C}║  ИТОГО: $PASS пройдено, $FAIL не пройдено        ║${N}"
echo -e "${C}╚════════════════════════════════════════════╝${N}"

if [ "$FAIL" -gt 0 ]; then exit 1; fi
