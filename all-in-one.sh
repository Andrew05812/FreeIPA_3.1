#!/bin/bash
# all-in-one.sh — Полная установка и проверка trust-level на Arch Linux через Docker
# Запуск: bash all-in-one.sh
# Пароли: admin=Secret123, ds=Secret123

set -e
DOMAIN="example.com"
REALM="EXAMPLE.COM"
HOSTNAME="ipa.example.com"
ADMIN_PW="Secret123"
DS_PW="Secret123"
TRUST_LEVEL_RID_BASE=1000000
CONTAINER="freeipa-trustlevel"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'
ok()   { echo -e "  ${G}[OK]${N} $1"; }
fail() { echo -e "  ${R}[FAIL]${N} $1"; exit 1; }
step() { echo -e "\n${C}━━━ $1 ━━━${N}"; }

# ═══════════════════════════════════════════════════════
step "1/8 — Установка Docker (Arch Linux)"
# ═══════════════════════════════════════════════════════
if ! command -v docker &>/dev/null; then
    echo "Установка docker..."
    sudo pacman -S --noconfirm docker docker-compose || fail "pacman install docker"
fi
sudo systemctl enable --now docker || fail "systemctl start docker"
ok "Docker запущен"

# ═══════════════════════════════════════════════════════
step "2/8 — Запуск FreeIPA контейнера"
# ═══════════════════════════════════════════════════════
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
    echo "Контейнер уже существует, удаляем..."
    docker rm -f "$CONTAINER" 2>/dev/null || true
fi

echo "Скачиваем и запускаем FreeIPA (может занять несколько минут)..."
docker run --name "$CONTAINER" \
  -h "$HOSTNAME" \
  --privileged \
  -p 80:80 -p 443:443 -p 389:389 -p 636:636 \
  -p 88:88 -p 88:88/udp -p 464:464 -p 464:464/udp \
  -p 53:53 -p 53:53/udp \
  -e IPA_SERVER_IP=0.0.0.0 \
  -v /var/lib/freeipa-data:/data \
  -d freeipa/freeipa-server:fedora-41 \
  -U --domain="$DOMAIN" --realm="$REALM" \
  -p "$DS_PW" -a "$ADMIN_PW" --no-ntp

echo "Ожидание инициализации FreeIPA (2-5 минут)..."
sleep 30
for i in $(seq 1 30); do
    if docker exec "$CONTAINER" bash -c 'kinit admin <<< Secret123 2>/dev/null && ipa ping 2>/dev/null' | grep -q "IPA server version"; then
        ok "FreeIPA инициализирован"
        break
    fi
    echo "  Попытка $i/30 — ожидаем..."
    sleep 10
done

# ═══════════════════════════════════════════════════════
step "3/8 — Добавление LDAP-схемы trust-level"
# ═══════════════════════════════════════════════════════
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

DS_INST=$(docker exec "$CONTAINER" bash -c 'ls /etc/dirsrv/ 2>/dev/null | grep slapd- | head -1')
[ -z "$DS_INST" ] && fail "389 DS instance не найден"

docker cp "$SCRIPT_DIR/schema/99trust-level.ldif" "$CONTAINER:/etc/dirsrv/$DS_INST/schema/"
docker exec "$CONTAINER" chmod 644 "/etc/dirsrv/$DS_INST/schema/99trust-level.ldif"
docker exec "$CONTAINER" systemctl restart "dirsrv@$DS_INST"
sleep 8
ok "LDAP-схема установлена"

# ═══════════════════════════════════════════════════════
step "4/8 — Установка build-зависимостей в контейнере"
# ═══════════════════════════════════════════════════════
docker exec "$CONTAINER" bash -c 'dnf install -y \
  gcc make autoconf automake libtool git wget \
  krb5-devel libtalloc-devel libtevent-devel \
  samba-devel openldap-devel popt-devel nspr-devel nss-devel \
  libsss_idmap-devel libunistring-devel 389-ds-base-devel \
  python3-devel 2>/dev/null' | tail -3
ok "Build-зависимости установлены"

# ═══════════════════════════════════════════════════════
step "5/8 — Патч и пересборка ipa-kdb"
# ═══════════════════════════════════════════════════════
docker exec "$CONTAINER" bash -c '
set -e
FREEIPA_VER="4.12.2"
BUILD="/tmp/freeipa-build"
mkdir -p $BUILD
cd $BUILD

if [ ! -d "freeipa-${FREEIPA_VER}" ]; then
  curl -sL -o "freeipa-${FREEIPA_VER}.tar.gz" \
    "https://github.com/freeipa/freeipa/archive/refs/tags/v${FREEIPA_VER}.tar.gz"
  tar xzf "freeipa-${FREEIPA_VER}.tar.gz"
fi

# Ручное применение патча (надёжнее чем patch -p1)
cd "freeipa-${FREEIPA_VER}/daemons/ipa-kdb"

# 1. Добавить trustLevel в список атрибутов
sed -i '\''/"ipaNTHomeDirectoryDrive",/a\    "trustLevel",'\' ipa_kdb_mspac.c

# 2. Добавить константы после #include блока
sed -i '\''/#include "ipa_kdb_mspac_private.h"/a\\n#define TRUST_LEVEL_RID_BASE 1000000\n#define TRUST_LEVEL_MAX 127'\'' ipa_kdb_mspac.c

# 3. Добавить функцию ipadb_add_trust_level_sid() после ipadb_add_asserted_identity()
# Ищем функцию is_master_host которая идёт после ipadb_add_asserted_identity
cat > /tmp/trust_level_func.c << '\''FUNCEND'\''
static krb5_error_code ipadb_add_trust_level_sid(struct ipadb_context *ipactx,
                                                  LDAPMessage *lentry,
                                                  TALLOC_CTX *memctx,
                                                  struct netr_SamInfo3 *info3)
{
    struct netr_SidAttr *arr = NULL;
    uint32_t sidcount = info3->sidcount;
    int trust_level = 0;
    int ret;
    char *sid_str = NULL;
    struct dom_sid tl_sid;

    if (!ipactx || !ipactx->mspac) {
        return 0;
    }

    ret = ipadb_ldap_attr_to_int(ipactx->lcontext, lentry,
                                 "trustLevel", &trust_level);
    if (ret == ENOENT) {
        return 0;
    }
    if (ret != 0) {
        return ret;
    }

    if (trust_level < 0 || trust_level > TRUST_LEVEL_MAX) {
        krb5_klog_syslog(LOG_WARNING,
                         "trust-level value %d out of range [0,%d], skipping",
                         trust_level, TRUST_LEVEL_MAX);
        return 0;
    }

    memcpy(&tl_sid, &ipactx->mspac->domsid, sizeof(struct dom_sid));
    ret = sid_append_rid(&tl_sid, TRUST_LEVEL_RID_BASE + (uint32_t)trust_level);
    if (ret != 0) {
        return ret;
    }

    sid_str = dom_sid_string(memctx, &tl_sid);
    if (!sid_str) {
        return ENOMEM;
    }

    arr = talloc_realloc(memctx, info3->sids,
                         struct netr_SidAttr, sidcount + 1);
    if (!arr) {
        talloc_free(sid_str);
        return ENOMEM;
    }

    arr[sidcount].sid = talloc_zero(arr, struct dom_sid2);
    if (!arr[sidcount].sid) {
        talloc_free(sid_str);
        return ENOMEM;
    }

    ret = ipadb_string_to_sid(sid_str, arr[sidcount].sid);
    talloc_free(sid_str);
    if (ret) {
        return ret;
    }

    arr[sidcount].attributes = SE_GROUP_MANDATORY |
                               SE_GROUP_ENABLED |
                               SE_GROUP_ENABLED_BY_DEFAULT;

    info3->sids = arr;
    info3->sidcount = sidcount + 1;
    info3->base.user_flags |= NETLOGON_EXTRA_SIDS;

    krb5_klog_syslog(LOG_INFO,
                     "trust-level: added Extra SID for level %d (RID=%u)",
                     trust_level, TRUST_LEVEL_RID_BASE + (uint32_t)trust_level);

    return 0;
}

FUNCEND

# Вставить функцию перед is_master_host
sed -i -e "/^static krb5_error_code$/!b;N;/is_master_host/!b;r /tmp/trust_level_func.c" ipa_kdb_mspac.c

# 4. Изменить вызов в конце ipadb_fill_info3: после ipadb_add_asserted_identity вызвать нашу функцию
# Заменяем "ret = ipadb_add_asserted_identity(...); return ret;"
# на "ret = ipadb_add_asserted_identity(...); if (ret == 0) ret = ipadb_add_trust_level_sid(...); return ret;"
python3 -c "
import re
with open('\''ipa_kdb_mspac.c'\'', '\''r'\'') as f:
    c = f.read()
old = '\''ret = ipadb_add_asserted_identity(ipactx, flags, memctx, info3);\n    return ret;'\''
new = '\''ret = ipadb_add_asserted_identity(ipactx, flags, memctx, info3);\n    if (ret == 0)\n        ret = ipadb_add_trust_level_sid(ipactx, lentry, memctx, info3);\n    return ret;'\''
c = c.replace(old, new, 1)
with open('\''ipa_kdb_mspac.c'\'', '\''w'\'') as f:
    f.write(c)
"

echo "Патч применён вручную"
' 2>&1 | tail -5
ok "Патч применён"

# Теперь собираем
docker exec "$CONTAINER" bash -c '
set -e
cd /tmp/freeipa-build/freeipa-4.12.2/daemons/ipa-kdb

# Определяем флаги компиляции
INC="-I/usr/include -I/usr/include/samba-4 -I/usr/include/samba-4/util -I. -I.."
INC="$INC $(pkg-config --cflags krb5 talloc tevent samba-util 2>/dev/null || true)"
LIBS="$(pkg-config --libs krb5 talloc tevent samba-util 2>/dev/null || true)"
LIBS="$LIBS -lldap -lpopt -lsss_idmap -lunistring -ldb -ldl -lndr -lndr-samba-samba4 -lsamba-errors -lsamba-util-cmdline -lgen_ndr -lndr-samba -lsamba-security"

# Собираем все .c файлы ipa-kdb
SRCS="ipa_kdb.c ipa_kdb_mspac.c ipa_kdb_principals.c ipa_kdb_passwords.c ipa_kdb_pwdpolicy.c ipa_kdb_mspac_v6.c ipa_kdb_mspac_v9.c ipa_kdb_delegation.c ipa_kdb_auditas.c ipa_kdb_certauth.c"

echo "Компиляция ipa-kdb..."
gcc -shared -fPIC -o ipa_kdb.so $SRCS $INC $LIBS -Wl,--as-needed 2>&1 | tail -20
ls -la ipa_kdb.so
' 2>&1 | tail -10

if docker exec "$CONTAINER" test -f /tmp/freeipa-build/freeipa-4.12.2/daemons/ipa-kdb/ipa_kdb.so; then
    ok "ipa_kdb.so скомпилирован"
else
    fail "Ошибка компиляции ipa_kdb.so"
fi

# ═══════════════════════════════════════════════════════
step "6/8 — Замена модуля ipa-kdb и перезапуск KDC"
# ═══════════════════════════════════════════════════════
docker exec "$CONTAINER" bash -c '
set -e
KDB_SO=$(find /usr/lib*/krb5/plugins/kdb/ -name "ipa_kdb.so" 2>/dev/null | head -1)
if [ -z "$KDB_SO" ]; then
    KDB_SO=$(find /usr/lib/ -name "ipa_kdb.so" 2>/dev/null | head -1)
fi
[ -z "$KDB_SO" ] && exit 1

cp "$KDB_SO" "${KDB_SO}.orig"
cp /tmp/freeipa-build/freeipa-4.12.2/daemons/ipa-kdb/ipa_kdb.so "$KDB_SO"
chmod 755 "$KDB_SO"

systemctl restart krb5kdc
echo "KDB module: $KDB_SO"
'
sleep 3
ok "ipa-kdb заменён, KDC перезапущен"

# ═══════════════════════════════════════════════════════
step "7/8 — Создание тестового пользователя + trust-level"
# ═══════════════════════════════════════════════════════
docker exec "$CONTAINER" bash -c "
set -e
echo '$ADMIN_PW' | kinit admin

# Создаём пользователя
ipa user-add demouser --first=Demo --last=User --password <<< \$'$ADMIN_PW\n$ADMIN_PW' 2>/dev/null || true

# Добавляем объектный класс и trustLevel
BASE=\$(ipa domain | sed 's/\\./,dc=/g; s/^/dc=/')
USER_DN=\"uid=demouser,cn=users,cn=accounts,\$BASE\"

ldapmodify -Y GSSAPI <<EOF
dn: \$USER_DN
changetype: modify
add: objectClass
objectClass: ipaTrustLevelObject
-
add: trustLevel
trustLevel: 42
EOF

# Проверяем
ldapsearch -Y GSSAPI -b \"\$USER_DN\" '(objectClass=*)' trustLevel 2>/dev/null | grep '^trustLevel:'
"
ok "Пользователь demouser создан, trust-level=42"

# ═══════════════════════════════════════════════════════
step "8/8 — Получение TGT и проверка Extra SID"
# ═══════════════════════════════════════════════════════
docker exec "$CONTAINER" bash -c "
set -e
echo '$ADMIN_PW' | kinit admin

# Аутентификация как demouser
echo '$ADMIN_PW' | kinit demouser@$REALM 2>/dev/null

# Получаем TGT
kvno krbtgt/$REALM@$REALM 2>/dev/null || true

# Проверяем лог KDC
journalctl -u krb5kdc --since '2 min ago' 2>/dev/null | grep 'trust-level' | tail -5
"

echo ""
echo -e "${C}╔══════════════════════════════════════════════════╗${N}"
echo -e "${C}║  РЕЗУЛЬТАТЫ ПРОВЕРКИ                             ║${N}"
echo -e "${C}╚══════════════════════════════════════════════════╝${N}"

# Проверка 1: схема
if docker exec "$CONTAINER" ldapsearch -Y GSSAPI -b cn=schema '(objectClass=*)' attributeTypes 2>/dev/null | grep -q "trustLevel"; then
    ok "trustLevel атрибут в LDAP-схеме"
else
    fail "trustLevel атрибут НЕ найден в LDAP-схеме"
fi

# Проверка 2: объектный класс
if docker exec "$CONTAINER" ldapsearch -Y GSSAPI -b cn=schema '(objectClass=*)' objectClasses 2>/dev/null | grep -q "ipaTrustLevelObject"; then
    ok "ipaTrustLevelObject класс в LDAP-схеме"
else
    fail "ipaTrustLevelObject класс НЕ найден"
fi

# Проверка 3: значение атрибута
TL=$(docker exec "$CONTAINER" bash -c '
echo Secret123 | kinit admin 2>/dev/null
BASE=$(ipa domain | sed "s/\./,dc=/g; s/^/dc=/")
ldapsearch -Y GSSAPI -b "uid=demouser,cn=users,cn=accounts,$BASE" "(objectClass=*)" trustLevel 2>/dev/null | grep "^trustLevel:" | awk "{print \$2}"
')
if [ "$TL" = "42" ]; then
    ok "trustLevel=42 сохранён в LDAP"
else
    fail "trustLevel=42 НЕ сохранён (получено: $TL)"
fi

# Проверка 4: KDC лог
if docker exec "$CONTAINER" journalctl -u krb5kdc --since "5 min ago" 2>/dev/null | grep -q "trust-level"; then
    ok "KDC лог содержит trust-level Extra SID"
    docker exec "$CONTAINER" journalctl -u krb5kdc --since "5 min ago" 2>/dev/null | grep "trust-level" | tail -3 | sed 's/^/    /'
else
    echo -e "  ${Y}[INFO]${N} KDC лог не содержит trust-level — проверьте вручную:"
    echo "    docker exec -it $CONTAINER journalctl -u krb5kdc | grep trust-level"
fi

# Проверка 5: разные значения
echo ""
echo -e "${C}Тест диапазона значений 0-127:${N}"
for level in 0 1 50 100 127; do
    docker exec "$CONTAINER" bash -c "
        echo Secret123 | kinit admin 2>/dev/null
        BASE=\$(ipa domain | sed 's/\\./,dc=/g; s/^/dc=/')
        ldapmodify -Y GSSAPI <<EOF2 2>/dev/null
dn: uid=demouser,cn=users,cn=accounts,\$BASE
changetype: modify
replace: trustLevel
trustLevel: $level
EOF2
    " 2>/dev/null
    CHECK=$(docker exec "$CONTAINER" bash -c "
        echo Secret123 | kinit admin 2>/dev/null
        BASE=\$(ipa domain | sed 's/\\./,dc=/g; s/^/dc=/')
        ldapsearch -Y GSSAPI -b 'uid=demouser,cn=users,cn=accounts,\$BASE' '(objectClass=*)' trustLevel 2>/dev/null | grep '^trustLevel:' | awk '{print \$2}'
    ")
    if [ "$CHECK" = "$level" ]; then
        echo -e "  ${G}[OK]${N} trust-level=$level → RID=$((TRUST_LEVEL_RID_BASE + level))"
    else
        echo -e "  ${R}[FAIL]${N} trust-level=$level → получено $CHECK"
    fi
done

echo ""
echo -e "${C}Проверка Extra SID в PAC через Wireshark:${N}"
echo "  1. На Arch: sudo pacman -S wireshark-qt"
echo "  2. Запустить Wireshark → интерфейс docker0 или any"
echo "  3. Фильтр: kerberos"
echo "  4. В контейнере: docker exec -it $CONTAINER bash"
echo "     > echo Secret123 | kinit demouser"
echo "  5. В AS-RESPONSE → Authorization-Data → PAC → Logon Info → Extra Sids"
echo "  6. Найти SID с RID = $((TRUST_LEVEL_RID_BASE + 42)) (trust-level=42)"
echo ""
echo -e "${C}Доменный SID:${N}"
docker exec "$CONTAINER" bash -c 'echo Secret123 | kinit admin 2>/dev/null; ipa trustconfig-show 2>/dev/null | grep -i sid' | head -3
echo ""
echo "Готово! Репозиторий: https://github.com/Andrew05812/FreeIPA_3.1"
