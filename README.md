# Практическая работа #3, часть 1 — FreeIPA + MIT Kerberos: trust-level в MS-PAC

## Задание

Реализовать хранение в LDAP каталоге FreeIPA численного атрибута `trust-level` (0–127) для учётных записей пользователей и передачу значения данного атрибута внутри MS-PAC сертификата пользователя (в TGT) в виде Extra SID.

---

## Быстрый старт на Fedora (полная установка с нуля)

### Требования
- Fedora Server 44 (или любой дистрибутив с пакетом freeipa-server)
- 2 CPU, 3 GB RAM, 20 GB диск
- Интернет

### Установка (копировать и вставлять по блокам)

**Блок 1 — Установка FreeIPA:**
```bash
hostnamectl set-hostname ipa.example.com
IP=$(ip -4 addr show | grep -oP 'inet \K[\d.]+' | grep -v 127 | head -1)
echo "$IP   ipa.example.com ipa localhost" > /etc/hosts
dnf install -y --exclude=openh264 freeipa-server freeipa-server-dns freeipa-server-trust-ad @development-tools gcc make autoconf automake libtool git wget python3-ldap rpm-build
ipa-server-install --domain=example.com --realm=EXAMPLE.COM --hostname=ipa.example.com --admin-password=Secret123 --ds-password=Secret123 --no-ntp --unattended
```

**Блок 2 — Добавление LDAP-схемы trust-level:**
```bash
echo Secret123 | kinit admin
ldapmodify -D "cn=Directory Manager" -w Secret123 << 'EOF'
dn: cn=schema
changetype: modify
add: attributeTypes
attributeTypes: ( 1.3.6.1.4.1.53263.999.1.1 NAME 'trustLevel' DESC 'Numerical trust level 0-127' EQUALITY integerMatch ORDERING integerOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE X-ORIGIN 'FreeIPA Trust Level' )
-
add: objectClasses
objectClasses: ( 1.3.6.1.4.1.53263.999.1.2 NAME 'ipaTrustLevelObject' DESC 'Auxiliary for trustLevel' SUP top AUXILIARY MAY ( trustLevel ) X-ORIGIN 'FreeIPA Trust Level' )
EOF
```

**Блок 3 — Скачивание исходников FreeIPA и патч:**
```bash
dnf download --source freeipa-server
rpm2cpio freeipa-*.src.rpm | cpio -idmv
dnf builddep -y --spec freeipa.spec
rpmbuild -bp freeipa.spec
KDB_DIR=$(find ~/rpmbuild/BUILD -name ipa_kdb_mspac.c | head -1 | xargs dirname)
cd $KDB_DIR

# Добавляем trustLevel в список атрибутов LDAP-запроса
sed -i '/"ipaNTHomeDirectoryDrive",$/a\    "trustLevel",' ipa_kdb_mspac.c

# Добавляем константы
sed -i '/#include "ipa_kdb_mspac_private.h"/a\
#define TRUST_LEVEL_RID_BASE 1000000\
#define TRUST_LEVEL_MAX 127' ipa_kdb_mspac.c

# Добавляем функцию ipadb_add_trust_level_sid
cat > /tmp/trust_func.c << 'FUNCEND'

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

python3 << 'PYEND'
with open("ipa_kdb_mspac.c", "r") as f:
    c = f.read()
func = open("/tmp/trust_func.c").read()
c = c.replace("static krb5_error_code\nis_master_host(", func + "\nstatic krb5_error_code\nis_master_host(")
old = "ret = ipadb_add_asserted_identity(ipactx, flags, memctx, info3);\n    return ret;"
new = "ret = ipadb_add_asserted_identity(ipactx, flags, memctx, info3);\n    if (ret == 0)\n        ret = ipadb_add_trust_level_sid(ipactx, lentry, memctx, info3);\n    return ret;"
c = c.replace(old, new, 1)
with open("ipa_kdb_mspac.c", "w") as f:
    f.write(c)
print("PATCH DONE")
PYEND
```

**Блок 4 — Сборка и установка патченного модуля:**
```bash
cd $(find ~/rpmbuild/BUILD -path "*/freeipa-4.13.1-build/freeipa-4.13.1" -type d | head -1)
./configure --prefix=/usr --sysconfdir=/etc 2>&1 | tail -3
cd util && make -j$(nproc) 2>&1 | tail -3
cd ../daemons/ipa-kdb && make -j$(nproc) 2>&1 | tail -10

# Версионный скрипт
cat > ipadb.map << 'EOF'
EXPORTED {
    global: kdb_function_table;
           certauth_ipakdb_initvt;
           kdcpolicy_ipakdb_initvt;
    local: *;
};
EOF

# Линковка с правильными зависимостями
gcc -shared -fPIC -Wl,--no-as-needed -Wl,--version-script=ipadb.map -o .libs/ipadb.so .libs/ipa_kdb.o .libs/ipa_kdb_mspac.o .libs/ipa_kdb_mspac_v9.o .libs/ipa_kdb_principals.o .libs/ipa_kdb_passwords.o .libs/ipa_kdb_pwdpolicy.o .libs/ipa_kdb_delegation.o .libs/ipa_kdb_audit_as.o .libs/ipa_kdb_certauth.o .libs/ipa_kdb_kdcpolicy.o .libs/ipa_kdb_common.o .libs/ipa_kdb_mkey.o ../../util/.libs/libutil.a -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -lldap -llber -lpopt -lsss_idmap -lsss_certmap -lunistring -ltalloc -ltevent -lsamba-util -lsamba-errors -lndr-krb5pac -lndr-standard -lndr -lcrypto -lpwquality -ldl

# Установка
cp -f /usr/lib64/krb5/plugins/kdb/ipadb.so /usr/lib64/krb5/plugins/kdb/ipadb.so.orig
cp -f .libs/ipadb.so /usr/lib64/krb5/plugins/kdb/ipadb.so
systemctl restart krb5kdc
systemctl is-active krb5kdc
```

**Блок 5 — Проверка (доказательство преподу):**
```bash
echo Secret123 | kinit admin

# 1. Создаём пользователя
ipa user-add testuser --first=Test --last=User --password <<< $'Secret123\nSecret123'

# 2. Добавляем trustLevel
ldapmodify -Y GSSAPI << 'EOF'
dn: uid=testuser,cn=users,cn=accounts,dc=example,dc=com
changetype: modify
add: objectClass
objectClass: ipaTrustLevelObject
-
add: trustLevel
trustLevel: 42
EOF

# 3. Проверяем что значение сохранено в LDAP
ldapsearch -Y GSSAPI -b "uid=testuser,cn=users,cn=accounts,dc=example,dc=com" trustLevel

# 4. Получаем TGT и проверяем Extra SID в PAC
ldappasswd -Y GSSAPI -s "NewPass123" "uid=testuser,cn=users,cn=accounts,dc=example,dc=com"
ldapmodify -Y GSSAPI << 'EOF'
dn: uid=testuser,cn=users,cn=accounts,dc=example,dc=com
changetype: modify
replace: krbPasswordExpiration
krbPasswordExpiration: 20380101000000Z
EOF
echo NewPass123 | kinit testuser@EXAMPLE.COM
grep "trust-level" /var/log/krb5kdc.log | tail -1

# 5. Проверяем разные значения 0-127
echo Secret123 | kinit admin
for level in 0 50 100 127; do
  ldapmodify -Y GSSAPI <<EOF
dn: uid=testuser,cn=users,cn=accounts,dc=example,dc=com
changetype: modify
replace: trustLevel
trustLevel: $level
EOF
  echo NewPass123 | kinit testuser@EXAMPLE.COM 2>/dev/null
  echo Secret123 | kinit admin 2>/dev/null
  grep "trust-level" /var/log/krb5kdc.log | tail -1
done
```

---

## Команды для доказательства преподу

Эти команды показывают что **каждое требование задания выполнено**:

### Требование 1: Атрибут trust-level хранится в LDAP
```bash
# Показываем что атрибут есть в схеме
ldapsearch -Y GSSAPI -b cn=schema '(objectClass=*)' attributeTypes 2>/dev/null | grep trustLevel

# Показываем что объектный класс есть
ldapsearch -Y GSSAPI -b cn=schema '(objectClass=*)' objectClasses 2>/dev/null | grep ipaTrustLevelObject

# Показываем что значение сохраняется и читается
ldapmodify -Y GSSAPI << 'EOF'
dn: uid=testuser,cn=users,cn=accounts,dc=example,dc=com
changetype: modify
replace: trustLevel
trustLevel: 42
EOF
ldapsearch -Y GSSAPI -b "uid=testuser,cn=users,cn=accounts,dc=example,dc=com" trustLevel
```
**Ожидаемый вывод:** `trustLevel: 42`

### Требование 2: Значение 0-127 корректно хранится
```bash
echo Secret123 | kinit admin
for level in 0 1 50 100 127; do
  ldapmodify -Y GSSAPI <<EOF
dn: uid=testuser,cn=users,cn=accounts,dc=example,dc=com
changetype: modify
replace: trustLevel
trustLevel: $level
EOF
  VAL=$(ldapsearch -Y GSSAPI -b "uid=testuser,cn=users,cn=accounts,dc=example,dc=com" trustLevel 2>/dev/null | grep "^trustLevel:" | awk '{print $2}')
  echo "trust-level=$VAL -> RID=$((1000000 + VAL))"
done
```
**Ожидаемый вывод:**
```
trust-level=0 -> RID=1000000
trust-level=1 -> RID=1000001
trust-level=50 -> RID=1000050
trust-level=100 -> RID=1000100
trust-level=127 -> RID=1000127
```

### Требование 3: trust-level передаётся в MS-PAC как Extra SID в TGT
```bash
# Установить trust-level=42
echo Secret123 | kinit admin
ldapmodify -Y GSSAPI << 'EOF'
dn: uid=testuser,cn=users,cn=accounts,dc=example,dc=com
changetype: modify
replace: trustLevel
trustLevel: 42
EOF

# Получить TGT
echo NewPass123 | kinit testuser@EXAMPLE.COM

# Доказательство: KDC лог показывает добавление Extra SID
grep "trust-level" /var/log/krb5kdc.log | tail -1
```
**Ожидаемый вывод:**
```
trust-level: added Extra SID for level 42 (RID=1000042)
```

### Требование 4: Формат Extra SID (доменный SID + RID)
```bash
# Узнать доменный SID
ipa trustconfig-show --all 2>/dev/null | grep "Идентификатор безопасности"
```
**Ожидаемый вывод:** `Идентификатор безопасности: S-1-5-21-2609696107-2343131759-2222240319`

**Формула Extra SID:** `S-1-5-21-<domain_sub_auths>-<1000000 + trust_level>`

Для trust-level=42: `S-1-5-21-2609696107-2343131759-2222240319-1000042`

### Требование 5 (упрощение): Перенос из TGT в TGS
FreeIPA автоматически копирует все Extra SID из TGT в TGS. Это реализовано в `ipadb_common_verify_pac()` — исходный код FreeIPA (не требует модификации).

---

## Кодирование trust-level в Extra SID

| trust-level | RID | Extra SID (пример) |
|---|---|---|
| 0 | 1000000 | S-1-5-21-X-Y-Z-1000000 |
| 42 | 1000042 | S-1-5-21-X-Y-Z-1000042 |
| 127 | 1000127 | S-1-5-21-X-Y-Z-1000127 |

**Формула:** `RID = 1_000_000 + trust_level`
**Декодировка:** `trust_level = RID - 1_000_000` (если 1_000_000 ≤ RID ≤ 1_000_127)

---

## Проверка PAC через Wireshark (визуальное доказательство)

1. `dnf install -y wireshark`
2. Запустить: `tshark -i any -f "tcp port 88" -c 10`
3. В другом терминале: `echo NewPass123 | kinit testuser@EXAMPLE.COM`
4. В AS-REP пакете: Authorization-Data → PAC → Logon Info → Extra Sids
5. Найти SID с RID = 1000000 + trust_level

---

## Структура репозитория

```
schema/99trust-level.ldif        — Расширение LDAP-схемы
patches/ipa-kdb-trust-level.patch — Патч ipa-kdb (C)
freeipa-plugin/trustlevel.py     — FreeIPA Python-плагин
setup/                           — Скрипты установки
docker/                          — Docker-окружение
tools/                           — Утилиты
report/report.md                 — Академический отчёт
```

## Технические детали

### LDAP-схема
- Атрибут `trustLevel` (OID: 1.3.6.1.4.1.53263.999.1.1) — INTEGER, SINGLE-VALUE
- Объектный класс `ipaTrustLevelObject` (OID: 1.3.6.1.4.1.53263.999.1.2) — AUXILIARY, MAY trustLevel

### Патч ipa-kdb
Модифицирует `ipa_kdb_mspac.c`:
1. Добавляет `trustLevel` в список запрашиваемых LDAP-атрибутов
2. Добавляет функцию `ipadb_add_trust_level_sid()` — читает trustLevel из LDAP, конструирует Extra SID
3. Вызывает функцию из `ipadb_fill_info3()` после `ipadb_add_asserted_identity()`

### Перенос TGT → TGS
FreeIPA автоматически копирует все SID (включая Extra SID) из TGT в TGS. Реализация для TGT достаточна.
