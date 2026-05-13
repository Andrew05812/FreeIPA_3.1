#!/bin/bash
# fix-plugin.sh — Патч + сборка ipa-kdb плагина
# Запуск: sudo bash fix-plugin.sh

set -e

KDB=$(find ~/rpmbuild/BUILD -name ipa_kdb_mspac.c | head -1 | xargs dirname)
cd "$KDB"

echo "[1/6] Добавляем trustLevel в список атрибутов..."
if grep -q '"trustLevel"' ipa_kdb_mspac.c; then
  echo "  Уже добавлено"
else
  sed -i '/"ipaNTHomeDirectoryDrive",$/a\    "trustLevel",' ipa_kdb_mspac.c
  echo "  Добавлено"
fi

echo "[2/6] Добавляем константы TRUST_LEVEL_RID_BASE и TRUST_LEVEL_MAX..."
if grep -q TRUST_LEVEL_RID_BASE ipa_kdb_mspac.c; then
  echo "  Уже добавлены"
else
  sed -i '/#include "ipa_kdb_mspac_private.h"/a\
#define TRUST_LEVEL_RID_BASE 1000000\
#define TRUST_LEVEL_MAX 127' ipa_kdb_mspac.c
  echo "  Добавлены"
fi

echo "[3/6] Добавляем функцию ipadb_add_trust_level_sid..."
if grep -q ipadb_add_trust_level_sid ipa_kdb_mspac.c; then
  echo "  Уже добавлена"
else
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
with open("ipa_kdb_mspac.c", "w") as f:
    f.write(c)
PYEND

  echo "  Функция добавлена"
fi

echo "[4/6] Добавляем вызов ipadb_add_trust_level_sid..."
if grep -q "ipadb_add_trust_level_sid(ipactx, lentry" ipa_kdb_mspac.c; then
  echo "  Уже добавлен"
else
  python3 << 'PYEND'
with open("ipa_kdb_mspac.c", "r") as f:
    c = f.read()
old = "ret = ipadb_add_asserted_identity(ipactx, flags, memctx, info3);\n    return ret;"
new = "ret = ipadb_add_asserted_identity(ipactx, flags, memctx, info3);\n    if (ret == 0)\n        ret = ipadb_add_trust_level_sid(ipactx, lentry, memctx, info3);\n    return ret;"
c = c.replace(old, new, 1)
with open("ipa_kdb_mspac.c", "w") as f:
    f.write(c)
PYEND

  echo "  Вызов добавлен"
fi

echo "[5/6] Сборка..."
BUILD_ROOT=$(find ~/rpmbuild/BUILD -path "*/freeipa-4.13.1-build*/freeipa-4.13.1" -type d | head -1)
if [ -z "$BUILD_ROOT" ]; then
  BUILD_ROOT=$(find ~/rpmbuild/BUILD -name "freeipa-4.13.1" -type d | head -1)
fi
cd "$BUILD_ROOT"
./configure --prefix=/usr --sysconfdir=/etc 2>&1 | tail -3
cd util && make -j$(nproc) 2>&1 | tail -3
cd ../daemons/ipa-kdb && make -j$(nproc) 2>&1 | tail -10

cat > ipadb.map << 'EOF'
EXPORTED {
    global: kdb_function_table;
           certauth_ipakdb_initvt;
           kdcpolicy_ipakdb_initvt;
    local: *;
};
EOF

gcc -shared -fPIC -Wl,--no-as-needed -Wl,--version-script=ipadb.map -o .libs/ipadb.so \
  .libs/ipa_kdb.o .libs/ipa_kdb_mspac.o .libs/ipa_kdb_mspac_v9.o \
  .libs/ipa_kdb_principals.o .libs/ipa_kdb_passwords.o .libs/ipa_kdb_pwdpolicy.o \
  .libs/ipa_kdb_delegation.o .libs/ipa_kdb_audit_as.o .libs/ipa_kdb_certauth.o \
  .libs/ipa_kdb_kdcpolicy.o .libs/ipa_kdb_common.o .libs/ipa_kdb_mkey.o \
  ../../util/.libs/libutil.a \
  -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err -lldap -llber -lpopt \
  -lsss_idmap -lsss_certmap -lunistring -ltalloc -ltevent \
  -lsamba-util -lsamba-errors -lndr-krb5pac -lndr-standard -lndr \
  -lcrypto -lpwquality -ldl

echo "[6/6] Установка плагина..."
cp -f /usr/lib64/krb5/plugins/kdb/ipadb.so /usr/lib64/krb5/plugins/kdb/ipadb.so.orig
cp -f .libs/ipadb.so /usr/lib64/krb5/plugins/kdb/ipadb.so
systemctl restart krb5kdc

echo ""
echo "ГОТОВО! Плагин установлен. Проверка:"
echo "  strings /usr/lib64/krb5/plugins/kdb/ipadb.so | grep trust-level"
