# Практическая работа #3, часть 1 — FreeIPA + MIT Kerberos: trust-level в MS-PAC

**Программный стек:** FreeIPA, MIT Kerberos

## Задание

Реализовать хранение в LDAP каталоге FreeIPA численного атрибута `trust-level` (0–127) для учётных записей пользователей и передачу значения данного атрибута внутри MS-PAC сертификата пользователя (в TGT) в виде Extra SID.

---

## Быстрый старт (Docker — рекомендуется для Arch Linux)

```bash
git clone https://github.com/BuMcHiKa/FreeIPA_3.1.git
cd FreeIPA_3.1

# 1. Запуск контейнера FreeIPA
cd docker/
docker-compose up -d

# 2. Инициализация FreeIPA (при первом запуске)
docker exec -it freeipa-server ipa-server-install \
    --domain=example.com --realm=EXAMPLE.COM \
    --hostname=ipa.example.com \
    --admin-password=Secret123 --ds-password=Secret123 \
    --no-ntp --unattended

# 3. Применение trust-level патча внутри контейнера
docker exec -it freeipa-server /tmp/setup-inside-container.sh example.com

# 4. Демонстрация
docker exec -it freeipa-server bash /vagrant/demo.sh example.com
```

## Быстрый старт (прямая установка на Arch/Fedora)

```bash
git clone https://github.com/BuMcHiKa/FreeIPA_3.1.git
cd FreeIPA_3.1

# Пошаговая установка:
sudo bash setup/00-prerequisites-arch.sh    # Зависимости Arch
sudo bash setup/01-setup-freeipa.sh example.com  # Установка FreeIPA
sudo bash setup/02-add-ldap-schema.sh       # LDAP-схема trust-level
sudo bash setup/03-install-plugin.sh         # Python-плагин (опционально)
sudo bash setup/04-patch-and-rebuild-ipa-kdb.sh  # Патч ipa-kdb + пересборка
bash setup/05-verify.sh                     # Верификация
```

---

## Использование

### Установка trust-level для пользователя

```bash
# Способ 1: через LDAP (универсальный)
ldapmodify -Y GSSAPI <<EOF
dn: uid=testuser,cn=users,cn=accounts,dc=example,dc=com
changetype: modify
add: objectClass
objectClass: ipaTrustLevelObject
-
add: trustLevel
trustLevel: 42
EOF

# Способ 2: через FreeIPA CLI (если установлен плагин)
ipa user-mod testuser --trustlevel=42

# Способ 3: через helper-скрипт
bash tools/set-trust-level.sh testuser 42
```

### Чтение trust-level

```bash
# Через LDAP
ldapsearch -Y GSSAPI -b "uid=testuser,cn=users,cn=accounts,dc=example,dc=com" trustLevel

# Через helper
bash tools/get-trust-level.sh testuser
```

### Проверка Extra SID в TGT

```bash
# 1. Получить TGT
kinit testuser

# 2. Wireshark: фильтр kerberos.msg_type == 11
#    В AS-REP → Authorization-Data → PAC → Logon Info → Extra Sids
#    Найти SID с RID = 1000000 + trust_level

# 3. Через журнал KDC
journalctl -u krb5kdc | grep "trust-level"
```

---

## Кодирование trust-level в Extra SID

| trust-level | RID | Extra SID (пример) |
|---|---|---|
| 0 | 1000000 | S-1-5-21-X-Y-Z-1000000 |
| 42 | 1000042 | S-1-5-21-X-Y-Z-1000042 |
| 127 | 1000127 | S-1-5-21-X-Y-Z-1000127 |

**Формула:** `RID = 1 000 000 + trust_level`

**Декодировка:** `trust_level = RID - 1 000 000` (если `1 000 000 ≤ RID ≤ 1 000 127`)

---

## Структура репозитория

```
.
├── README.md                       # Данная документация
├── demo.sh                         # Скрипт демонстрации для защиты
├── schema/99trust-level.ldif        # Расширение LDAP-схемы
├── patches/ipa-kdb-trust-level.patch # Патч ipa-kdb (C)
├── freeipa-plugin/trustlevel.py     # FreeIPA Python-плагин
├── setup/                          # Скрипты установки
├── docker/                         # Docker-окружение
├── tools/                          # Утилиты
└── report/report.md                # Академический отчёт
```

---

## Технические детали

### LDAP-схема

- Атрибут `trustLevel` (OID: `1.3.6.1.4.1.53263.999.1.1`) — INTEGER, SINGLE-VALUE
- Объектный класс `ipaTrustLevelObject` (OID: `1.3.6.1.4.1.53263.999.1.2`) — AUXILIARY, MAY trustLevel

### Патч ipa-kdb

Модифицирует `ipa_kdb_mspac.c`:

1. Добавляет `trustLevel` в список атрибутов, запрашиваемых из LDAP
2. Добавляет функцию `ipadb_add_trust_level_sid()` — считывает trustLevel из LDAP и добавляет Extra SID в `netr_SamInfo3`
3. Вызывает функцию из `ipadb_fill_info3()` после `ipadb_add_asserted_identity()`

### Почему RID_BASE = 1 000 000

- Пользовательские RID в FreeIPA начинаются с ~1000
- Групповые RID в том же диапазоне
- RID 1 000 000+ гарантированно не конфликтует с системными RID
- Диапазон 1 000 000–1 000 127 уникально идентифицирует trust-level SID

### Перенос TGT → TGS

FreeIPA автоматически копирует все SID (включая Extra SID) из TGT в TGS при обработке TGS-REQ. Реализация для TGT достаточна.
