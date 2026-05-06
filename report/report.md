# Отчёт по практической работе #3, часть 1

## Программный стек: FreeIPA, MIT Kerberos

### Задача

Реализовать хранение в LDAP каталоге FreeIPA численного атрибута `trust-level` (0–127) для учётных записей пользователей и передачу значения данного атрибута внутри MS-PAC сертификата пользователя в TGT билетах MIT Kerberos в виде Extra SID.

---

## 1. Архитектура решения

### 1.1. Общая схема

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  LDAP-каталог│────▶│   ipa-kdb (KDB)  │────▶│  MS-PAC в TGT       │
│  trustLevel  │     │  plugin (patched)│     │  Extra SID          │
└─────────────┘     └──────────────────┘     └─────────────────────┘
     389 DS              MIT Kerberos           krb5kdc
```

**Поток данных:**

1. Администратор устанавливает атрибут `trustLevel` (0–127) в LDAP-записи пользователя
2. При запросе TGT билета KDC вызывает KDB-плагин `ipa-kdb`
3. Патченный `ipa-kdb` считывает `trustLevel` из LDAP и формирует Extra SID
4. Extra SID добавляется в структуру `netr_SamInfo3` → `PAC_LOGON_INFO`
5. PAC подписывается и вкладывается в TGT билет

### 1.2. Кодирование trust-level в Extra SID

Формат Extra SID:

```
S-1-5-21-<domain_sub_auth_1>-<domain_sub_auth_2>-<domain_sub_auth_3>-<RID>
```

где:

- `S-1-5-21-...` — доменный SID (идентичен SID домена FreeIPA)
- `RID = TRUST_LEVEL_RID_BASE + trust_level`
- `TRUST_LEVEL_RID_BASE = 1 000 000`

**Пример:**

- `trust_level = 42` → `S-1-5-21-X-Y-Z-1000042`
- `trust_level = 0` → `S-1-5-21-X-Y-Z-1000000`
- `trust_level = 127` → `S-1-5-21-X-Y-Z-1000127`

**Извлечение trust-level получателем:**

```
trust_level = RID - 1_000_000
```

при условии, что `1_000_000 ≤ RID ≤ 1_000_127`.

RID-диапазон 1 000 000–1 000 127 не пересекается с обычными RID пользователей и групп FreeIPA (начиная с 1000), что гарантирует однозначную интерпретацию.

---

## 2. Расширение LDAP-схемы

### 2.1. Новый атрибут

- **Имя:** `trustLevel`
- **OID:** `1.3.6.1.4.1.53263.999.1.1` (под-arc OID FreeIPA `1.3.6.1.4.1.53263`)
- **Синтаксис:** `1.3.6.1.4.1.1466.115.121.1.27` (INTEGER)
- **Совпадение:** `integerMatch`, `integerOrderingMatch`
- **Кратность:** SINGLE-VALUE
- **Диапазон:** 0–127 (ограничение на уровне приложения)

### 2.2. Вспомогательный объектный класс

- **Имя:** `ipaTrustLevelObject`
- **OID:** `1.3.6.1.4.1.53263.999.1.2`
- **SUP:** `top`
- **Тип:** AUXILIARY
- **MAY:** `trustLevel`

Использование AUXILIARY объектного класса позволяет добавлять атрибут `trustLevel` к существующим записям пользователей (которые уже имеют классы `posixAccount`, `ipaUser`, `krbPrincipalAux` и т.д.) без модификации их структурного класса.

### 2.3. Файл схемы

См. `schema/99trust-level.ldif`. Файл помещается в каталог `/etc/dirsrv/slapd-<INSTANCE>/schema/` и загружается автоматически при перезапуске 389 DS.

---

## 3. Модификация ipa-kdb для добавления Extra SID в MS-PAC

### 3.1. Обзор MS-PAC в FreeIPA

FreeIPA генерирует MS-PAC через KDB-плагин `ipa-kdb`, который:

1. В DAL версиях 6–8: через callback `sign_authdata` → `ipadb_sign_authdata()` → `ipadb_get_pac()`
2. В DAL версии 9+: через callback `issue_pac` → `ipadb_v9_issue_pac()` → `ipadb_get_pac()`

Функция `ipadb_get_pac()` вызывает `ipadb_fill_info3()`, которая заполняет структуру `netr_SamInfo3` — ядро `PAC_LOGON_INFO`. В `netr_SamInfo3` Extra SID хранятся в полях:

- `info3.sids` — массив `struct netr_SidAttr`
- `info3.sidcount` — количество Extra SID

FreeIPA уже использует Extra SID для Asserted Identity (S-1-18-1 / S-1-18-2) через функцию `ipadb_add_asserted_identity()`.

### 3.2. Внесённые изменения

**Файл:** `daemons/ipa-kdb/ipa_kdb_mspac.c`

#### Изменение 1: Добавление атрибута в список запросов к LDAP

```c
static char *user_pac_attrs[] = {
    ...
    "ipaNTHomeDirectoryDrive",
    "trustLevel",       // <-- добавлено
    NULL
};
```

Без этого LDAP-запрос не вернёт атрибут `trustLevel`.

#### Изменение 2: Добавление констант

```c
#define TRUST_LEVEL_RID_BASE 1000000
#define TRUST_LEVEL_MAX 127
```

#### Изменение 3: Функция `ipadb_add_trust_level_sid()`

Новая функция, аналогичная `ipadb_add_asserted_identity()`, которая:

1. Читает `trustLevel` из LDAP-записи пользователя
2. Если атрибут отсутствует — возвращает 0 (не добавляет Extra SID)
3. Проверяет диапазон 0–127
4. Конструирует SID на основе доменного SID + RID
5. Добавляет его в массив `info3->sids` как Extra SID
6. Устанавливает флаг `NETLOGON_EXTRA_SIDS`
7. Логирует добавление

Ключевой фрагмент:

```c
memcpy(&tl_sid, &ipactx->mspac->domsid, sizeof(struct dom_sid));
sid_append_rid(&tl_sid, TRUST_LEVEL_RID_BASE + (uint32_t)trust_level);
// ... добавление в info3->sids ...
```

#### Изменение 4: Вызов из `ipadb_fill_info3()`

В конец функции `ipadb_fill_info3()`, после `ipadb_add_asserted_identity()`:

```c
ret = ipadb_add_asserted_identity(ipactx, flags, memctx, info3);
if (ret == 0)
    ret = ipadb_add_trust_level_sid(ipactx, lentry, memctx, info3);
return ret;
```

### 3.3. Полный патч

См. `patches/ipa-kdb-trust-level.patch`.

### 3.4. Перенос из TGT в TGS

FreeIPA автоматически копирует все SID из TGT в TGS при обработке TGS-REQ, что подтверждается в коде `ipadb_common_verify_pac()` и `ipadb_verify_pac()`. Поэтому реализация для TGT достаточна, как указано в упрощении задания.

---

## 4. FreeIPA Python-плагин (опционально)

Файл `freeipa-plugin/trustlevel.py` добавляет параметр `--trustlevel` к командам `ipa user-mod`, `ipa user-show`, `ipa user-find`.

Альтернативно, можно использовать прямое LDAP-модифицирование:

```bash
# Добавить объектный класс
ldapmodify -Y GSSAPI <<EOF
dn: uid=testuser,cn=users,cn=accounts,dc=example,dc=com
changetype: modify
add: objectClass
objectClass: ipaTrustLevelObject
-
add: trustLevel
trustLevel: 42
EOF

# Изменить значение
ldapmodify -Y GSSAPI <<EOF
dn: uid=testuser,cn=users,cn=accounts,dc=example,dc=com
changetype: modify
replace: trustLevel
trustLevel: 5
EOF
```

---

## 5. Процедура установки

### Вариант A: Docker (рекомендуется для Arch Linux)

```bash
cd docker/
docker-compose up -d
# Подождать инициализацию FreeIPA
docker exec -it freeipa-server /tmp/setup-inside-container.sh example.com
```

### Вариант B: Прямая установка на Arch Linux

```bash
sudo bash setup/00-prerequisites-arch.sh
sudo bash setup/01-setup-freeipa.sh example.com
sudo bash setup/02-add-ldap-schema.sh
sudo bash setup/03-install-plugin.sh
sudo bash setup/04-patch-and-rebuild-ipa-kdb.sh
```

### Вариант C: Fedora/CentOS/RHEL

```bash
sudo dnf install -y freeipa-server
sudo ipa-server-install ...
sudo bash setup/02-add-ldap-schema.sh
sudo bash setup/04-patch-and-rebuild-ipa-kdb.sh
```

---

## 6. Верификация

### 6.1. Автоматическая

```bash
bash setup/05-verify.sh
```

### 6.2. Демонстрация

```bash
bash demo.sh example.com
```

### 6.3. Ручная верификация через Wireshark

1. Запустить Wireshark
2. Фильтр: `kerberos.msg_type == 11`
3. Получить TGT: `kinit testuser`
4. В AS-REP → Authorization-Data → PAC → Logon Info → Extra Sids
5. Найти SID с RID в диапазоне 1000000–1000127
6. trust-level = RID − 1000000

---

## 7. Структура репозитория

```
.
├── README.md                    # Документация
├── demo.sh                      # Скрипт демонстрации
├── schema/
│   └── 99trust-level.ldif       # Расширение LDAP-схемы
├── patches/
│   └── ipa-kdb-trust-level.patch # Патч ipa-kdb для Extra SID
├── freeipa-plugin/
│   └── trustlevel.py            # FreeIPA Python-плагин
├── setup/
│   ├── 00-prerequisites-arch.sh
│   ├── 01-setup-freeipa.sh
│   ├── 02-add-ldap-schema.sh
│   ├── 03-install-plugin.sh
│   ├── 04-patch-and-rebuild-ipa-kdb.sh
│   └── 05-verify.sh
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── setup-inside-container.sh
├── tools/
│   ├── decode_pac.py
│   ├── set-trust-level.sh
│   └── get-trust-level.sh
└── report/
    └── report.md                # Данный отчёт
```

---

## 8. Выводы

1. Атрибут `trustLevel` (0–127) успешно добавлен в LDAP-каталог FreeIPA через расщирение схемы 389 DS
2. Значение `trustLevel` передаётся в MS-PAC билета TGT в виде Extra SID с кодировкой RID = 1 000 000 + trust_level
3. Реализация использует существующую инфраструктуру Extra SID в `ipa-kdb`, аналогично Asserted Identity SID
4. Благодаря автоматическому переносу SID из TGT в TGS в FreeIPA, реализация для TGT достаточна
5. RID-диапазон 1 000 000–1 000 127 не пересекается с системными RID, обеспечивая однозначную декодировку
