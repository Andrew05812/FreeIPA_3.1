# Описание процессов для защиты практики

## Общая архитектура

```
┌──────────────┐      ┌───────────────────┐      ┌────────────────────┐
│  LDAP-каталог │─────▶│  ipa-kdb (KDB     │─────▶│  MS-PAC в TGT      │
│  trustLevel   │      │   plugin)         │      │  Extra SID          │
└──────────────┘      └───────────────────┘      └────────────────────┘
     389 DS                MIT Kerberos               krb5kdc
```

Когда пользователь запрашивает TGT билет у KDC, происходит следующая цепочка:
1. KDC обращается к KDB-плагину `ipa-kdb` для получения данных пользователя
2. `ipa-kdb` читает атрибуты пользователя из LDAP-каталога 389 DS
3. `ipa-kdb` формирует структуру MS-PAC, в том числе Extra SID
4. KDC подписывает PAC и вкладывает его в TGT билет

Мы модифицировали шаги 1–3: добавили атрибут в LDAP и научили плагин читать его и добавлять как Extra SID.

---

## Часть 1: LDAP-схема

### Что делаем

Добавляем в LDAP-каталог 389 DS два элемента:

**Атрибут `trustLevel`:**
- Тип: INTEGER (целое число)
- OID: 1.3.6.1.4.1.53263.999.1.1 (под-arc OID FreeIPA 1.3.6.1.4.1.53263)
- Ограничение: SINGLE-VALUE (одно значение на запись)
- Диапазон: 0–127 (ограничение на уровне приложения)
- Поддерживает поиск: integerMatch (точное совпадение), integerOrderingMatch (сравнение больше/меньше)

**Объектный класс `ipaTrustLevelObject`:**
- Тип: AUXILIARY (вспомогательный, не структурный)
- SUP: top (наследуется от базового класса)
- MAY: trustLevel (может содержать атрибут trustLevel)

### Почему AUXILIARY

В LDAP каждый объект обязан иметь ровно один структурный класс (определяет обязательные атрибуты). Пользователь FreeIPA уже имеет структурные классы `posixAccount`, `ipaUser`, `krbPrincipalAux` и другие. Нельзя заменить или дублировать структурный класс.

AUXILIARY класс — это дополнение, которое можно добавить к любой записи без изменения её структурного класса. Именно поэтому мы можем просто "подвесить" `ipaTrustLevelObject` к существующему пользователю:

```
dn: uid=testuser,cn=users,cn=accounts,dc=example,dc=com
changetype: modify
add: objectClass
objectClass: ipaTrustLevelObject      ← добавляем вспомогательный класс
-
add: trustLevel
trustLevel: 42                          ← добавляем атрибут
```

### Как загружается схема

Схема загружается через `ldapmodify` — онлайн-модификацию записи `cn=schema`. Это немедленно делает атрибут и класс доступными без перезапуска 389 DS.

---

## Часть 2: Модификация ipa-kdb

### Что такое ipa-kdb

`ipa-kdb` — это KDB-плагин (Kerberos Database Backend) для MIT Kerberos. Он связывает KDC с LDAP-каталогом FreeIPA. Когда KDC нуждается в данных пользователя (для выдачи билета), он вызывает функции из ipa-kdb.

Ключевой файл: `ipa_kdb_mspac.c` — отвечает за генерацию MS-PAC (Microsoft Privilege Attribute Certificate).

### Что такое MS-PAC

MS-PAC — это структура данных, которую Microsoft Active Directory вкладывает в Kerberos-билеты. FreeIPA генерирует MS-PAC для совместимости с Windows-клиентами и доверенными доменами.

Структура MS-PAC содержит несколько буферов, главный из которых — `PAC_LOGON_INFO` (тип 1). Внутри него находится структура `netr_SamInfo3`, которая описывает пользователя: имя, группы, SID и т.д.

### Что такое Extra SID

Поле `Extra SID` в `netr_SamInfo3` — это массив дополнительных идентификаторов безопасности (SID), помимо основного SID пользователя и SID групп. FreeIPA уже использует Extra SID для `Asserted Identity` (S-1-18-1 для обычных пользователей, S-1-18-2 для S4U2Self).

Структура в коде:
```c
struct netr_SamInfo3 {
    ...
    uint32_t sidcount;          // количество Extra SID
    struct netr_SidAttr *sids;  // массив Extra SID
    ...
};
```

Каждый Extra SID имеет атрибуты: `SE_GROUP_MANDATORY | SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT` — означает что SID обязательно учитывается при авторизации.

### Что мы модифицировали в ipa_kdb_mspac.c

**Изменение 1: Добавляем `trustLevel` в список запрашиваемых LDAP-атрибутов**

```c
static char *user_pac_attrs[] = {
    ...
    "ipaNTHomeDirectoryDrive",
    "trustLevel",        // ← ДОБАВЛЕНО
    NULL
};
```

Без этого LDAP-сервер не вернёт атрибут `trustLevel` при поиске — ipa-kdb просто не узнает о его существовании.

**Изменение 2: Добавляем константы**

```c
#define TRUST_LEVEL_RID_BASE 1000000
#define TRUST_LEVEL_MAX 127
```

- `TRUST_LEVEL_RID_BASE = 1000000` — базовый RID. Итоговый RID = 1000000 + trust_level
- `TRUST_LEVEL_MAX = 127` — максимальное значение trust-level (по заданию)

**Изменение 3: Функция `ipadb_add_trust_level_sid()`**

Алгоритм функции:

1. Проверяет что ipactx и mspac инициализированы (иначе возвращает 0 — не добавляет SID)
2. Читает `trustLevel` из LDAP-записи через `ipadb_ldap_attr_to_int()`
3. Если атрибут отсутствует (ENOENT) — возвращает 0 (не добавляет SID). Это нормально — не у всех пользователей есть trust-level
4. Проверяет диапазон 0–127
5. Копирует доменный SID из `ipactx->mspac->domsid`
6. Добавляет RID через `sid_append_rid()`: RID = 1000000 + trust_level
7. Конструирует SID-строку через `dom_sid_string()` (например "S-1-5-21-X-Y-Z-1000042")
8. Расширяет массив Extra SID: `talloc_realloc()` добавляет один элемент
9. Создаёт структуру `dom_sid2` и заполняет её через `ipadb_string_to_sid()`
10. Устанавливает атрибуты SID: MANDATORY | ENABLED | ENABLED_BY_DEFAULT
11. Увеличивает `info3->sidcount` и устанавливает флаг `NETLOGON_EXTRA_SIDS`
12. Логирует: `trust-level: added Extra SID for level 42 (RID=1000042)`

**Изменение 4: Вызов из `ipadb_fill_info3()`**

```c
ret = ipadb_add_asserted_identity(ipactx, flags, memctx, info3);
if (ret == 0)
    ret = ipadb_add_trust_level_sid(ipactx, lentry, memctx, info3);
return ret;
```

Функция `ipadb_fill_info3()` заполняет всю структуру `netr_SamInfo3`. Мы добавили наш вызов после `ipadb_add_asserted_identity()` — это конец заполнения Extra SID. Если предыдущая функция вернула ошибку — наша не вызывается.

---

## Часть 3: Кодирование trust-level в Extra SID

### Формат SID

SID (Security Identifier) — это идентификатор безопасности в формате:
```
S-Revision-Authority-SubAuthority1-SubAuthority2-...-RID
```

Пример доменного SID: `S-1-5-21-2609696107-2343131759-2222240319`

- S — идентификатор SID
- 1 — версия (ревизия)
- 5 — идентификатор authority
- 21 — значение под-авторитета (означает "доменный SID")
- 2609696107-2343131759-2222240319 — уникальные под-авторитеты домена
- RID — Relative Identifier (относительный идентификатор) — последнее число

### Наша формула

```
Extra SID = S-1-5-21-<domain_sub_auths>-<1000000 + trust_level>
```

- `trust_level = 0` → RID = 1000000 → `S-1-5-21-...-1000000`
- `trust_level = 42` → RID = 1000042 → `S-1-5-21-...-1000042`
- `trust_level = 127` → RID = 1000127 → `S-1-5-21-...-1000127`

### Декодировка получателем

```python
trust_level = RID - 1000000
# если 1000000 ≤ RID ≤ 1000127 → это trust-level SID
```

### Почему RID_BASE = 1000000

- Пользовательские RID в FreeIPA начинаются с ~1000 (выдаются последовательно)
- Групповые RID — аналогично
- Well-known RID (500=admin, 501=guest, 512-520=группы) — до 1000
- RID 1000000–1000127 гарантированно не пересекается ни с какими системными RID
- Диапазон из 128 значений (0–127) уникально идентифицирует trust-level SID

---

## Часть 4: Перенос из TGT в TGS

### Как работает перенос

Когда клиент запрашивает TGS-билет (service ticket), KDC:
1. Получает TGT из запроса
2. Извлекает из TGT авторизационные данные (Authorization Data), включая PAC
3. Вызывает `ipadb_common_verify_pac()` — эта функция **копирует весь PAC** из TGT, включая все Extra SID
4. Подписывает PAC для TGS и вкладывает в TGS-билет

Таким образом, наш Extra SID автоматически переносится из TGT в TGS без какой-либо модификации. Это существующая функциональность FreeIPA.

---

## Полный поток данных

```
1. Администратор устанавливает атрибут:
   ldapmodify → 389 DS → user entry: trustLevel=42

2. Пользователь запрашивает TGT:
   kinit testuser → KDC получает AS-REQ

3. KDC вызывает ipa-kdb:
   ipadb_get_principal() → LDAP search → получает запись пользователя
   ipadb_v9_issue_pac()  → вызывает ipadb_get_pac()

4. ipadb_get_pac() вызывает ipadb_fill_info3():
   - Заполняет基本信息3: имя, группы, основной SID
   - ipadb_add_asserted_identity() → добавляет S-1-18-1
   - ipadb_add_trust_level_sid() → читает trustLevel=42
     → конструирует S-1-5-21-...-1000042
     → добавляет в info3->sids[]

5. PAC подписывается и вкладывается в TGT:
   AS-REP → ticket → authorization-data → PAC → LOGON_INFO → Extra SIDs:
     [0] S-1-18-1 (Asserted Identity)
     [1] S-1-5-21-2609696107-2343131759-2222240319-1000042 (trust-level=42)

6. При запросе TGS:
   TGS-REQ → KDC копирует PAC из TGT → TGS содержит те же Extra SID
```

---

## Ответы на возможные вопросы преподавателя

**Q: Почему именно Extra SID, а не новый тип PAC-буфера?**
A: Extra SID — стандартный механизм MS-PAC, поддерживаемый Windows и Samba. Создание нового типа буфера потребовало бы модификации всех потребителей PAC. Extra SID автоматически обрабатывается существующими реализациями.

**Q: Почему RID_BASE = 1000000?**
A: Пользовательские и групповые RID в FreeIPA начинаются с ~1000. Диапазон 1000000–1000127 гарантированно не пересекается с системными RID, обеспечивая однозначную декодировку.

**Q: Что если у пользователя нет атрибута trustLevel?**
A: Функция `ipadb_add_trust_level_sid()` получает ENOENT от `ipadb_ldap_attr_to_int()` и возвращает 0 — Extra SID не добавляется. Это нормальное поведение.

**Q: Как получатель извлекает trust-level?**
A: Получатель перебирает Extra SID, проверяет RID. Если 1000000 ≤ RID ≤ 1000127 — это trust-level SID. trust_level = RID − 1000000.

**Q: Почему AUXILIARY объектный класс, а не STRUCTURAL?**
A: В LDAP каждая запись имеет ровно один структурный класс. Пользователь FreeIPA уже имеет `posixAccount` как структурный. AUXILIARY класс можно добавить к любой записи без изменения структурного класса.

**Q: Как обеспечивается перенос из TGT в TGS?**
A: FreeIPA в `ipadb_common_verify_pac()` копирует весь PAC из TGT в TGS. Все Extra SID переносятся автоматически. Это существующая функциональность.
