# История изменений

Техническая история репозитория по состоянию на 27.11.2026. Дата — дата коммитов в их локальном часовом поясе; номера релизов не назначались. Актуальные статусы P01 — в [Preflight](docs/PREFLIGHT_P01.md); контур P02 — в [RBAC](docs/RBAC.md); прогресс, трудоёмкость и все подэтапы — в [журнале подэтапов](docs/SUBTASKS.md), подробные доказательства приёмок — в [SUBTASKS-EVIDENCE](docs/SUBTASKS-EVIDENCE.md); остальные документы R3.2 сохраняют исторические формулировки этапа 0.

## 27.11.2026 — P06: объединённое gap-покрытие и строгий CI Gate

В единую ветку fix/p06-audit-findings-2026-11-27 объединены DB-boundary
follow-up и независимое расширение тестов. Добавлено 159 тестов: unit — 99,
DB/runtime-role — 8, HTTPS/races — 14, web client — 38. Реальные PostgreSQL
проверки доказывают запрет прямого DML, атомарность comment+audit, basis
recheck на COMMIT, PII audit-before-decrypt, role/scope/state, конкурентные
idempotency keys, mid-read revocation, rollback и uncertain COMMIT.

Существующий браузерный сценарий расширен: второй комментарий,
stale-ETag → 412 → refresh → retry, отзыв PII-права с проверкой очистки
экрана. Job p06-acceptance содержит строгие точные счётчики:
149 database-free unit/client tests и 133 server gap tests, 0 неожиданных
skip; плюс exact-SHA builds, wire, PostgreSQL 18.7, HTTPS/browser proof и
redacted evidence. p06-results.mjs фиксирует totals и обязательные названия
тестов, не позволяя зелёному job пропустить opt-in suites.

Исправлены два error-mapping дефекта в apps/api/src/requests/card/comments.ts:
ошибка read/decrypt slot остаётся 503 NOT_READY, но отказ final beforeOpen()
не поглощается и сохраняет авторизационный статус; определённый отказ DB/audit
при записи комментария также даёт 503 NOT_READY. F-2 теперь обычный
обязательный passing test, без it.fails; рядом подтверждены полный rollback
и отсутствие plaintext. Дополнительный unit test отдельно проверяет проброс
FORBIDDEN из final pre-decrypt recheck.

Локальные результаты DeepSeek для предыдущего набора были 148 unit/client,
132/132 server gap и browser 1/1. Новый объединённый набор содержит по одному
добавленному unit test и исправлению F-2; он требует повторного exact-SHA
прогона с totals 149/133. P06 PASS не объявляется до зелёного нового
GitHub Actions run на опубликованном SHA. P06 остаётся T-only; полный DB dump
+ managed comment-slot restore — отдельный blocker до R/реальных ПД.

## 27.11.2026 — P06 follow-up audit remediation (verification pending)

Отдельная ветка `fix/p06-audit-findings-2026-11-27` закрывает найденные
после исторической приёмки defence-in-depth замечания: запись внутренних
комментариев перенесена в узкую DB-функцию с атомарным аудитом и независимыми
проверками P05/CITY/GLOBAL; прямой DML runtime запрещён; запрос реестра
ограничен 512 кандидатами с отказом без частичной страницы; основание и staff
session повторно проверяются непосредственно перед расшифровкой комментария.
Добавлен обязательный P06 CI Gate (линт, typecheck, сборки, opt-in server/load
и HTTPS browser). Это **не PASS** до успешного прогона на exact SHA и проверки
результатов тестов, включая параллельно добавляемые fault-injection тесты
отказа PII-аудита. P06 остаётся только в T; полный P06 restore dump+managed
comment slots — отдельный blocker до переноса в R/реальных ПД.

## 27.11.2026 — P06 закрыт: 4 из 4 приняты, ASTRA PASS P06

- **Статус:** P06 открыт отдельным поручением владельца и закрыт 27.11.2026 в
  границах изолированной композиции T. Четыре локальных коммита: реестр
  `c6ff390`, карточка и комментарии `e2389e4`, поиск `a717fe4`, дашборд
  `affa0ce`. Каждый подэтап прошёл отдельный адресный аудит GPT‑6.2‑Astra с
  вердиктом PASS; затем отдельный полный статический аудит P06 от базы
  `e7dbd61` — **ASTRA PASS P06**. Владелец принял все четыре подэтапа.
- **P06-01 — реестр** (`c6ff390`): `GET /api/v1/requests` с фильтрами `from`,
  `to`, `status`, `urgency`, `categoryId`, `districtId`, `sourceId`,
  `contactMode`, `provider`, `limit`, `cursor`; `GET /api/v1/requests/filters` —
  закрытые списки категорий, районов и источников; экран `/crm/requests`.
  В выборку попадают только заявки с неотозванным исходным согласием формы или
  действующим основанием ручного ввода; отзыв во время чтения даёт
  `503 NOT_READY` без частичной страницы. Keyset-пагинация по
  `created_at DESC, public_number DESC` с микросекундной точностью, курсор
  привязан к версии города и фильтрам.
- **P06-02 — карточка, история и комментарии** (`e2389e4`):
  `GET /api/v1/requests/{id}/card` и `…/events`; история до 100 последних
  событий без данных автора, тела команды, идентификаторов сессий и контактов.
  Телефон показывается только по нажатию «Показать контакты»: сервер до
  расшифровки подтверждает запись аудита без открытых значений и заново
  проверяет основание, а без действующего разрешения на звонок номер не
  возвращается. Комментарии пишутся зашифрованными, повтор с тем же ключом
  идемпотентности не создаёт дубль.
- **P06-03 — поиск** (`a717fe4`): `POST /api/v1/requests/search` с телом ровно
  `{kind, query}` для `number`, `name`, `phone`. Номер ищется по существующему
  публичному номеру; имя нормализуется (NFC, нижний регистр, схлопывание
  пробелов), «Е» и «Ё» различаются; телефон требует полного международного
  формата. Для имени и телефона дополнительно нужно городское
  `customer.pii.read`. Индекс хранит HMAC‑SHA‑256 токены отдельным 32‑байтным
  ключом с доменом среды, поколения, города и поля; ротация переключает
  поколение атомарно, старый экземпляр отклоняет поиск и запись прежним ключом.
  Отзыв основания удаляет обе проекции в транзакции отзыва.
- **P06-04 — дашборд и снимок реестра** (`affa0ce`): `GET /api/v1/crm/dashboard`
  с `asOf`, `definitionsVersion=p06-v1`, границами местного дня, состояниями
  метрик и ссылками готовых показателей. Счётчик и список используют один
  снимок, поэтому цифра сходится с выборкой, на которую ведёт. Показатели,
  зависящие от назначений, визитов, смет, отчётов и доступности мастеров,
  помечены `not_ready` до P09/P11/P12.
- **Проверки:** сборки API/Web/Mini App на каждом снимке; 11 серверных
  сценариев P06 в изолированном PostgreSQL с реальным HTTPS; 66 веб-тестов;
  Chromium-сценарий от дашборда и списка по снимку через реестр и поиск к
  карточке, истории, комментарию и защищённому показу контактов. В PostgreSQL
  проверены границы московского дня, 23- и 25-часовые сутки в Берлине и обе
  половины исторической повторённой полуночи в Гаване. `EXPLAIN ANALYZE`:
  реестр 2,843 мс, сборка снимка и сверка версий 3,835 и 2,986 мс — без
  авторизации и HTTP.
- **Границы:** маршруты P06 (`/requests`, `/filters`, `/search`,
  `/requests/{id}/card`, `/crm/dashboard`) зарегистрированы только в композиции
  T; release R их не содержит, что подтверждается отдельным тестом границы R/T.
  Поиск работает по точному совпадению — частичных совпадений, поиска по адресу
  и по тексту нет. Индекс поиска — производные данные: исходные ячейки,
  резервные копии и полное обезличивание остаются за P13P. Рабочая БД не
  мигрировалась, реальных ПД нет.

## 27.11.2026 — FULL P05 PASS; owner acceptance 4/4

- **Приёмка:** P05-01…P05-04 реализованы и приняты владельцем (4/4) в
  synthetic scope. P05-01 сохраняет ранее зафиксированную историческую
  acceptance (`f2caab05`); P05-02/P05-03/P05-04 приняты владельцем
  27.11.2026.
- **Эквивалентность ревью:** владелец прямо признал ChatGPT
  `PASS — FULL P05` эквивалентом требуемого `PASS — FULL ASTRA P05`.
  Это owner-authorized equivalence, а не заявление о проведённом отдельном
  Astra-run.
- **Точный technical Gate:** run [45953489126](https://github.com/Good-Eli/fixlevelup/actions/runs/45953489126),
  candidate SHA `0d7f60dbee1bddca63e9f1868a03ebf1230ec69f`; семь required jobs
  плюс freeze job — **8/8 success**. Freeze artifact
  `p05-exact-candidate-45953489126`, 681 tracked files, manifest SHA-256
  `f781b1facbbb2c8117e464ec4a8d24dfbaf2f9c38353a6cbc60f70a44b39dd5e`,
  canonical tree SHA-256
  `3c6ab92f01f6b1c2c5f379f60aa529da62221365f356e15e31124801f53ed8b5`.
- **Targeted proof:** CITY-RBAC × state × command — 432 cells across 9 HTTPS
  phases; both one-ticket real-engine HTTP attachment cases passed (READY
  attach+digest and refuse after retention decision); F-01 direct-DML boundary,
  PII/decrypt, partial effects/rollback, restore, migration 24/370 CHECKs,
  builds, wire and browser gates all passed.
- **P05-03:** F callback/repair submit, staff manual intake with separate
  staff evidence, channel readiness/offers (without live delivery), READY
  attachment, retention interlock and staff bridge; migration 024.
- **P05-04:** allowlisted early F/staff commands, PHONE withdrawal/cancel,
  bounded non-PII staff read, read-only waiting/cleanup selectors, OpenAPI 3.1
  and typed client.
- **Boundaries:** P05 HTTP controllers remain in isolated test composition T;
  release composition R does not register P05 routes. Migrations 023/024 were
  tested only on disposable PostgreSQL. No working DB migration, production
  deployment, real PII, public site/file byte transport, live channel delivery
  or manager notification was activated. After this documentation/policy
  amendment, run full CI and freeze again on the resulting exact SHA before
  fast-forward to `main`; no production action is authorized.

## 22.11.2026 — P04 принят полностью (4 из 4), FULL ASTRA P04 — PASS

- **Статус:** P04 открыт прямым поручением владельца 22.11.2026 на изолированных synthetic данных. [План](docs/P04-PLAN.md) прошёл безусловный Gate 0 PASS `GPT-6.2 Astra` (high); каждый подэтап получил свой PASS и адресный локальный коммит. Итоговый [FULL ASTRA P04](docs/P04-AUDIT.md) — **PASS 22.11.2026** после пяти межсрезовых исправлений; принятые коммиты не переписаны.
- **P04-01** (`d04758c`) — typed каталог и источники фиксированной цены: категории, бренды, модели, симптомы и позиции WORK/PART/MATERIAL/TRAVEL/DIAGNOSTICS с версиями, архивом и `row_version`; mapping «симптом → работа той же категории»; серии цен по `(city,item)`; append-only версии цены в `BIGINT` минорных единиц с обязательной 1:1 проекцией периода и `EXCLUDE` по пересечению; shared fence для свежего чтения цены. Миграция `019`.
- **P04-02** (`2a29c79`) — правила, диапазоны и детерминированный расчёт: политика города с явным порядком и совместимостью правил, `EVENING`/`NIGHT`/`EXPRESS`/`SURCHARGE`/`DISCOUNT`, `FIXED`/`RATE`, базы `WORKS`/`WORKS_AND_PARTS`/`ORDER_BASE`, `HALF_UP`/`DOWN`; количество канонической десятичной строкой, расчёт на `BigInt` без `Number`, неизменяемый snapshot v1 с сохранённой локальной проекцией времени. Миграция `020`.
- **P04-03** (`39d1c72`) — закрытый staff API и ручные данные Авито: права `catalog.*`, `pricing.*`, `content.external-reviews.*` с COMPANY/CITY scope, неизменяемые квитанции, `Idempotency-Key` и `If-Match`, bounded keyset-списки, один OpenAPI 3.1 и проверяемый typed client. Миграция `021`.
- **P04-04** (`30079d3`) — CRM-раздел каталога и цен и полнота 14 групп: формы create/edit/publish/archive/history с явным городом для цены, канонические ссылки P03 для зон и контента, браузерные и HTTPS-проверки.
- **Исправления FULL ASTRA P04** (`7a60d4c`) — пять межсрезовых замечаний закрыты адресно, без переписывания принятых коммитов.
- Границы: реальный [прайс](info/Прайс.txt) не читается и не импортируется, доменных сидов нет, Q06/Q09/Q10 открыты. Нет заявок, планирования, смет, оплат, публичных маршрутов и production.

## 22.11.2026 — P03-05 принят владельцем в synthetic scope, Astra Gate 2 PASS

- Владелец отдельно поручил начать P03-05, потребовал Astra после плана и после готовности и явно выбрал A: 18 личных GLOBAL-источников только исходному bootstrap-назначению, не общей роли. Astra Gate 1 — PASS после исправления шести MUST плана. Принятый baseline `225af45` опубликован: [GitHub Actions 44972705234](https://github.com/Good-Eli/fixlevelup/actions/runs/44972705234) — success только для этого SHA (реализация C/D/E — `dd87cb4`). Предыдущее поручение не начинать P03-05 ниже относится к приёмке P03-04 и заменено отдельным разрешением.
- Реализованы закрытые CRM и HTTP для географии и существующих сущностей: семь полей компании, пять справочников, FAQ/FACT/SEO, legal REQUEST_PROCESSING/MARKETING, безопасная сводка готовности. Additive `018`: каталог, личный bootstrap-источник, десять операций с минимальными квитанциями. Общий `@fixlevelup/p03-contracts` — внутренний ESM без внешних зависимостей. Нет сохраняемого черновика настроек/справочника/контента/документа: только явная публикация неизменяемой версии; прежние географические черновики сохранены.
- Независимый migration proof — PASS: 18 миграций / 188 CHECK. Первое source review Gate 2 выявило четыре MUST (staff v0, связка snapshot+V формы, авторизация старой цели/типа до 409, предупреждение о действии CITY role grant на всех членов роли). Четыре исправления повторно сверены в source review; адресно подтверждены management API 19/19, Web 23/23 (16+7), geography 5/5 и restore 1/1. Полный E927/927 в73файлах, browser150/150 и real HTTPS smoke1/1 прошли. После E изменены только два Legal React keys и QA fixtures; follow-up Web23/23, production build, workspace typecheck/lint пройдены. Окончательный полный Astra Gate 2 — PASS, открытых MUST нет; [точные доказательства](docs/P03-05-CONTRACT.md#4-итоговые-доказательства-22112026). Владелец принял P03-05 22.11.2026; P03 — 100% (5 из 5 приняты). Отдельный полный аудит Astra P03-01…P03-05 — окончательный PASS после двух межсрезовых expiry-исправлений, E933/933 на неизменном дереве и нового HTTPS smoke1/1. Прежний 932/933 сохранён как неуспешный; без изменений исходников выполнен отдельный полный повтор. [Общий аудит и граница доказательств](docs/P03-AUDIT.md). Commit и обычный push в GitHub прямо разрешены владельцем после общего PASS; `7799b86` опубликован, [GitHub Actions 44983060539](https://github.com/Good-Eli/fixlevelup/actions/runs/44983060539) — success (прогон 28).
- Нет новых файловых HTTP, клиентских intake/F, `ADDRESS_COVERAGE` HTTP, external reviews, privacy cases, P04/P09/providers, реальных ПД, default TTL/retention или production. Рабочая БД не мигрировалась.

## 22.11.2026 — P03-04 полностью принят владельцем во внутреннем synthetic scope

- **Статус:** владелец принял весь P03-04 после полного Astra A→E PASS. C/D/E implementation: `dd87cb45fcdb828dc51995409a049b4f2af01063`; 113 файлов, без изменения исторических SQL014/015. Все три межсрезовых MUST закрыты, E — 876/876 в 66 файлах без пропусков. P03 — 80% (4 из 5 приняты); P03-05 не начинать. Публикация и GitHub CI проверяются после push; [контракт и evidence](docs/P03-04CDE-CONTRACT.md#6-current-status-and-evidence).
- Миграция `016` `20261122000200_file_processing_access` — аддитивно: три UNIQUE-индекса как FK-targets для существующих неизменяемых строк, таблицы `file_runtime_epochs`, `file_privacy_controls`, `file_sanitized_attempts`, `file_publications`; runtime epoch не сеется.
- Миграция `017` `20261122000300_file_privacy_deletion` — расширяет `file_privacy_controls` полями hold/delete/ledger и добавляет `file_delete_items`; дефолты описывают прежнее открытое состояние, а не политику хранения.
- Модули `apps/api/src/files/`: `file-processing` (локальный decoder, структура изображения, protocol), `file-lifecycle` (публикация, processing registry/evidence, budget), `file-access` (метаданные и выдача потоком по тикетам), `file-privacy` (retention, hold, delete claim/deletion, broker), `file-restore` (инвентарь, объекты, записи, rescrub), `file-ledger` (кодек, verifier, PG-ledger).
- Инфраструктура: `infra/file-processing` (Dockerfile воркера, ClamAV-сборки, launcher, preflight, OCI-отчёт), `infra/file-ledger` (отдельная PG-база, SQL ledger и роли), `infra/file-restore` (ресурсы restore-прогона).
- Одиннадцать новых тестовых файлов (`file-lifecycle-*`, `file-privacy-*`, `file-processing-*`, `file-access`, `file-ledger`, `file-restore`) и три фикстуры; отдельные скрипты проверки миграций `016`/`017`. Прямая runtime-зависимость `sharp@0.35.5`.
- **Промежуточная запись 22.11.2026 (историческая):** первоначально `typecheck` всего workspace — exit 0; два unit-файла под `--pool=threads` — 5 passed / 11 skipped. **Тогда ещё не были проверены:** полный Vitest (форки-пул падал с `spawn EPERM` в песочнице), migration proof `016`/`017`, Playwright, реальные ClamAV/Sharp, ledger-цепочка и restore. HTTP-маршрутов в `files/**` нет, signed URL, реальные ПД и production не добавлялись.
- Границы: нет HTTP/DI-маршрутов, signed URL, staff/client issuance, real PII или production. Security E PASS ограничен точными scanner/decoder digest и offline entrypoint; это не «0 CVE» или production approval для произвольного Node/updater/новых image rebuilds. Q02/Q12/Q13/Q16 и P03-05 остаются открытыми.

## 22.11.2026 — историческая запись приёмки P03-04B1+B2

- Обязательный **Astra PASS по B1** получен до создания B2. После реализации B2 первое Astra review выявило 3 MUST FIX; они адресно исправлены, повторный read-only вердикт — **PASS для B2**, блокеров в согласованном synthetic scope не осталось. Владелец принял B1+B2 22.11.2026 и разрешил коммит/push в GitHub; отдельно поручено завершить оставшиеся C/D/E.
- Внутренний private S3 adapter и [координатор](docs/P03-04B2-CONTRACT.md): durable регистрация до чтения source, COMMIT dispatch до PUT, bounded PUT+полный GET по actual bytes/SHA-256, exact original GIVEN/post-IO authorization и один `QUARANTINED` binding. Retry использует новый ключ, UNKNOWN остаётся учтённым; restart reconciliation — только зарегистрированный GET, без авто-привязки или освобождения по 404.
- Итог: **767/767 Vitest в 56 файлах**, оба real PG/S3 opt-in без skipped; B1 52 + B2 36 адресных проверок. **15 миграций/149 CHECK**, populated014→015/fresh/replay/drift/column ACL — PASS. generate/typecheck/source-lint/API-Web-Mini App builds, dependency525/audit0, secret scan/diff — PASS. В принятом B migration014/hash и код A не менялись; новая015 применялась только к изолированным тестовым БД.
- Одна прямая API runtime-зависимость `@aws-sdk/client-s3@3.1172.0`; дополнительных package identities нет. Нет HTTP, READY, scanner/EXIF, выдачи, DELETE/restore или real PII/production. Q02/Q12/Q13/Q16 открыты. Принят и опубликован именно B1+B2: `e44fae8d44c20bf430fc4ee67e8d8d85a1a47706`, [GitHub Actions 44960486563](https://github.com/Good-Eli/fixlevelup/actions/runs/44960486563) — success. Прогресс P03 на момент приёмки B составлял 60% (3 из 5).
- Локальный verification capacity fix: ignored Compose override `shm_size:512m` только postgres service, тот же named volume и подтверждённая прежняя database/system identity; без удаления БД/томов/сегментов и без изменения committed infra config. Это устранило ENOSPC при live PostgreSQL statistics DSM; не DB migration/deploy.

## 21.11.2026 — историческая запись приёмки P03-04A

- P03-03 зафиксирован локально в `9116812` (48 файлов, без push); отдельно сохранена пользовательская пояснительная таблица SUBTASKS. Перед стартом P03-04 план проверен `GPT-6.2 Astra` (high); [план и замечания](docs/P03-04-PLAN.md) отделяют первый срез от полного P03-04.
- Миграция `014` добавляет `file_upload_intents`, immutable owner/policy/exact-consent snapshot и только RESERVED→CANCELLED. Внутренние F-owned reserve/read/cancel порты требуют raw proof, явный READ COMMITTED, текущий точный GIVEN и DB-clock после ожиданий; quotas считают незавершённые резервы. Policy обязательна, idempotent replay не расходует вторую квоту. Audit/outbox транзакционны.
- **Статус:** 21.11.2026 владелец принял только срез A (no-byte, RESERVED→CANCELLED) в synthetic внутреннем scope. Финальные результаты: **679/679 Vitest в 50 файлах** (40 unit + 17 реальных PostgreSQL), **14 миграций и 138 CHECK** fresh/013→014/replay/drift/ACL, SQL014 SHA-256 `2ec24c3365b4681859cd11d4fc7dd031fc487d410ff695692f4a2ec650bb4377`; workspace typecheck, source-lint и production builds API/Web/Mini App — PASS; secret scan/diff/whitespace — PASS. Во время адресных исправлений schema не менялась, новых зависимостей в срезе A нет. Предыдущий gate 670/670 в 50 файлах (34 unit + 14 PG) и первое read-only ревью без приёмки сохраняются как исторические. Повторный read-only вердикт Astra — **PASS**, все три MUST FIX и SHOULD закрыты. Принятый срез A зафиксирован отдельным локальным коммитом `7d92122`, без B.
- Это не загрузка файлов: нет object key/S3 IO/SDK/scanner/EXIF/READY/download/delete/restore, новых зависимостей или HTTP; staff-owner FK — только будущая форма, runtime staff INSERT запрещён. На эту дату P03-04 целиком ещё не был завершён: был принят только внутренний срез A, а прогресс составлял 60% (3 из 5). На момент приёмки A реализация B была приостановлена до отдельного предложения; затем владелец разрешил B1+B2 с обязательными Astra gates (итог выше). Принятый A-коммит не включает B. Q02/Q12/Q13/Q16 остаются открытыми.

## Принят — P03-03: внутренние порты настроек, справочников и согласий

- Подэтап открыт прямым поручением владельца 21.11.2026 после принятого P03-02. Добавляется слой данных и внутренние типизированные порты: nullable ревизии настроек компании со ссылками на reviewed политику, малые типизированные справочники (`CALLBACK_INTERVAL` — в городе, остальные — в компании), контент COMPANY/CITY с источником значения, юридические документы и append-only события согласия, минимальный pre-submit anchor доверенной серверной сессии. Контракт — [P03-03](docs/P03-03-CONTRACT.md), решение — [DECISIONS §24](docs/DECISIONS.md#24-p03-03--внутренние-порты-настроек-справочников-и-согласий).
- **Границы, которые не расширяются:** нет HTTP-маршрутов, capability, ролей и CRM-форм (P03-05), нет intake/submit и выпуска F-сессии (P05), нет файлов (P03-04). Q02/Q13 остаются открытыми: срок жизни anchor задаёт вызывающая политика без TTL по умолчанию; сроки хранения не выдумываются — в настройках компании хранятся только `security/retention/upload/legal_review` policy refs как reviewed provenance, а не сами правила. Юридические документы хранят неизменяемый текст: synthetic-тесты создают документы со своим текстом, реальные тексты утверждает владелец. `ADDRESS_COVERAGE` — зарезервированное слово словаря без live-включения: нет реального документа, seed и маршрута; synthetic-вставка для проверки раздельности целей допустима.
- **Статус:** 21.11.2026 в 21:34 владелец принял P03-03 в synthetic внутреннем scope после адресной доработки трёх замечаний независимого ревью. Актуальное evidence принятого среза — 13 миграций и 121 CHECK, полный Vitest **622/622 в 48 файлах**, 39 configuration + 36 legal случаев; исправления: READ COMMITTED-изоляция legal-транзакции, точный `timezoneCityVersionId` источника и повторная проверка expiry после document lock. typecheck/source-lint/сборка PASS; Playwright не запускался (frontend не менялся), внешний CI, deploy и push не выполнялись. Предыдущий прогон 610/610 в 48 файлах и 39 configuration + 24 legal случаев относится к срезу до возврата на доработку и сохраняется как исторический. Принятый срез коммитится отдельным локальным коммитом; SHA не заявлен. P03 — 60% (3 из 5 приняты). Q02/Q12/Q13/Q16 остаются открытыми; публичных файлов и intake нет.

## Принят — P03-02: районы, зоны и территориальные полномочия

- Миграции `011` и `012` добавляют версионированное покрытие зон и два разных вида назначений: административные города сотрудника и датированные допуски мастера к работам. Чужие городские ссылки и изменение опубликованной версии запрещены. Публикация черновика требует актуальных версий самого черновика и зоны.
- Первый подтверждённый администратор автоматически получает пять географических прав на своё исходное назначение. Это не выдача прав всем ADMIN. Менеджер может редактировать черновики или допуски только при явных правах в назначенных городах; мастер получает только свою действующую сводку. Успешная запись, аудит, outbox и квитанция для безопасного повтора фиксируются вместе. Контракт и проверка — [P03-02](docs/P03-02-ACCESS.md).

## Принят — P03-01: город и его опубликованные настройки

- P03-01 принят владельцем 21.11.2026. Добавлены схема городов и неизменяемые ревизии, связь primary city с настройками компании и серверное чтение контекста `SINGLE_CITY`. Город определяется только в режиме `SINGLE_CITY`, если он одновременно основной и единственный активный. При другой конфигурации подстановки нет.
- Это синтетический первый подэтап, не открытие приёма заявок. Миграция не создаёт городов и не выдаёт `CITY`-полномочий. P03-02 разрешён к планированию; [план и точки приёмки P03](docs/SUBTASKS-EVIDENCE.md#p03--доказательства-состав-и-приёмки-по-подэтапам) сохраняют остальные gates.

## 20–21.11.2026 — контур сотрудников P02 (P02-01—P02-06)

Шесть подэтапов: контракты доступа, учётные записи, веб-аутентификация, серверная авторизация, Telegram-вход мастера и управление доступом. Каждый открывался отдельным разрешением владельца. Доменных сущностей заявок, каталога, расписания и клиентских каналов это не добавляет.

- **P02-01 — контракты и минимальная модель доступа** (`a50bb04`, только документы): администратор и менеджер входят в веб-кабинет, мастер — через Telegram Mini App, клиент — через TG/VK/MAX. Канал входа сам по себе прав не даёт; staff-права отделены от клиентских request grants; обязательны default deny и запрет самоэскалации. Q03/Q12/Q17 фиксируются открытыми, а не решаются молча. Детали — [DECISIONS §21](docs/DECISIONS.md#21-p02-01--модель-доступа-и-контракт-каналов).
- **P02-02 — учётные записи и bootstrap** (`02766f6`): таблицы `staff`, `staff_web_credentials`, `staff_bootstrap_marker`. Первый администратор создаётся одноразовой консольной командой — без пароля по умолчанию и без открытой регистрации; повтор запрещён атомарным marker. Отдельная команда `staff:recover` меняет забытый пароль существующего ACTIVE ADMIN. Пароль хранится как Argon2id PHC. Мастеру веб-пароль не создаётся.
- **P02-03 — веб-аутентификация M/A** (`7c56302`): `POST /api/v1/auth/login`, `GET /auth/me`, `POST /auth/session/renew`, `POST /auth/logout`, `POST /auth/password/change`. Сервер хранит только SHA-256 хеш токена; cookie `__Host-` с Secure/HttpOnly/SameSite=Strict; проверяются точный Origin и session-bound CSRF. Сессия живёт 30 минут простоя и не более 12 часов; renew атомарно меняет токен, не продлевая абсолютный предел. Пять неудач по логину за 15 минут плюс лимит источника. Web auth выключена, пока не задан `WEB_AUTH_ENABLED=1` с полной валидной конфигурацией.
- **P02-04 — серверная авторизация** (`0041698`, `24944dc`): типизированный staff principal из проверенной сессии, guard с `@RequireCapability`, default deny. Для записи сессия, состояние сотрудника и права перепроверяются под блокировками в одной транзакции с самой операцией. Guard зарегистрирован в DI явно: отсутствие зависимости падает на старте приложения, а не при первом запросе, поэтому проверка прав не может молча выродиться в доступ без авторизации.
- **P02-05 — Telegram-аутентификация мастера** (`f1045e6`, hotfix-и `6946a1b`, `d05b664`): проверка подписи `initData` по официальному алгоритму с сравнением за постоянное время и контролем `auth_date`. Обмен возможен только по заранее существующей активной связи `staff_telegram_links` и только для ACTIVE TECHNICIAN; в базе хранится digest, не сырые данные. Сессия привязана к конкретной строке связи, поэтому перепривязка гасит старую сессию, а grace-повтор не воскрешает её и не продлевает TTL. Автоматического веб-логина нет.
- **P02-06 — управление доступом и жизненный цикл** (`8f0b204`): каталог permissions, роли, назначения, их API и раздел CRM `/crm/access`; контракт — [RBAC](docs/RBAC.md). У сотрудника одна текущая роль; наследования, индивидуальных grants и кэша полномочий нет; пять прав защищённые. Все RBAC-записи берут одну `pg_advisory_xact_lock` до строк субъекта и цели, защита последнего активного ADMIN действует и в API, и в БД. Cutover-миграция `009` требует остановки писателей старой версии, отзывает прежние runtime-привилегии на `user_permissions` и не повышает legacy-гранты до административных.

**Ограничения контура.** `CITY` не выдаётся: принадлежности сотрудника и объекта городу ещё нет. Первичной привязки Telegram к сотруднику нет, поэтому реальный Telegram-вход не используется. Нет инструмента выпуска web credential новому сотруднику. Списки отдаются целиком, без cursor pagination. Откат на старый бинарник после cutover невозможен. Ручная проверка bootstrap/recovery в настоящем TTY, живой Telegram E2E, доверенный HTTPS reverse proxy и согласование обработки ПД остаются открытыми gates.

**CI по этим коммитам.** Прогоны 12–14 завершились failure: добавленные по запросу владельца информационные patch-файлы в `info/` срабатывали в secret scan. В проверенном прогоне [44804420059](https://github.com/Good-Eli/fixlevelup/actions/runs/44804420059) единственная упавшая задача — «Scan repository and all available Git history for secrets», остальные три — success. Патчи удалены, а для единственного false positive добавлено исключение, привязанное к commit/path/line/rule и к SHA-256 blob-а. Прогон [44815347477](https://github.com/Good-Eli/fixlevelup/actions/runs/44815347477) на commit `8f0b204333395dcee1a1808b703a4dfbdce9efa9` завершился успешно. Это подтверждение конкретного SHA, а не production readiness.

## 20.11.2026 — технический foundation

- **Workspace и база:** создан приватный pnpm workspace с техническими заготовками API/worker, Web и Mini App, общими настройками TypeScript, lint, тестирования и сборки. Добавлены изолированная dev PostgreSQL, Prisma tooling и технические SQL-миграции audit/outbox; отдельные роли миграций и runtime ограничивают права, audit доступен runtime только для чтения и добавления. Предусмотрены проверки fresh/upgrade/replay, drift, транзакций и ограничений на синтетических данных. Доменные таблицы и бизнес-функции не добавлены. (`2325c21`)
- **API и worker:** readiness проверяет доступ runtime-role и совместимость технической схемы, liveness не зависит от БД. Добавлен технический outbox с атомарным claim, lease, ограниченными повторами и fencing по владельцу и поколению. Реестр обработчиков пуст: реальные сообщения не отправляются, exactly-once доставка не обещается. (`fbfbc4a`, `af93f45`)
- **Локальное S3 и восстановление (P01-01.10B):** добавлен приватный single-node Garage для разработки и проверки S3 subset. Отдельный synthetic drill выполняет логический backup/restore PostgreSQL и объектов с проверкой хешей и прав в изолированной цели; это не production backup, не PITR и не доказательство согласованного snapshot при параллельных записях. (`7fe5bba`, `5e32e6b`)
- **Linux и браузеры (P01-01.11A–C):** документированы локальные offline build/runtime proof с настоящими POSIX SIGINT/SIGTERM и отдельная изолированная Linux-интеграция PostgreSQL и Garage. Технические страницы Web и Mini App проверены Playwright в Chromium, Firefox и WebKit на desktop и mobile viewport; это не проверка реальных устройств или бизнес-сценариев. (`2ab41f3`, `5b2258e`, `cd8ca7e`)
- **CI (P01-12A):** добавлен GitHub Actions pipeline технических проверок, включая Linux proofs, browser smoke, контроль зависимостей/лицензий и секретов; исходные материалы перенесены в `info/`. Remote run [44671802032](https://github.com/Good-Eli/fixlevelup/actions/runs/44671802032) для push-коммита `94bc0c2573e5809ff9313055ff36ca25537f4877` завершился успешно. Это подтверждение конкретного прогона, не production deployment или приёмка продукта. (`94bc0c2`)
- **P01-12B.1 — README, license evidence и future Git identity:** подготовлены корневой README и технический review 29 exact dependency/license identities. Все 29 сопоставлены с frozen lockfile/snapshot graph; upstream evidence и недостающие архивные/артефактные проверки перечислены в [license review](docs/THIRD_PARTY_LICENSE_REVIEW.md). F06 остаётся PARTIAL до фактического deployment SBOM, notices и legal distribution review. Для F07 выбран ID-based noreply для будущих коммитов; настройку нужно применить локально по [инструкции](docs/F07-LOCAL-GIT-IDENTITY.md). История не переписывалась. Проверен CI run `44675339571` на `b42e0ef` (4/4 jobs success). Подэтап подготовлен к приёмке.

Локальные доказательства и их ограничения описаны в [Linux proof](infra/linux-proof/README.md), [Linux integration](infra/linux-integration/README.md), [browser proof](infra/browser-proof/README.md) и [backup drill](infra/backup/README.md). Реальные пользовательские данные, интеграции мессенджеров и production readiness не заявляются.

## 20.11.2026 — последующая актуализация P01

- **P01-12B.1.1:** исправлена привязка CI evidence: run [44677729359](https://github.com/Good-Eli/fixlevelup/actions/runs/44677729359) относится к commit `1165f0d950984c2555e61aceef681640ff0e075d`; предыдущий run `44675339571` — к `b42e0ef`. Локальный commit `4e707d5`.
- **P01-12B.2:** владелец подтвердил ID-based GitHub noreply и проверки future Author/Committer; F07 переведён в PASS. Сохранение старой публичной экспозиции metadata принято без переписывания истории. Локальный commit `275ec85`.
- **P01-12C — подготовлено к приёмке:** по сообщению владельца, выполнен независимый read-only аудит, критических блокеров в проверенном техническом scope не обнаружено; P01 рекомендуется к приёмке с ограничениями. F06 остаётся PARTIAL: архивные проверки, artifact-level SBOM/notices и legal/distribution review обязательны до коммерческого распространения и production release, но не блокируют следующий этап на synthetic data. P02 требует отдельного разрешения владельца. Это не production readiness.

## 21.11.2026 — сверка статусов P01/P02 и документации

- Уточнено различие между завершённой реализацией подэтапов, итоговой приёмкой владельца и production/live readiness. P01 принят владельцем как технический closeout с ограничениями: F01–F05/F07 PASS, F06 PARTIAL. P02-01—P02-06 реализованы и закоммичены; P02 принят владельцем в согласованных границах.
- В ROADMAP сведены все оговорки P01/P02: F06 release gates; synthetic-only backup/restore; сохранённая историческая Git metadata; TTY gate bootstrap/recovery; отсутствие первичной Telegram-привязки и выпуска web credential; CITY scope; отсутствие pagination и customer request grants; отсутствие live Telegram E2E, доверенной HTTPS reverse proxy и согласования обработки реальных ПД.
- Зафиксирована операционная граница cutover migration 009: старый бинарник после отзыва legacy grants не является допустимым rollback target. Перед применением нужны остановка старых writers и проверяемый backup/restore plan.
- Уточнены README и SUBTASKS: snapshot P01 0ffc7c2, кодовый snapshot P02 8f0b204, последующий документационный closeout 5c8205f; CI run 44815347477 относится к 8f0b204, а не к docs-only closeout.
- Эта редакция документации не меняет код, миграции, runtime-конфигурацию, БД или CI. Она фиксирует уже состоявшуюся приёмку P01/P02 в ограниченных границах; live/legal gates остаются открытыми. На момент этой сверки P03 ещё не был открыт; он открыт позже отдельным поручением владельца — см. разделы P03-01 и P03-02 выше.
