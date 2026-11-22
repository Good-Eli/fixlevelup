# P03-05 — защищённое управление P03 и общая приёмка: план

**Статус 22.11.2026: Astra Gate 1 — PASS для исправленного плана.** Владелец прямо поручил начать P03-05 и потребовал аудит Astra после составления плана и после готовности. Первый аудит — NOT PASS; все шесть групп MUST исправлены, затем Astra повторно прочитала полную редакцию и дала PASS на уровне плана. Владелец выбрал **вариант A** (§2.1): отдельный личный источник новых прав первоначальному администратору. Реализация разрешена в согласованном synthetic scope; миграция рабочей БД и реальные grants не разрешены. Код, DDL и рабочая БД на стадии планирования не менялись. После реализации и полного gate обязателен второй независимый аудит Astra; PASS плана не является приёмкой этапа. Baseline — `225af45` (приёмка P03-04), implementation P03-04 — `dd87cb4`, GitHub CI [44972705234](https://github.com/Good-Eli/fixlevelup/actions/runs/44972705234) success. Пользовательская пояснительная таблица и её строка журнала в [SUBTASKS](SUBTASKS.md) остаются отдельной незакоммиченной правкой.

Источники: [P03-05 и DoD](SUBTASKS.md#состав-подэтапов-и-как-проверяем), [P03 roadmap](ROADMAP.md#p03--settingslegalfiles-и-типизированные-справочники), [P03-03 ports](P03-03-CONTRACT.md), [утверждённая география](P03-02-ACCESS.md), [RBAC](RBAC.md), [API §12](API.md#12-контент-настройки-аналитика-и-аудит). Наличие проектной строки API не означает существование сущности или разрешение реальных операций.

**Завершение по факту:** P03-05 реализован, прошёл окончательный Astra Gate 2 и принят владельцем 22.11.2026; все пять подэтапов P03 приняты. Новым поручением перед коммитом выполнен полный аудит Astra P03-01…P03-05: после двух межсрезовых исправлений и новых проверок — окончательный **PASS** ([отчёт](P03-AUDIT.md)); владелец прямо разрешил после него commit/push в GitHub. Это не разрешение на P04 или production. Ниже сохраняется проверенный до реализации план.

## 1. Результат и не-цели

Результат — закрытая CRM и staff API для **существующих** сущностей P03: города и их версии, районы/зоны/покрытие, company settings, пять типизированных справочников, FAQ/FACT/SEO content и purpose-specific legal documents. Оператор управляет ими через формы, получает актуальные версии, причины неполноты и исторические публикации, а не вручную правит SQL. Все записи проверяют текущую сессию, capability, роль, scope, объект, I/V и оставляют атомарный безопасный аудит.

Весь scope проверяется на synthetic data. Не создаются реальные города/контакты/юридические тексты, production seeds, default retention/TTL/quota, фиктивные price/request/visit parents. Не включаются P04 prices, P05 intake/выпуск F/согласия за клиента, P09 dispatch, provider setup/live checks, external reviews, privacy cases, analytics/audit-wide UI. Эти последние проектные endpoints не имеют необходимых domain models в текущей схеме и не относятся к сдаче управления существующими сущностями P03. P03-04 file processing/stream/delete/restore остаются internal/default off, без новых файловых HTTP или staff-download grants. Q02/Q12/Q13/Q16 и production gates открыты.

## 2. Обязательные решения до реализации

### 2.1. Начальная выдача новых прав — требуется явный выбор владельца

В существующем P02 администратор делегирует только право, которое сам уже имеет (`role-policy.ts`, `checkReplacement`). Поэтому один каталог новых кодов без выдачи оставляет их недоступными из CRM даже первому администратору. Нельзя молча сделать их `protected` (обязательными всем ADMIN), расширить старые пять geography bootstrap grants или разрешить любое самоповышение через `roles.permissions.manage`.

**Предложение A (рекомендуется, требует выбора владельца):** отдельный одноразовый личный источник 18 новых GLOBAL management codes только первоначальному подтверждённому SYSTEM ADMIN и его исходному bootstrap-assignment. Отдельный реестр `(original_assignment_id, closed_code, row_version, revoked_at, revoked_by)` и issuer **без параметров**; не менять старый geography issuer и его пять кодов. Под RBAC write lock issuer проверяет singleton bootstrap marker, существующий web credential, ACTIVE SYSTEM ADMIN/role и единственное исходное назначение за всю историю. Вызов при санкционированном upgrade и в той же транзакции fresh console bootstrap; нет подходящего назначения — no-op без подстановки. PUBLIC/runtime EXECUTE запрещён; runtime INSERT/DELETE/TRUNCATE запрещены. Issuer идемпотентен, не обновляет role_permissions и не оживляет отозванные строки. Повторный вход, migration replay, recovery, переезд на новую роль и reassign не перевыпускают источник.

Отзыв: `GET /settings/management/bootstrap` показывает только доступные этому SYSTEM ADMIN коды/версии источника; `POST /settings/management/bootstrap/:staffId/:code/revoke` с I и `If-Match: "p03-vN"`, пустым body. Требуются текущие SYSTEM ADMIN, `roles.permissions.manage` и GLOBAL того же кода до отзыва; target — исходное назначение, в ответе минимальная квитанция версии источника. В одной RC-транзакции NULL→DB timestamp, authenticated actor, row_version+1, audit/outbox/receipt; даже self-revoke не возвращает содержимое/старый grant. Повтор по тому же I — прежняя minimal receipt после новой проверки актуальной authority; если сам источник уже был снят и другого GLOBAL нет, replay отказывает, не восстанавливает право. UI отдельно подтверждает необратимый отзыв.

**Граница эффекта для выбора владельца:** отзыв личного источника не отзывает уже сознательно выданные самостоятельные grants ролей. Если администратор явно включит код на общей SYSTEM ADMIN роли, его получат все сотрудники с этой ролью, а не выбранный человек; UI перечисляет scope и предупреждает о таком эффекте до подтверждения. Механизм A сам общей роли ничего не выдаёт. Решение разрешает реализацию/проверку на новых изолированных БД; миграция рабочей БД и выдача прав реальным людям требуют отдельного разрешения.

**Альтернатива B:** каталог без начальных grants, начальная настройка только независимым offline provisioning с собственной проверенной authority. Synthetic tests могут выдавать права в изолированной fixture как setup, но это не доказывает пригодность чистой установки к управлению из CRM. Не объявлять P03-05 полностью завершённым для clean-install management без согласованного commissioning пути.

Первый аудит Astra оценил обе границы и рекомендовал A при явной авторизации владельца. Исправленный план получает адресную повторную сверку Astra, затем владелец одним выбором утверждает этот вариант и описанную матрицу P03; B оставляет новые коды без начальной выдачи и clean-install management неподтверждённым. До этого source/DDL не реализуются.

### 2.2. Предлагаемая runtime-матрица новых прав

Это проект technical management policy для проверки Astra/владельца, не выдача прав. Все новые catalog codes обычные (`protected=false`), roles/grants не возникают от одного наличия кода. TECHNICIAN/TG никогда не получает administrative P03. Все записи требуют независимого matching read grant; publication не подразумевает manage/read.

| Группа | Коды | SYSTEM ADMIN с явным grant | MANAGER/CUSTOM web с явным grant |
| --- | --- | --- | --- |
| Company | `settings.fullread`, `settings.manage` | Только SYSTEM ADMIN GLOBAL: full read/history; publish complete revision — manage+fullread | Full company read и любая company write запрещены даже при drifted grant; безопасная operational projection доступна только через отдельную readiness-группу |
| Readiness | `settings.readiness.read` и независимый `geography.read` для city sections | Свои разрешённые секции, явный список missing/unsupported gates | Безопасные коды причин и city sections только из назначенных городов; не получает legal text/policy refs/чужой primary через readiness |
| Справочники | `references.<type>.read/manage`, по паре для каждого из 5 типов | GLOBAL; CALLBACK_INTERVAL также CITY с назначением | COMPANY types: явно делегируемый GLOBAL на конкретный тип; CALLBACK_INTERVAL: только CITY и действующее admin-city assignment. Нельзя передавать произвольное имя таблицы/другой type |
| Content | `content.read/manage/publish` | GLOBAL для COMPANY и любого города либо CITY в назначенном городе | Только CITY, текущее admin-city assignment. COMPANY content management не открывается manager по умолчанию; расширение потребует явного решения |
| Legal | `legal.read`, `legal.manage` | Только SYSTEM ADMIN GLOBAL, manage+read для create/publish; actor/reviewer = аутентифицированный staff | Нет даже при ошибочно записанном grant |
| Geography | прежние 5 codes | Без расширения утверждённой P03-02 матрицы | Без расширения P03-02; zones/district drafts, не city settings/publish |

Всего 18 новых кодов (2 company, 1 readiness, 10 reference, 3 content, 2 legal); их точный список фиксируется в контракте и миграции до начала source-реализации. При выборе варианта A первоначальный SYSTEM ADMIN получает один источник этих GLOBAL полномочий; прочие сотрудники — только последующее явное делегирование допустимых кодов/областей.

URL-типы, DB enum и capability segment сопоставляются явно; исходная грамматика `permissions_metadata_check` не расширяется:

| URL type | DB type | Новые точные коды | Допустимый stored scope |
| --- | --- | --- | --- |
| `callback_interval` | `CALLBACK_INTERVAL` | `references.callbackinterval.read`, `references.callbackinterval.manage` | CITY для web M/CUSTOM/A; GLOBAL только SYSTEM ADMIN |
| `payment_method` | `PAYMENT_METHOD` | `references.paymentmethod.read`, `references.paymentmethod.manage` | GLOBAL для web M/CUSTOM/A |
| `cancel_reason` | `CANCEL_REASON` | `references.cancelreason.read`, `references.cancelreason.manage` | GLOBAL для web M/CUSTOM/A |
| `decline_reason` | `DECLINE_REASON` | `references.declinereason.read`, `references.declinereason.manage` | GLOBAL для web M/CUSTOM/A |
| `request_source` | `REQUEST_SOURCE` | `references.requestsource.read`, `references.requestsource.manage` | GLOBAL для web M/CUSTOM/A |
| — | company | `settings.fullread`, `settings.manage` | GLOBAL, только SYSTEM ADMIN |
| — | readiness | `settings.readiness.read` | GLOBAL для web M/CUSTOM/A; это право на safe projection, не глобальная территория |
| — | content | `content.read`, `content.manage`, `content.publish` | CITY для web M/CUSTOM/A; GLOBAL только SYSTEM ADMIN |
| — | legal | `legal.read`, `legal.manage` | GLOBAL, только SYSTEM ADMIN |

В 018 адресно заменить `role_permissions_scope_check`: сохранить прежние правила всех существующих кодов, добавить CITY только для новых content/callback codes. Новый guard разрешает scope/target role ровно из таблицы; перед catalog INSERT проверить полное отсутствие всех 18 codes, коллизия прерывает всю migration. Новые коды `protected=false`, active; неизвестный/disabled/drifted grant не authority. CUSTOM сохраняет существующий channel marker: CUSTOM-web с MANAGER marker получает manager-матрицу по явным grants, CUSTOM-TG с TECHNICIAN marker имеет нулевые эффективные P03 grants и операции, даже если та же CUSTOM роль содержит domain grants для web. Shared role assignment не запрещается; actor must be entitled to delegate все её stored domain grants.

Территории всех требуемых прав **пересекаются**. GLOBAL manage + CITY read не даёт COMPANY write или чужой city; read+manage+publish должны покрывать один и тот же реальный target. CITY content не читает COMPANY revision через `allow_company_fallback`: fallback — правило использования, не administrative authority. Чужая CITY identity — 404; отсутствие operation grant — 403. actor/reviewedBy/ready/publishedAt/consent fields browser не задаёт.

Единый delegation contract используется в `RolesService.replacePermissions/checkReplacement`, `StaffService.create/requireDelegable`, `StaffService.assign`, каталоге/AccessView/DB guard/CRM. Выдача кода, расширение scope и назначение готовой роли требуют у actor живой GLOBAL **того же** кода и допустимость target. Сохранение прежнего полностью неизменного grant на другой видимой роли не является новой выдачей; смена CITY→GLOBAL или другой code не retention. `adminAssign` при **новом** административном городе под тем же RBAC lock проверяет GLOBAL каждого effective CITY P03-кода цели, для которого действительно расширяется область. Отзыв города этим не ограничивается. Это не расширяет прежние пять geography grants. Проверяются оба порядка grant→city и city→grant, create/assign роли-посредника, CUSTOM-web и CUSTOM-TG.

## 3. API и storage-contract

### 3.1. Команды на существующих портах

Новый namespace исходников `settings/management/`; не копировать SQL-инварианты из configuration/legal. Authorization расширяется отдельным domain-grant contract (не смешивать multi-scope с фиксированными staff capabilities). `AccessView` получает отдельные P03 grants; старый staff/geo контракт сохраняется. Одна transaction: explicit RC → RBAC policy lock → authenticated staff/link/session → trusted role/grants/назначения → company advisory lock при необходимости → city → target aggregate. Не открывать вложенную транзакцию внутри ports. Legal port повторно проверяет RC на этом же клиенте; real-PG composition обязателен.

Каждая новая административная mutation принимает `Idempotency-Key` UUID, а existing aggregate — `If-Match: "p03-vN"` (company version 0 допустима для просмотра, но первая revision создаётся существующей geography activation). Geography сохраняет свой `"geo-vN"`. Без I — 400, без обязательной V — 428, stale новой команды — 412. После уточнения Gate 2 changed-payload replay даёт 409 только при независимой текущей авторизации исходной и запрошенной целей; исходная цель вне допуска — 403/404. Для `bootstrapRevoke` любое несовпадение digest даёт одинаковый 404 без данных, так как прежний closed code не хранится отдельно от digest; точный replay всё равно требует актуальный GLOBAL точного кода. Creates не требуют версии несуществующего aggregate. Scope/реальный parent/type/visibility проверяются до receipt replay, включая созданный объект по server ID из receipt. Для replay проверяется право читать разрешённую историческую identity после archive; archive не разрешает новую publication. CAS применяется только к **новой** mutation: identical replay не отказывается из-за того, что исходная версия была успешно изменена этой командой.

После любого потенциального ожидания внутри callback нужна повторная проверка сессии/активности, включая fresh DB `clock_timestamp()` после receipt SELECT и после последних domain/audit/outbox/receipt INSERT перед successful transaction completion. Удерживаемые RBAC/staff/session locks сериализуют revoke/role change, но не останавливают expiry. Истекшая idle/absolute session → 401 и весь write rollback; ни minimal receipt, ни detail не раскрываются. Read callbacks также завершают свежей session-clock проверкой после последнего SELECT; larger response сериализуется после освобождения DB connection. Lost-COMMIT-ACK recovery начинает новую RC/auth transaction и возвращает только найденную identical receipt после проверки реального target и свежей проверки **после** её чтения. Не начинать повторную mutation автоматически.

Новая additive018 `p03_command_receipts`: `actor_id`, closed `operation`, UUID `key`, `request_sha256` (versioned canonical envelope `v,actor,operation,target,key,expectedVersion,normalizedBody`), `entity_id`, `entity_version`, nullable `revision_id`, nullable `revision_version`, DB timestamp. Unique(actor,operation,key), immutable UPDATE/DELETE/TRUNCATE deny, узкие column privileges. Хеш не шифрует body и не публикуется; raw request/legal text/operator data никогда не хранятся в receipt/audit/outbox. В ответе ровно:

| Operation | Minimal response data |
| --- | --- |
| `companyPublish` | `{id,version}` — ID и sequence новой company revision |
| `referenceCreate`, `referenceArchive`, `contentCreate`, `contentArchive`, `legalCreate` | `{id,version}` — stable aggregate и его row_version |
| `referencePublish`, `contentPublish`, `legalPublish` | `{id,version,revisionId,revisionVersion}` — stable aggregate, новый row_version и exact immutable revision |
| `bootstrapRevoke` | `{id,version}` — ID исходного assignment и новая версия exact closed-code source; code остаётся в path |

Receipt shape по операции фиксирует CHECK; revision-поля либо оба заполнены, либо оба NULL, UUID/positive finite versions валидны. Response replay имеет те же data/ETag; replay-marker можно вернуть отдельным header, не изменяя data. Concurrent identical commands сериализуются RBAC write lock: один domain result, immutable receipt. Ошибка receipt/audit/outbox откатывает domain+evidence. Существующий domain port audit сохраняется; management event добавляет authenticated actor к structural create (включая legal document), payload только IDs/closed enums/version. Отдельные fault tests каждого evidence write. Без SQL/драйверных/введённых данных в fixed problem responses, Cache-Control:no-store.

Миграция018 только additive: catalog+guards+receipt table и, если явно выбран A, отдельный bootstrap registry/issuer. Исторические001–017 не редактируются. Prisma, proof inventories и auth-readiness меняются согласованно; новые routes default-off при schema/capability/issuer incompatibility. Не превращать механическую `/health/ready` в обещание бизнес/юридической готовности.

### 3.2. Явные маршруты

Все paths относительно `/api/v1`; staff-web only, exact Origin, JSON + CSRF для mutations, no-store. Existing geography endpoints переиспользуются; публичного city selector нет.

| Routes | Операции |
| --- | --- |
| `GET /settings/versions`, `GET /settings/versions/:version` | Только `settings.fullread`: latest/history/exact revision. Manager не получает full DTO; operational safe projection — отдельный readiness endpoint |
| `POST /settings/versions` | Полная типизированная immutable revision; только 7 existing fields, primary/launch mode не меняются этим command |
| `GET /settings/readiness` | Перечень разрешённых P03 missing/configured секций и `NOT_IMPLEMENTED/NOT_ASSESSED` для P04/P05/P09/providers/production, не фиктивное `ready:true` |
| `GET/POST /settings/references/:type`, `GET /settings/references/:type/:id` | Бounded list/create identity/detail; callback требует cityId, остальные cityId отвергают |
| `GET/POST /settings/references/:type/:id/versions`, `POST …/:id/archive` | Неизменяемая reviewed version+CAS и однонаправленный archive; исторический exact snapshot остаётся |
| `GET/POST /content/blocks`, `GET /content/blocks/:id` | scope-specific bounded list/create/details; real target scope из DB, не body |
| `GET /content/blocks/:id/revisions`, `POST …/:id/publish`, `POST …/:id/archive` | Text остаётся в локальном редакторе до explicit publish; публикация — новая immutable revision+CAS |
| `GET/POST /legal/documents`, `GET /legal/documents/:id`, `GET …/:id/versions`, `GET …/:id/versions/:versionId`, `POST …/:id/publish` | Только REQUEST_PROCESSING/MARKETING; version text/checksum/provenance для legal.read; create/publish требует legal.manage+read и verified actor |

ADDRESS_COVERAGE остаётся зарезервированным: через новые HTTP list/detail/create/publish не открывается и не используется по умолчанию. Consent/session history не выдаётся legal management UI; нет кнопок GIVE/REVOKE за клиента. No generic patch arbitrary settings JSON.

Справочники/content/legal уже имеют immediate-publication ports, но не persisted editable draft. В этом scope формы держат неподтверждённый текст только в памяти; запись отправляется после явного подтверждения «Опубликовать новую версию». Нет фиктивного PATCH draft, черновики не сохраняются в localStorage. Content create identity и archive — manage, publish — manage+publish; проверяемая неизменяемая revision с sourceRef обязательна. Legal publication не трактует нажатие как юридическое одобрение real text; synthetic-only acceptance и реальные provenance/решения остаются отдельными.

### 3.3. Списки и wire schema

Все administrative lists получают bounded keyset `limit` 1…200 (default50), `cursor` и `{items,pageInfo:{hasMore,nextCursor}}`; parent version/ETag сохраняются. Stable sort `(code,id)` или `(version,id)`, cursor versioned/bound parent/type/city/scope/filter, не credential и не authority. Невалидный/чужой курсор не меняет server scope. SQL authorization/filter/keyset predicates применяются **до LIMIT+1** на каждой странице; total counts без отдельной нужды не вычисляются. Geography extension backward-compatible: старые `{items,version?}` не удаляются, pageInfo добавляется. Фильтры без дубликатов/unknown query keys.

Истории content/legal/company — **компактные summaries**, без `body`, operator address, legal basis и source text: identity/version/title (content/legal), publishedAt и checksum (legal). Точная content/reference revision читается через `GET …/:id/revisions/:revisionId` / `GET …/:id/versions/:versionId` с independently verified same-parent/type/city, legal exact route приведён выше. Полные тела не выдаются по 200 штук. Ограничения сериализованного UTF-8 ответа: list/history ≤512 KiB, exact legal revision ≤2 MiB, exact content ≤256 KiB; превышение закрывает ответ безопасным fixed error, не отдаёт partial DTO. Summary shape/длины в shared contract гарантируют этот budget, проверяются maximum-bound fixtures. Сериализация и проверка bytes не удерживают DB transaction.

Existing full district-coverage GET не превращается в первую страницу: он возвращает **весь** bounded mapping текущей version либо явный отказ, никогда partial set. CRM загружает его независимо от paged district picker, держит полный набор включая строки вне текущей страницы и при PUT отправляет полный набор; не удаляет невидимые/архивированные строки автоматически. Изменение набора требует explicit action и свежую version. Scope-safe picker: city `{id,code,status,version,currentVersionId}`, city version `{id,sequence,timezone,published}`, technician `{id,displayName,version}` только по существующему `requireTechnicianAccess` в конкретном разрешённом городе; никакого глобального staff list/credentials/role detail. Новый narrow picker дополнительно требует matching `staff.geography.read` и существующую visibility, а не staff.read по умолчанию.

Readiness DTO строится по allowlist и не сериализует внутренний `CompanySettingsReadiness` напрямую. Только fixed section/status/missing codes + разрешённые city IDs/names; SYSTEM ADMIN с fullread может отдельно получить primary/settings details. Manager не получает чужой primary, policy refs, operator/contact text, legal document IDs/body. REQUEST_PROCESSING проверяется отдельно; MARKETING не является prerequisite, ADDRESS_COVERAGE исключён даже по guessed ID. Любые `ready`, global counts, полный primary и sourceRef не переносятся автоматически из внутренних ports.

Общий runtime-neutral wire contract — один небольшой `packages/p03-contracts` workspace package без новых внешних библиотек; plain schema/operation metadata, pure bounded response decoders и type definitions, без универсального schema-framework. API/web импортируют только public wire contract, не server ports/credentials. Build JS+declarations перед API/Web, отдельный export/dist, никаких cross-source API-rootDir imports. Детерминированный Node generate/verify сверяет endpoint/DTO shapes; generated outputs не коммитятся. Exact dependency graph/lock review перед workspace edge, no lifecycle scripts.

При новом package обновляются root build/typecheck и clean-install tooling, Docker manifest COPY и `infra/file-processing/Dockerfile.dockerignore`: максимум новый package manifest, **без** wire/CRM source в decoder context/runtime. В настоящее P03-04 trusted worker не добавлять CRM imports; не менять decoder/scanner image pins/fixture descriptor. Existing exact worker snapshot используется для regression. Чистая сборка application и воспроизводимость build recipe проверяются отдельно; новый полученный OCI digest сам доверенным не становится и требует отдельного review, если вообще понадобится запускать его. Existing catalog/source/runtime ACL remain minimal.

### 3.4. Размеры HTTP

До существующего 4 KiB parser установить selector по **точному HTTP method+normalized path**: только legal POST publish — 1 MiB UTF-8, content POST publish — 128 KiB, coverage PUT — 64 KiB. Остальные запросы, в том числе auth/RBAC и несовпавшие aliases/methods, остаются 4 KiB strict JSON. Prefix/wildcard не выбирает увеличенный parser. Content-Type/schema не доверяют, compressed Content-Encoding отклоняется (inflate:false), фактические streaming bytes ограничиваются до JSON parse, Content-Length не заменяет bound. На чтение body отводится 10 s absolute deadline с закрытием сокета/cleanup, обработка body до DB connect/lock. Превышение — safe 413, deadline — safe 408, unsupported encoding — 415, malformed JSON — 400; parser error адаптер явно создаёт соответствующий HttpException для ProblemFilter, сырое Express error/body в лог/ответ не попадают. Fixed responses no-store.

UI проверяет domain char length и фактические UTF-8 JSON bytes; 200k legal chars не означает, что любые escape-представления проходят 1 MiB. Auth/Origin preflight не заменяет locked authorization; reverse-proxy sample/test caps согласованы, live proxy не меняется. Пограничные non-ASCII/chunked/over-limit/slow/encoding/неверный method тестируются actual HTTP, 4KiB old auth cap остаётся regression.

## 4. CRM

Новые закрытые разделы в существующей CRM: «Города и зоны», «Настройки и справочники», «Контент», «Документы», «Готовность». Переиспользуются current cookie auth, CSRF из памяти, no-store same-origin relative URLs, не создавать второй auth/backend. Навигация из существующего workspace, no public links. Форма/кнопка видны только по live server access projection, но это не замена server authorization.

География: create draft city, history/local version/publish/activate/primary/deactivate через существующие команды; districts/zone draft/coverage/publish/archive. Второй synthetic city используется для scope proof, не multi-city production activation. Manager не получает city-write/publish от district management. Membership/admin-city operations, уже доступные в P03-02, показываются только при независимых staff.geography/role grants; bounded scoped picker не раскрывает глобальный staff list. Неиспользуемый dispatch/visit UI не строится.

Настройки: полный admin editor 7 полей с provenance, missing-state вместо default/фиктивного значения; manager получает только safe readiness projection с отдельным `settings.readiness.read`. Справочники — отдельный тип и scope, интервалы в явном city/timezone, история и archive. Content — простые textareas, plain React text (без HTML injection/markdown engine), explicit source и preview из выбранной revision. Legal — отдельная purpose/kind, exact text/checksum/history, explicit publication; никаких consent toggles.

Общий command UX: один in-flight, UUID I на submission; потеря сети, неразбираемый успешный ответ и неопределённый 5xx не доказывают rollback. Сохранить **тот же** in-memory key/canonical payload/If-Match и исходную authenticated identity для явного retry, не создавать новый command автоматически. При смене actor/channel/generation pending request уничтожается; повтор от другого identity запрещён. Подтверждённый успех с неудачным refresh не переотправляется: показать безопасное подтверждение без раскрытия карточки, далее только reload/login. После подтверждения — повторная проверка identity/access и чтение актуальной версии; stale 412 требует явной сверки, не silent overwrite. Logout/unmount/change actor немедленно очищают текст/квитанции/pending bodies, abort generation prevents late stale data. Ничего чувствительного в URL/localStorage/log/toast. Доступность labels/keyboard/status/error summary, desktop/mobile, XSS/security-text tests.

## 5. Рабочие пакеты и независимость

1. Root: план/решения/общий contract и координация scope. Astra: read-only план до source.
2. Schema/authz: additive018+Prisma, new capability/delegation/issuer/locking authorization; independent migration proof отдельным агентом.
3. Management server: transaction runner, inputs/reads/routes/body limits/DI + port adapters; не менять file-lifecycle и исторические миграции. Стабильный wire contract до CRM.
4. CRM: отдельные файлы управления + минимальный navigation integration; независимый browser author не пишет server code.
5. Independent PG/HTTP tests: real Nest+PG, фикстуры текущих ролей/городов, race/fault/replay; никакие mock response не доказывают security.
6. Root integration: review final diff/frozen gates/docs/secrets; Astra: полный готовый P03-05 + межсрезовая P03 regression до предъявления владельцу.

Точные disjoint write scopes и зависимости будут записаны на team board после audit/решения о bootstrap. Нет concurrent generator/formatter по чужим файлам.

## 6. Приёмка и доказательства

### 6.1. Полнота: форма → route → право → доказательство

| Форма/операция | Маршруты | Право/версия | Доказательство |
| --- | --- | --- | --- |
| Город identity/local history/version/publish/activate/primary/deactivate | существующие `/settings/service-cities/**` | утверждённые geography read/manage/publish, `geo-vN` | API+PG invariant/роль; browser admin journey и manager read-only |
| Район create/edit/archive | `…/administrative-districts/**` | geography.read/manage, `geo-vN`, published dependencies guards | wrong-city/stale+archive PG, формы/browser |
| Zone drafts/coverage/publish/archive | `…/service-areas/**` | geography.read/manage/publish, draft+parent versions | полный mapping с district вне страницы, compare-and-swap/race+history, browser |
| Admin-city assignment/revoke | `…/administrators/:staffId/assignments/**` | прежние geo.manage GLOBAL+staff.role.assign, новые same-code GLOBAL P03 расширяемых CITY grants | посредник без собственного content/callback права denied, оба порядка grant/territory |
| Technician city/zone admission/revoke | существующие `…/technicians/:staffId/**` + narrow scoped picker | независимые staff.geography.read/manage, target staff version | no foreign roster leak, interval/same-city/history, browser scoped form |
| Company full fields/history/publication | `/settings/versions/**` | settings.fullread+manage SYSTEM ADMIN, `p03-vN` | empty/missing denied, carry-over geo primary concurrency, real CRM publish smoke |
| 5 типов refs, callback interval/точная history/archive | `/settings/references/:type/**` | matching type read/manage, intersection CITY/GLOBAL | wrong type/city/timezone, >200 pages, archived history и browser |
| Content identity/history/exact body/publish/archive | `/content/blocks/**` | content.read/manage/publish в одном target scope | CITY cannot fallback-read COMPANY, XSS/plain text, stale/receipt/fault browser+PG |
| Legal identity/history/exacttext/publish | `/legal/documents/**` | legal.read/manage SYSTEM ADMIN | checksum/text immutable, actor server, ADDRESS_COVERAGE guessed-ID denial, UTF8/bytes/actual smoke |
| Safe readiness sections | `/settings/readiness` | settings.readiness.read + независимые section grants | manager no refs/primary/foreigncity, MARKETING not prerequisite, explicit NOT_ASSESSED |
| Permissions editing and role assignment | существующий role/staff UI/API | roles.permissions.manage/staff.role.assign + own GLOBAL same-code | replace/create/assign/mixed CUSTOM channel, role-wide effect confirmation |
| Bootstrap-source inspection/revoke (A) | `/settings/management/bootstrap/**` | SYSTEM ADMIN roles.permissions.manage + own exact GLOBAL; I/V | issuer/recovery/reassignment no regrant, revoke actor/clock/version, role grants independent |

Тестовый real browser smoke использует production Next и **изолированный same-origin HTTPS loopback proxy** с временным synthetic certificate/CA только в fixture, реально работающую Secure-cookie, Nest и новую PG DB. Никаких ослаблений app cookie/auth, production TLS/proxy config или replacement DSH GUI. Проверяются реальный admin publish и прямой server denial менеджеру; шесть browser projects отдельно проверяют остальные формы с явно synthetic intercepted responses. Source dumps/password/cert private keys остаются ignored и не выводятся.

G01–G07 сохраняют [исходные определения](DATABASE.md#обязательные-инварианты-и-fk), не семь общих PASS: G01 — P03 same-city anchor/reference proof, request/visit до P05/P09 неприменимы; G02 — immutable city/area/reference snapshots, future request snapshots неприменимы; G03 — pricing/quotes до P04/P11 неприменимы; G04 — существующие membership same-city/period guards, dispatch до P09 неприменим; G05 — timezone provenance P03, visit/cross-city schedule до P09 неприменим; G06 — нет public city selector, staff administration не public intake; G07 — второй synthetic city/timezone/district/zone existing commands без ALTER, цена до P04 неприменима.

### 6.2. Gate

- Migration018: populated017→018 preservation, fresh/capped older paths/replay/drift, exact column ACL/triggers/FKs/CHECK/receipt immutability; catalog collision/default-grants negative; bootstrap identity/revoke/reassign/absence/expiry proofs для выбранного варианта. Не применять к рабочей dev DB. Старые SQL001–017 и capped017 proof неизменны; hardcoded inventories/guards (`auth-db-fixture`, `file-privacy-fixture`, restore chain assertion) обновить на явную полную expected018 chain, не ослаблять до «есть какая-нибудь миграция». Отдельный current 018 proof, остальным историческим proof передать capped history как раньше.
- Real API/PG каждой группы: no session, TG/master/wrongrole, disabled user/session stale, missing read/manage/publish, forbidden GLOBAL/CITY, city assignment revoke vs in-flight command, foreign UUID/filter/cursor/hidden counts, extra actor/published/ready/secret fields. Never write values to logs.
- Same key samebody parallel/lostresponse returns minimal identical receipt; changedbody/target/version409 только после допуска обеих целей (bootstrap mismatch всегда404); replayafterpermissionrevoke403/404 before receipt; audit/outbox/receipt fault→rollback. No locked client/network wait. Permission revoke checked afteractualwait; committed command not retroactively erased.
- Domain invariants: company/geography concurrent primary revision carryfields; no circular gate requiring completed company before its first city activation; invalid/missingfield publish denied; referencewrongtype/city/archived/current/history; contentcompanyfallbackexplicit; legalcurrentversionchecksums and ADDRESS_COVERAGEdeny; no consent/PII routes.
- HTTP 4KiB auth unchanged; actual UTF-8/boundary/compressed/malformed Content-Length/error413 tests for route-local caps. All GET/POST responses no-store.
- Browser: Chromium/Firefox/WebKit desktop+mobile production bundle; forms/history/missingdata, independent read/manage/publish, staleversion/revoke/actorchange, scopepicker no foreigndata, no auto-retry/XSS/largeUTF8/errors. Existing mocked-browser suites remain explicitly UI proofs. Добавить минимум один **real CRM→same-origin proxy→Nest→isolated PG** smoke для admin manage/publish и manager-denial; это не live production proof. Существующий browser infrastructure стартует тестовый Next, не заменяет DSH GUI.
- Full regression: generate/contracts consistency, Prisma validate/migration proofs, workspace typecheck/source ESLint (existing ignored test-results archives исключаются), API/Web/MiniApp builds, full Vitest с **всеми шестью opt-ins P03-04** без обязательных skipped, browser suites, dependency/license/frozen lock+secret/history/diff scans. Code/test/schema/contract and worker descriptor hashes до/после, JSON docs-only postgate deltas отдельно. Числа только фактически полученные.
- Итоговый **полный аудит Astra P03-05 и стыков P03-01…04**: scope/authz/delegation, data/HTTP/client, receipts/revocation/readiness и документы. Все MUST исправить и предъявить актуальный frozen gate на окончательном дереве, не только адресный PASS.

Успех этого плана не означает приёмку владельцем. После готовности и Astra PASS — отчёт владельцу. Commit только после его приёмки согласно AGENTS; нового push-разрешения и старта P04 этот запрос не даёт.
