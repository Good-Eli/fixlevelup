# Technical API/worker, DB readiness и P01-01.9A Outbox

Технические процессы одного backend-пакета. API использует Prisma/adapter-pg
для read-only readiness под отдельной runtime-role. Worker подключён к БД;
claim/lease/fencing реализованы для технического outbox. Production handlers
пока отсутствуют, поэтому события не забираются и не помечаются обработанными.
Бизнес-модули, провайдеры и реальные отправки не реализованы.

## Запуск из корня репозитория (PowerShell)

```powershell
$env:COREPACK_HOME = Join-Path $env:LOCALAPPDATA 'fixlevelup-tooling\corepack'
$env:COREPACK_ENABLE_AUTO_PIN = '0'
$env:COREPACK_DEFAULT_TO_LATEST = '0'
corepack pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies
corepack pnpm run check
$env:NODE_ENV = 'development'
$env:APP_HOST = '127.0.0.1'
$env:APP_PORT = '4000'
$env:SHUTDOWN_TIMEOUT_MS = '10000'
$env:DB_HOST = '127.0.0.1'
$env:DB_PORT = '55432'
$env:DB_NAME = 'fixlevelup_dev'
$env:DB_USER = 'fixlevelup_runtime'
# DB_PASSWORD задайте существующим runtime-role secret через локальное окружение.
# Не используйте bootstrap/migrator password и не печатайте его в командной строке.
corepack pnpm --filter @fixlevelup/api start
# В отдельном процессе с теми же техническими env:
corepack pnpm --filter @fixlevelup/api start:worker
```

Entrypoints не загружают .env автоматически. .env.example — перечень
технических переменных без secrets. API и worker требуют DB_PASSWORD runtime-role;
локальные credentials уже существуют в ignored database-tooling/.env.
Entrypoint не читает этот файл автоматически и не использует migrator/admin.
Оба entrypoint валидируют общий technical config. Worker не слушает порт,
хотя APP_HOST/APP_PORT пока входят в общий config contract.
Порт 0 разрешён исключительно для NODE_ENV=test. Foundation привязан к loopback;
внешняя публикация и reverse proxy относятся к следующим подэтапам.

## P02-02: первоначальный администратор

**Ограничение окружения:** оба CLI намеренно жёстко привязаны к локальному dev
PostgreSQL `127.0.0.1:55432`, базе `fixlevelup_dev` и роли `fixlevelup_migrator`;
выбор другой БД через аргументы или переменные не поддерживается. Это защита
текущего dev scope, а не универсальная production-процедура: для других сред
потребуются отдельный согласованный инструмент, конфигурация и security review.

**Открытый gate, принятый владельцем для P02-02:** ручная проверка bootstrap и
recovery в доступной человеку интерактивной консоли не выполнена. Она обязательна
перед первым реальным использованием этих CLI в рабочей среде: проверить скрытие
пароля, подтверждение, Backspace, несовпадение, Ctrl+C и восстановление терминала
на полностью изолированных synthetic данных. Автоматизированные pseudo-TTY
проверки не заменяют ручную проверку.

Только локальный оператор на доверенной машине, после применения миграций; не
использовать удалённый или записываемый терминал. В отдельном доверенном процессе
задайте `DB_PASSWORD` миграционной роли `fixlevelup_migrator` через защищённый
механизм окружения, не печатая значение; затем из корня репозитория после API
build запустите в настоящем интерактивном терминале:

```powershell
corepack pnpm --filter @fixlevelup/api run staff:bootstrap
```

Оператор вводит логин, затем пароль и подтверждение без отображения. Не передавать
пароль в аргументах, переменных окружения, URL, переписке, файлах или логах. Не
запускать с перенаправленным stdin/stdout, через GUI без TTY или с включённой записью
терминала. Нужно отдельно отключить логирование параметров SQL и ошибок в БД,
прокси и диагностических средствах: приложение само не контролирует внешние логи.
Ошибка выводится обобщённо; при неопределённом результате commit сначала проверить
аудит/состояние, не повторять вслепую. Параллельные bootstrap сериализуются;
атомарный marker запрещает повтор даже после смены роли первого администратора.
Если существовал администратор до первого запуска, повтор также отклоняется.
Новый администратор назначается через [RBAC API](../../docs/RBAC.md) активному сотруднику с уже существующим web credential; повторный bootstrap для этого не используется. Миграционный владелец БД остаётся доверенной стороной.

Пароль хранится как Argon2id PHC с случайной солью; используется встроенный
`node:crypto` Node 24, API Argon2 в этой версии экспериментальный. Доступ к самому
инструменту и migrator DB credential — привилегированный локальный доступ; не давать
их недоверенным пользователям. Runtime API/worker не получают прав на staff-таблицы
на этом подэтапе; будущие способы управления требуют отдельного security review. Логин принимает латинские буквы, цифры и `._@+-`,
начинается с буквы или цифры; пароль от 16 до 1024 байт UTF-8 без управляющих
символов. Это технические ограничения P02-02, не заявленная завершённая password policy.

## Восстановление доступа администратора

Не повторять bootstrap и не удалять marker. Это отдельная привилегированная локальная
операция замены credential существующего **ACTIVE ADMIN**; она не создаёт аккаунт,
не меняет роль, login или состояние. Перед запуском владелец проверяет личность и
полномочия получателя и точный login, фиксирует причину обращения и разрешает
оператору работу. Нужны защищённая локальная консоль, миграционный credential и
резервная копия; убедитесь, что запись терминала и логирование параметров SQL,
ошибок/секретов в PostgreSQL, драйвере и промежуточных компонентах отключены.
При невозможности обеспечить эти условия — остановиться. Разграничение доступа к
БД и рабочему месту оператора необходимо: migrator имеет широкие DDL-права.

В отдельном доверенном терминале установите технический `DB_PASSWORD` для
`fixlevelup_migrator` через защищённый механизм окружения, не печатая значение;
после API build запустите:

```powershell
corepack pnpm --filter @fixlevelup/api run staff:recover
```

Без аргументов: введите существующий login, новый пароль и подтверждение;
пароль скрыт. В транзакции обновляются хэш и `auth_version`, записывается
`STAFF_RECOVERY` в audit; если пользователь отсутствует, не активен, не ADMIN,
или произошла ошибка — общий отказ и rollback. Оператор сверяет audit и наличие
ровно нужной учётной записи; при неопределённом commit сначала проверяет audit,
а не повторяет без проверки. Техническое окружение с credential после работы
закрывается/очищается; новый пароль вводит непосредственно доверенный владелец
или получает его по отдельно согласованному защищённому каналу. P02-03 web auth
при проверке сессии сверяет актуальный `auth_version`; восстановление увеличивает
его и тем самым делает старые web-сессии недействительными.

## P02-03: web auth менеджера и администратора

Web auth по умолчанию отключена: `/auth/*` отсутствуют. Для явного включения вместе
с настроенной runtime-БД задать `WEB_AUTH_ENABLED=1`, `WEB_AUTH_ORIGIN` — точный
HTTPS origin браузера без пути и завершающего `/`, `WEB_AUTH_CSRF_SECRET` и
`WEB_AUTH_THROTTLE_SECRET` — два независимых криптографически случайных значения
по 32 байта в lowercase hex. Частичная/невалидная конфигурация и одинаковые
секреты отклоняются при запуске; значения не печатать и не хранить в Git. Все
экземпляры API используют одни и те же секреты; их ротация инвалидирует CSRF или
меняет идентичность rate-limit ключей. Вход доступен только ACTIVE ADMIN/MANAGER.

Сервер хранит SHA-256 от случайного session token; cookie `__Host-...` требует
HTTPS на одном origin, Secure/HttpOnly/SameSite=Strict/Path=/ без Domain. Клиент
использует `POST /api/v1/auth/login` с JSON и `X-CSRF-Token: login`, затем для
`POST /api/v1/auth/session/renew`, `/api/v1/auth/logout` и
`/api/v1/auth/password/change` передаёт session-bound CSRF из ответа или
`GET /api/v1/auth/me` и точный Origin. `GET /me` требует `X-Auth-Request: 1`;
password change требует актуальный `If-Match` из ETag. Все ответы —
no-store, cookie-токен не возвращается в JSON. Сессия истекает через 30 минут
бездействия или 12 часов с входа; renew атомарно меняет токен и не продлевает
абсолютный предел. Одновременный renew только один раз успешен; потерянный ответ
может потребовать повторного входа. Logout отзывает текущую сессию; смена пароля
сохраняет текущую, но инвалидирует другие через актуальный `auth_version`.

Пять неудачных проверок по одному точному login в любые 15 минут блокируют дальнейшие
попытки; отдельный source-лимит — 50 на 15 минут. Проверки смены пароля также
ограничены. События хранятся в PostgreSQL под HMAC-ключами. Резервирование до
Argon2 учитывает параллельные попытки; успешные освобождают слот, сбой процесса
удерживает незавершённый резерв до истечения. Источник — прямой socket address,
не X-Forwarded-For; за reverse proxy все клиенты могут разделить один лимит. Для
реального proxy и публикации необходима отдельная проверенная доверенная схема
source IP. При ошибке хранилища доступ закрыт. Включённый API каждые 10 секунд запускает
ограниченную очистку истёкших попыток и ключей и сессий, истёкших более 30 дней
назад; каждая функция удаляет не более 100 записей за вызов. Это не полноценный
security/production approval или гарантия удержания БД при произвольной нагрузке.

## P03-03: внутренние порты настроек, справочников и согласий

Подэтап **принят владельцем 21.11.2026 в 21:34** в synthetic внутреннем scope
после адресной доработки трёх замечаний независимого ревью; принятый срез
коммитится отдельным локальным коммитом, SHA не заявлен.
Контракт — [P03-03-CONTRACT](../../docs/P03-03-CONTRACT.md), решение —
[DECISIONS §24](../../docs/DECISIONS.md#24-p03-03--внутренние-порты-настроек-справочников-и-согласий).

В `apps/api/src/settings/configuration/` и `apps/api/src/settings/legal/` реализованы
внутренние порты слоя данных: ревизии настроек компании со ссылками на reviewed
политику, малые типизированные справочники, контент с источником значения,
юридические документы и append-only события согласия, минимальный pre-submit
anchor доверенной серверной сессии. Порты покрыты контрактными тестами
(39 configuration + 36 legal случаев); полный Vitest — 622/622 в 48 файлах.
Предыдущий прогон 610/610 и 39 + 24 случаев — исторический, до доработки.

Границы, которые важно не нарушить при доработке:

- **Ни одного HTTP-маршрута, capability и роли** этот подэтап не добавляет; в
  `app.module.ts` контроллеры не регистрируются. Порты вызываются доверенным
  серверным кодом (будущие P03-05/P05) внутри уже открытой транзакции: они не
  аутентифицируют, не проверяют права и не являются защищёнными endpoints.
- Требование вызывающей транзакции проверяется в рантайме: блокировка настроек
  компании транзакционная, вне явной транзакции запись отклоняется, а не
  выполняется неатомарно.
- Q02/Q13 остаются открытыми: срок жизни anchor передаёт вызывающая политика без
  TTL по умолчанию; сроки хранения не выдумываются — в настройках компании
  хранятся только policy refs (reviewed provenance), а не сами правила.
  Юридические документы хранят неизменяемый текст: synthetic-тесты используют
  собственный текст, реальные тексты утверждает владелец. `ADDRESS_COVERAGE` —
  зарезервированное слово словаря без live-включения (нет реального документа,
  seed и маршрута); synthetic-вставка для проверки раздельности целей допустима.
- Реальные города, контакты, юридические тексты, документы и ПД не создаются:
  тестовые документы содержат только синтетический текст. Файлы и intake
  остаются за P03-04/P05.

## P03-04A: принятый no-byte срез резервирования файлов

Срез **принят владельцем 21.11.2026** в synthetic внутреннем scope: только резервирование `RESERVED→CANCELLED`, без передачи байтов. `src/files/reservations/` предоставляет только внутренние `reserveFileUpload`, `readFileUploadIntent`, `cancelFileUploadIntent`, `beginFileReservationTransaction`. Caller открывает READ COMMITTED до data access. Mandatory reviewed policy без defaults, raw F token, exact current GIVEN, DB clock после session→document→intent locks, pending quota и owner/key idempotency; cancel one-way CAS без нового согласия. Успех резервирует capacity, а не загружает файл. Нет S3 IO/SDK/HTTP/scanner/EXIF/READY/access/stream/delete и новых зависимостей. Staff-owner вариант явно отказывает до DB access.

Финальные проверки среза A: 679/679 Vitest в 50 файлах (40 unit + 17 PostgreSQL), 14 миграций/138 CHECK, SQL014 SHA-256 `2ec24c33…bb4377`, typecheck/source-lint/build PASS; повторный read-only вердикт Astra — PASS. Принятый срез A зафиксирован отдельным локальным коммитом `7d92122`, без B.

[План P03-04](../../docs/P03-04-PLAN.md) проверен Astra до реализации. На дату приёмки A P03-04 ещё не был завершён, P03 составлял 60%; обязательный отдельный Astra PASS для B1 затем предшествовал B2.

## P03-04B1+B2: private quarantine, принят владельцем

[Контракт B2](../../docs/P03-04B2-CONTRACT.md): `src/files/upload-coordinator/index.ts` предоставляет `uploadReservedFile(pool, storage, operationalPolicy, command)` с обязательными trusted synthetic bounds, raw F proof и cooperative body factory. Registration COMMIT предшествует factory/первому next, dispatch COMMIT — единственному PUT; locks не держатся на IO. Storage проверяет полный GET HTTP200 без Content-Range и actual bytes/SHA-256. После IO повторно проверяются exact original GIVEN, owner, policy, сроки и поколение/lease; единственный binding означает только QUARANTINED. Replay после ожидания binding читает свежий DB clock.

Operator-only direct `src/files/upload-coordinator/reconcile.ts` делает bounded GET exact registered key/target, фиксирует fenced observations и держит физическую charge UNKNOWN/поздних PUT. 404 не доказывает отсутствие, recovery не пишет старый key, не публикует и не удаляет. Opaque probe issuer не экспортируется из feature barrels. В принятом B additive015 добавила attempts и immutable quarantine objects, точные FK/column ACL, не изменяя SQL014 или код A. Позднее C/D/E доработали runtime guards A/B на полной цепочке, без правок SQL014/015.

Итог: 767/767 тестов, 56 файлов, real PG+S3 включены без skipped; B1 52/B2 36 адресных. Migration proof15/149CHECK, workspace tsc/source-lint/build, dependency525/audit0 и secret/diff PASS. Astra B2 PASS закрывает 3 MUST FIX: full GET, replay clock после SELECT, rollback/audit-outbox fault matrix. Владелец принял B1+B2 22.11.2026, разрешил отдельный коммит и push, поручил завершить остальные части P03-04. B опубликован в `e44fae8`, [GitHub Actions 44960486563](https://github.com/Good-Eli/fixlevelup/actions/runs/44960486563) — success. В границах принятого B не было HTTP/DI, READY, scanner/EXIF, выдачи/DELETE/restore или реальных ПД; Q02/Q12/Q13/Q16 открыты. Рабочая dev DB не мигрировалась.

## P03-04C/D/E: технически завершено, internal synthetic scope

Поверх принятого `e44fae8` в рабочем дереве лежат модули `src/files/file-processing/`
(локальный decoder, структура изображения, protocol), `file-lifecycle/`
(публикация, processing registry/evidence, budget), `file-access/` (метаданные и
выдача потоком по тикетам), `file-privacy/` (retention, hold, delete claim и
deletion, broker), `file-restore/` (инвентарь, объекты, записи, rescrub) и
`file-ledger/` (кодек, verifier, PG-ledger). Плюс аддитивные миграции `016`
(`file_processing_access`) и `017` (`file_privacy_deletion`) и прямая зависимость
`sharp@0.35.5`. Контракт — [P03-04CDE](../../docs/P03-04CDE-CONTRACT.md).

Только внутренний F-путь: JPEG/PNG/WebP без анимации могут стать READY после двух реальных сканов и sanitization; PDF остаётся в карантине, видео/анимация не допускаются к READY. Выдача — по закрытому ticket с повторной проверкой на каждый chunk; после D freeze закрыты также A read/exact replay. Новые B/C записи разрешены только в исходной ACTIVE epoch 1; после restore epoch 2+ доступ и DELETE касаются лишь скопированных объектов под текущей властью. Отсутствующая runtime row сохраняет legacy B на полной схеме.

Три межсрезовых MUST закрыты; полный Astra A→E — PASS (22.11.2026), E — 876/876 без пропусков. P03 технически завершён на 80% (4 из 5); P03-05 не начинать. См. [актуальный статус P03-04 и evidence](../../docs/P03-04CDE-CONTRACT.md#6-current-status-and-evidence). C/D/E ещё не закоммичены. Нет HTTP/DI, signed URL, staff grants, customer intake, production или реальных ПД; Q02/Q12/Q13/Q16 открыты. Рабочая dev БД не мигрировалась.

## Поведение

- GET /health/live: 200 {status:ok}, процесс API жив, без зависимости от каналов.
- GET /health/ready: 200 {status:ok} только при успешной проверке runtime
  identity/privileges и совместимой foundation структуры. Иначе503 NOT_READY.
  Подключение ленивое, отсутствие БД не блокирует запуск/liveness.
- Один single-flight probe на запросы readiness, pool max2; connection/query/
  statement/lock timeout1000ms, без detached SQL после HTTP Promise.race.
  Shutdown останавливает новые probes, ждёт текущий, закрывает Prisma/pool.
- При включённом web auth доступны также [защищённые операции RBAC](../../docs/RBAC.md); Mini App self-service регистрируется только при настроенном Telegram exchange.
- JSON parser включается только вместе с web auth, strict и ограничен 4 KiB;
  входные body не сохраняются и не логируются.
- X-Powered-By отключён; health/errors имеют Cache-Control:no-store.
- Error response содержит только type/title/status/code и server-generated requestId.
- SafeLogger через Nest ConsoleLogger пишет только fixed event+role, без raw
  exception, stack, env, request path/body/headers и provider IDs. Неструктурированные
  framework messages подавляются; NEST_LOG_LEVEL намеренно не используется.
- Worker создаёт Nest application context и heartbeat раз в минуту. Раз в секунду
  проверяет readiness; только зарегистрированные handler event types допускаются
  к claim. Пустой production registry оставляет все события нетронутыми.
- OutboxStore использует отдельный pool max2 под runtime-role. Один SQL claim:
  FOR UPDATE SKIP LOCKED, due/expiry по clock_timestamp PostgreSQL, UUID owner,
  bigint generation и attempt_count увеличиваются при выдаче lease.
- Lease по умолчанию30s, без продления. Complete/retry требуют id+owner+generation
  и ещё не истёкшую lease; status остаётся PENDING до EXPANDED/FAILED. EXPANDED
  означает успешный technical handler, а не доставку внешнего сообщения.
- Максимум3 попытки, retry через1s/2s (общая задержка capped30s). Error code только
  HANDLER_FAILED/ATTEMPTS_EXHAUSTED, без exception text/payload. Истёкшая последняя
  попытка переводится в FAILED при следующем claim этого поддерживаемого типа.
- Shutdown останавливает polling/claims, abort signal передаётся текущему handler,
  ожидается текущая работа и закрываются оба DB pools. При остановке lease не
  завершается: истечение позволяет recovery. Общий deadline lifecycle ограничивает
  handler, игнорирующий отмену. Fencing защищает queue state; будущий handler обязан
  сам обеспечивать идемпотентность своего эффекта. Exactly-once send не обещается.
- SIGINT/SIGTERM вызывают app.close, очищают worker timer; повторный сигнал не
  начинает второй shutdown. Deadline ограничивает зависшее/отклонённое закрытие.

## Dependencies

Runtime: @nestjs/common/core/platform-express 12.5.1 — HTTP/DI framework;
reflect-metadata 0.2.2 и rxjs 7.8.2 — необходимые Nest peers.
Dev: @nestjs/testing 12.5.1, supertest 7.3.2, @types/supertest 7.2.1 — DI/HTTP tests;
внутренний @fixlevelup/tooling — strict TypeScript config.
@nestjs/config не нужен собственному небольшому technical config validator.
Prisma client/adapter7.10.1 и pg8.23.1 — существующие runtime deps;
CLI/Studio/React/Visx исключены из API runtime graph. Swagger/DTO libs,
Nest CLI и SWC/Jest не добавлены. Для internal synthetic файлов добавлены точные `@aws-sdk/client-s3@3.1172.0` и `sharp@0.35.5` (последний — в рабочем C/D/E).
Dependency lifecycle scripts остаются запрещёнными.

## Проверки и границы доказательств

Один Vitest runner: Oxc legacy decorators+metadata, отдельно tsc NodeNext/ESM.
Class-field semantics выровнены через useDefineForClassFields:false.
Tests проверяют DI, constructor/parameter metadata, health, ошибки/secret canaries,
config rejection, heartbeat cleanup и реальные compiled ESM entrypoints.
Команда test сначала собирает API, чтобы compiled tests не использовали старый dist.

На Windows child.kill(SIGTERM) завершает процесс принудительно. Поэтому тесты
shutdown генерируют сигнал внутри compiled child (process.emit); это проверяет
обработчик и lifecycle, но не доставку OS-сигнала. Реальный POSIX SIGTERM и Linux
runtime проверяются позднее. Никаких production shutdown endpoints не добавлено.
Readiness проверяет required columns/type/nullability, PK/CHECK definitions,
required indexes и subset runtime privileges без чтения _prisma_migrations.
Это НЕ полный drift/security audit: typmods/defaults, дополнительные объекты,
functions и вся история миграций не сравниваются. При включённом web auth probe
дополнительно проверяет наличие необходимых identity/auth-таблиц, столбцов,
основных ограничений/индексов и ACL; это не полная проверка всех SQL-выражений и
безопасности схемы. Exact catalog definitions привязаны к текущей PG18.7 и требуют
review при обновлении major/minor.

Integration tests требуют локальные dev/runtime secrets и работающую FixLevelUp
PostgreSQL55432. Они создают отдельную random p018b test DB из template0 с копией
technical migrations и test-only _prisma_migrations stub, проверяют200→503 при
CHECKtrue/недостающем INSERT/wrong-index-columns. Dev schema/grants не меняются.
Test DB сохраняются. Ошибочный пароль, зависший TCP handshake и pool shutdown проверяются без остановки Docker. Операции сотрудников, ролей и permissions описаны в [RBAC](../../docs/RBAC.md).
