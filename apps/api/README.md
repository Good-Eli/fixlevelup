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
Создание других администраторов сейчас не реализовано. Привилегированный SQL-доступ
всё равно позволяет обходить приложение; когда добавится управление сотрудниками,
необходимо отдельно пересмотреть привилегии, аудит и протокол блокировок.

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

## Поведение

- GET /health/live: 200 {status:ok}, процесс API жив, без зависимости от каналов.
- GET /health/ready: 200 {status:ok} только при успешной проверке runtime
  identity/privileges и совместимой foundation структуры. Иначе503 NOT_READY.
  Подключение ленивое, отсутствие БД не блокирует запуск/liveness.
- Один single-flight probe на запросы readiness, pool max2; connection/query/
  statement/lock timeout1000ms, без detached SQL после HTTP Promise.race.
  Shutdown останавливает новые probes, ждёт текущий, закрывает Prisma/pool.
- При включённом web auth доступны его API-маршруты; business endpoints отсутствуют.
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
Nest CLI, SWC/Jest и provider SDK не добавлены.
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
Test DB сохраняются. Ошибочный пароль, зависший TCPhandshake и pool shutdown
проверяются без остановки Docker. Никаких write business endpoints здесь нет.
