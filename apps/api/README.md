# Technical API/worker и P01-01.8B DB readiness

Технические процессы одного backend-пакета. Бизнес-модули, провайдеры,
обработка jobs/outbox ещё не реализованы. API использует Prisma/adapter-pg
для read-only readiness под отдельной runtime-role; worker пока без DB wiring.

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
технических переменных без secrets. API требует DB_PASSWORD runtime-role;
локальные credentials уже существуют в ignored database-tooling/.env.
Entrypoint не читает этот файл автоматически и не использует migrator/admin.
Оба entrypoint валидируют общий technical config. Worker не слушает порт,
хотя APP_HOST/APP_PORT пока входят в общий config contract.
Порт 0 разрешён исключительно для NODE_ENV=test. Foundation привязан к loopback;
внешняя публикация и reverse proxy относятся к следующим подэтапам.

## Поведение

- GET /health/live: 200 {status:ok}, процесс API жив, без зависимости от каналов.
- GET /health/ready: 200 {status:ok} только при успешной проверке runtime
  identity/privileges и совместимой foundation структуры. Иначе503 NOT_READY.
  Подключение ленивое, отсутствие БД не блокирует запуск/liveness.
- Один single-flight probe на запросы readiness, pool max2; connection/query/
  statement/lock timeout1000ms, без detached SQL после HTTP Promise.race.
  Shutdown останавливает новые probes, ждёт текущий, закрывает Prisma/pool.
- Другие маршруты: безопасный problem response, business endpoints отсутствуют.
- Body parser отключён; входные body не сохраняются/не логируются.
- X-Powered-By отключён; health/errors имеют Cache-Control:no-store.
- Error response содержит только type/title/status/code и server-generated requestId.
- SafeLogger через Nest ConsoleLogger пишет только fixed event+role, без raw
  exception, stack, env, request path/body/headers и provider IDs. Неструктурированные
  framework messages подавляются; NEST_LOG_LEVEL намеренно не используется.
- Worker создаёт настоящий Nest application context и heartbeat раз в минуту.
  Это поддержание процесса, а не имитация выполненных jobs/notifications.
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
functions и вся история миграций не сравниваются. Exact catalog definitions
привязаны к текущей PG18.7 и требуют review при обновлении major/minor.

Integration tests требуют локальные dev/runtime secrets и работающую FixLevelUp
PostgreSQL55432. Они создают отдельную random p018b test DB из template0 с копией
technical migrations и test-only _prisma_migrations stub, проверяют200→503 при
CHECKtrue/недостающем INSERT/wrong-index-columns. Dev schema/grants не меняются.
Test DB сохраняются. Ошибочный пароль, зависший TCPhandshake и pool shutdown
проверяются без остановки Docker. Никаких write business endpoints здесь нет.
