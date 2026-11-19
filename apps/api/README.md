# P01-01.2 — Technical API and worker

Технические процессы одного backend-пакета. Бизнес-модули, провайдеры,
PostgreSQL/Prisma, обработка jobs и outbox ещё не реализованы.

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
corepack pnpm --filter @fixlevelup/api start
# В отдельном процессе с теми же техническими env:
corepack pnpm --filter @fixlevelup/api start:worker
```

Entrypoints не загружают .env автоматически. .env.example — перечень
технических переменных; реальных токенов и БД credentials пока нет.
Оба entrypoint валидируют общий technical config. Worker не слушает порт,
хотя APP_HOST/APP_PORT пока входят в общий config contract.
Порт 0 разрешён исключительно для NODE_ENV=test. Foundation привязан к loopback;
внешняя публикация и reverse proxy относятся к следующим подэтапам.

## Поведение

- GET /health/live: 200 {status:ok}, процесс API жив, без зависимости от каналов.
- GET /health/ready: 503 NOT_READY. Реальная DB/schema readiness будет позднее;
  текущая реализация не заявляет БД готовой и не подключается к ней.
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
Prisma, Swagger/DTO libs, Nest CLI, SWC/Jest и provider SDK не добавлены.
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
Изолированные fixtures не являются работой мессенджеров/БД/бизнес-модулей.
