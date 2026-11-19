# Prisma Foundation и P01-01.7A Technical Migrations

Private dev-only tooling. Prisma CLI 7.10.1 находится здесь, не в root/API
runtime. React/React DOM 19.3.1 и @types/react19.3.0 — исключительно peer
providers обязательной Prisma Studio-ветки. Studio не запускается.

## Адресное owner exception

prerelease-exceptions.json содержит единственные разрешённые exact upstream
исключения: девять @visx alpha и внутренний @prisma/engines-version build.
Это не общий allow prerelease; версии CLI/client/adapter остаются 7.10.1.
Engine build с префиксом8.1 не означает выбранную Prisma8RC. Полный граф
проверен по exact registry metadata/integrity, engines/peers/scripts/licenses.
Prisma preinstall и engines postinstall НЕ запускались, allowBuilds пуст.
Явный prisma generate — reviewed команда, не lifecycle hook.
Лицензии полного dev-графа включают также EPL-2.0/Unlicense и комбинации
MIT/ISC, кроме прежних MIT/Apache/BSD/LGPL/MPL/BlueOak/CC-BY/0BSD.
Это начальный inventory, не юридическое заключение или production SBOM.

## Команды из корня (PowerShell)

```powershell
$env:COREPACK_HOME = Join-Path $env:LOCALAPPDATA 'fixlevelup-tooling\corepack'
$env:COREPACK_ENABLE_AUTO_PIN = '0'
$env:COREPACK_DEFAULT_TO_LATEST = '0'
corepack pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies
corepack pnpm run db:generate
corepack pnpm run check
corepack pnpm run db:runtime-check
# Read-only proof: только существующая dev PostgreSQL FixLevelUp:
corepack pnpm run db:check
```

Schema prisma/schema.prisma содержит только технические AuditLog/OutboxEvent
в foundation schema; доменных моделей нет. P01-01.6 начинался с нулём models,
P01-01.7A добавил две reviewed SQL migrations.
Generation без credentials создаёт игнорируемый API src/generated/prisma,
moduleFormat esm, TS files/.js imports. Сборка tsc компилирует его в API dist.
Сгенерированные файлы имеют upstream ts-nocheck и исключены из ESLint;
авторский код и интеграция проверяются strict tsc/lint и compiled tests.
Повторная generation выполняется явно командами lint/typecheck/build,
не install hooks. CHECKPOINT_DISABLE/PRISMA_HIDE_UPDATE_MESSAGE и --no-hints
подавляют update/hint paths; Studio/dev DB server не вызываются.

## Изоляция API

API runtime: client/adapter-pg7.10.1, pg8.23.1; @types/pg8.23.1 dev only.
Адресный hoistPattern исключает Prisma tooling и React/Visx providers:
иначе optional peer Prisma CLI может разрешаться из API client даже без связи
в lock snapshot. Полный hoist:false обнаружил недостающий type-only dependency
в декларациях Nest; стандартное разрешение остальных пакетов сохранено.
Runtime audit проходит обязательные dependencies, установленные optional
packages и peers, а также проверяет imports скомпилированного API. CLI,
Studio, React/DOM и Visx в этих графах запрещены. Root/app entrypoints
не подключают proof к REST/worker: это отдельный технический executable.
Не копируйте монорепозиторный node_modules в production целиком; production
artifact должен содержать только API runtime graph. Контейнерный deploy позже.

## Read-only connection proof

check-connection читает только локальный игнорируемый dev-postgres/.env,
передаёт пароль child environment (не аргументы/логи). Target жёстко ограничен
127.0.0.1:55432/fixlevelup_dev, pool max2/timeout5s и session default read-only.
Выполняются только SELECT
identity/version и прежней p01_technical.persistence_probe. Ошибки фиксированные,
без URL/password/provider payload. Client отключается в finally.
Bootstrap dev superuser используется только в read-only proof и явном role/test
bootstrap. API/worker ещё не используют runtime credentials; DB readiness позже.

## P01-01.7A — Roles и технические миграции

- db:roles: одноразовое создание fixlevelup_migrator/fixlevelup_runtime с разными
  случайными256-bit passwords в локальном .env этого пакета (Git ignored).
  Повторное создание не ротирует/не меняет существующие роли молча.
- Обе роли: NO SUPERUSER/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS/INHERIT,
  memberships отсутствуют. Migrator владеет foundation и имеет DB CREATE только
  на FixLevelUp dev DB для schema DDL. Runtime не owner и не получает DB CREATE/TEMP.
- db:deploy: Prisma migrate deploy только к127.0.0.1:55432/fixlevelup_dev.
  Schema foundation; audit SELECT/INSERT, outbox SELECT/INSERT и column-limited
  UPDATE status/attempt_count. DELETE/TRUNCATE/DDL/migration history runtime запрещены.
- db:test-migrations: создаёт fresh/upgrade/shadow DB с уникальным p017a suffix.
  Fresh deploy, upgrade1→2 с данными, replay, history/schema diff, явный test-only
  ALTER drift+восстановление, catalog/CHECK/commit/rollback/privilege assertions.
  Shadow soft reset допустим ТОЛЬКО в отдельной созданной test shadow DB.
  Test DB сохраняются, не удаляются автоматически. Существующая dev DB не reset.

```powershell
corepack pnpm run db:roles       # один раз, только новая установка
corepack pnpm run db:deploy
corepack pnpm run db:test-migrations
```

Пароли не логируются/не передаются top-level CLI args. Prisma upstream может
передавать datasource своему engine внутренними args; не публикуйте process
command lines/DEBUG. Wrapper удаляет DEBUG/RUST_LOG и engine overrides, output
редактируется по secret. Локальный администратор/OS-admin всё равно доверенный.

Первый dev deploy обнаружил отсутствие DB CREATE у migrator на CREATE SCHEMA
IF NOT EXISTS. Транзакция откатила DDL; после узкого GRANT CREATE мигратору
неуспешная попытка отмечена migrate resolve --rolled-back, затем обе миграции
успешны. История попытки сохранена, reset/перезапись migration SQL не выполнялись.

db push/reset/studio не вызываются. Бизнес-таблиц, географии и worker обработки
outbox нет. Existing persistence data, чужие Docker resources и Git index/config
сохраняются. Реальный runtime-role API wiring и DB readiness — отдельный шаг.
