# Prisma Foundation и технические миграции audit/outbox

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
bootstrap. API и worker используют только fixlevelup_runtime credentials.

## P01-01.7A — Roles и технические миграции

- db:roles: одноразовое создание fixlevelup_migrator/fixlevelup_runtime с разными
  случайными256-bit passwords в локальном .env этого пакета (Git ignored).
  Повторное создание не ротирует/не меняет существующие роли молча.
- Обе роли: NO SUPERUSER/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS/INHERIT,
  memberships отсутствуют. Migrator владеет foundation и имеет DB CREATE только
  на FixLevelUp dev DB для schema DDL. Runtime не owner и не получает DB CREATE/TEMP.
- db:deploy: Prisma migrate deploy только к127.0.0.1:55432/fixlevelup_dev.
  Schema foundation; audit SELECT/INSERT, outbox SELECT/INSERT и column-limited
  UPDATE status/attempt_count и lease_owner/lease_generation/lease_expires_at/
  next_attempt_at/last_error_code. DELETE/TRUNCATE/DDL/migration history runtime запрещены.
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

db push/reset/studio не вызываются. Бизнес-таблиц и географии нет. Existing
persistence data, чужие Docker resources и Git index/config сохраняются.

## P01-01.9A — Claim, lease и fencing

Третья reviewed migration добавляет lease owner(UUID)/generation(bigint)/expiry,
next_attempt_at, safe error code, CHECK инварианты и due index. Прежние migration
SQL не меняются. Upgrade proofs проверяют пути1→latest и2→3 с сохранением данных,
повторный deploy и drift. Runtime grants по-прежнему column-level.

Outbox integration tests в API создают отдельную fixlevelup_p019a_worker_<suffix>
БД в том же FixLevelUp container, оставляют её для evidence и закрывают clients.
Синтетические handlers/command effects существуют только в tests. Production
registry пуст: claim unsupported событий и фиктивный EXPANDED запрещены.
После изменения схемы выполните db:deploy перед запуском API/worker; старый
readiness contract намеренно несовместим с новой структурой до обновления кода.

Audit 20.11.2026 выявил HIGH GHSA-7589-6fvf-x4pw в прежнем effect3.20.0
цепочки prisma7.10.1 → @prisma/config7.10.1. Владелец отдельно согласовал
адресный override @prisma/config@7.10.1>effect:3.22.1. Prisma CLI/client/adapter
остаются7.10.1; остальные package versions/права/scripts policy сохранены.
Это dev-only CLI graph; API runtime isolation audit не включает эту ветку.
У effect3.22.1 MIT, нет install hooks, registry tarball SHA512 совпадает с lock.
После замены обязательны frozen/offline install, полный audit, generation,
migration proofs, quality gate и runtime isolation.
Источник: https://github.com/advisories/GHSA-7589-6fvf-x4pw

## P03-03 — миграция 013 и инвентарь ограничений

Подэтап **принят владельцем 21.11.2026 в 21:34** в synthetic внутреннем scope
после адресной доработки трёх замечаний независимого ревью; принятый срез
коммитится отдельным локальным коммитом, SHA не заявлен.
Контракт — [P03-03-CONTRACT](../../docs/P03-03-CONTRACT.md).

- Миграция `20261121000400_settings_legal_references` (`013`) добавляет таблицы
  настроек/справочников/контента/документов/согласий и колонки настроек компании;
  проверки fresh, `012`→`013`, replay и drift выполнены до приёмки.
- `test-migrations.mjs` держит **жёсткий список** имён миграций и **точный перечень
  CHECK** с проверкой на равенство. Добавление `013` без обновления обоих списков
  ломает `db:test-migrations` независимо от корректности схемы, поэтому инвентарь
  расширяется вместе с миграцией, а не после.
- Независимый от DDL инвентарь ограничений оформляется отдельным модулем в стиле
  `test-area-migration.mjs`/`test-geo-access-migration.mjs`: ослабленный или
  удалённый guard обязан падать.
- Runtime получает только используемые column-level `SELECT`/`INSERT`/`UPDATE`;
  без `DELETE`/`TRUNCATE`/DDL, без `PUBLIC`-доступа и без `SECURITY DEFINER`
  делегирования. Отсутствие seed и автоматических грантов проверяется отдельно.
- Фактические результаты: **13 миграций и 121 CHECK**, fresh/`012`→`013`/replay/drift — PASS; SHA-256 итогового SQL `013` — `54fda83b0eff7055a0b1dbac46d9df64910666eb984bd5df316a30c9d81cfbf9`. Полный Vitest — 622/622 в 48 файлах (39 configuration + 36 legal). Миграция не развёрнута в рабочей БД.

## P03-04A — migration014, принятый no-byte reservation

`20261121000500_file_upload_reservations` добавляет только `file_upload_intents` и уникальный consent-basis index; 013 данные/ACL не переписываются. Только RESERVED/CANCELLED, actual owner FKs, immutable policy/basis, RC/live/current-consent/post-lock expiry/quota guards и narrow runtime columns. Нет files/S3/IO/READY. [План](../../docs/P03-04-PLAN.md) проверен Astra; срез A принят владельцем 21.11.2026, весь P03-04 не завершён (прогресс 60%).

Независимый `test-file-reservations-migration.mjs` проверяет 013→014/fresh/replay/drift, exact inventories/ACL и негативные guards. Старый013 proof ограничен своей capped history, final014 proof сравнивает актуальную Prisma schema и миграции. Migration gate выполняется только на случайных изолированных БД, не `db:deploy` рабочей dev БД. Итог: migration proof PASS — **14 миграций/138 CHECK**, fresh/013→014/replay/drift/ACL; финальный полный PostgreSQL Vitest — **679/679 в 50 файлах** (40 unit + 17 PG); SQL014 SHA-256 `2ec24c3365b4681859cd11d4fc7dd031fc487d410ff695692f4a2ec650bb4377`. Предыдущий gate 670/670 сохранён как исторический. Schema во время адресных исправлений не менялась. Принятый срез A коммитится отдельным локальным коммитом (создаёт root), SHA не заявлен; весь P03-04 не завершён.
