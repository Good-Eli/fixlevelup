# P05 lab runner (task-1) — private PostgreSQL + runner for the P05 gateway

Воспроизводимый локальный стенд для focused-проверок критического шлюза P05 и
измерений S3/024. Рабочий кластер (dev-postgres на хосте `127.0.0.1:55432`), его
том, роли и БД **не используются и не видны** из стенда: PostgreSQL-контейнер
запускается с `--network none`, runner подключается к нему через
`--network container:<pg>`, ни один порт на хост не публикуется. Внутри нет
Docker socket, внешней сети и смонтированных host `.env`.

## Ресурсы (только собственные, метки `dsh.owner=pg-lab`)

| Роль | Имя | Как создаётся |
|---|---|---|
| PostgreSQL 18.7 | `p05lab-pg-<runId>` | `postgres:18.7-bookworm@sha256:1757c628…` (тот же digest, что в `infra/dev-postgres/compose.yaml`), `--network none`, `--tmpfs /var/lib/postgresql:rw,size=2g`, без volumes |
| Runner (Node 24.22.3) | `p05lab-runner-<runId>` | `fixlevelup-p05-lab:local` (`Dockerfile`), `--network container:<pg>` |

Удалять адресно по этим именам; `docker rm -v`, `volume prune`, `system prune`
не применять (томов нет). `lab.mjs down` останавливает и удаляет ТОЛЬКО свои
контейнеры текущего runId.

## Два образа — два разных контура (не смешивать)

1. **`fixlevelup-p05-lab:local` — gateway 023 (frozen).** Собирается НЕ из живого
   дерева, а из `git archive f3cc8a0` + ровно три reviewed overlay-файла
   (`snapshot.mjs`). Незавершённый 024 и WIP-правки в него попасть не могут:
   `snapshot.mjs` собирает `p05-profile-catalog.ts` детерминированно из
   `git show f3cc8a0:…` + три точных патча (каждый обязан встретиться ровно один
   раз) и падает, если в результате появились `P05Profile`/`S3_HEAD`/`'S3'`.
   Цепочка миграций образа обязана заканчиваться на 023 — это проверяется.
2. **`fixlevelup-p05-lab:s3` — текущее дерево (S3/024).** Собирается из
   снапшота tracked + неигнорируемых untracked файлов (без `.env`, `node_modules`,
   `dist`, `test-results`, dumps — двойной фильтр). До передачи runtime-env
   выполняется `corepack pnpm run build` (генерация Prisma, контракты, API/Web/Mini App)
   без сети и без БД. Ошибка сборки останавливает прогон: Vitest не тестирует
   отсутствующие или случайно сохранённые локальные артефакты.

## Команды

```powershell
node infra/p05-lab/lab.mjs freeze              # экспорт frozen 023-дерева (git archive + overlay)
node infra/p05-lab/lab.mjs build [--fresh]     # собрать gateway-образ (--fresh = пересобрать снапшот)
node infra/p05-lab/lab.mjs up [--fresh]        # поднять PG + runner, провижинить/аттестовать кластер
node infra/p05-lab/lab.mjs status              # имена контейнеров + сводка БД (без секретов)
node infra/p05-lab/lab.mjs down                # stop+rm ТОЛЬКО своих контейнеров

# focused 023-прогон (exit code vitest пробрасывается)
node infra/p05-lab/lab.mjs run apps/api/tests/form-session-http.test.ts

# произвольная команда внутри 023-образа
node infra/p05-lab/lab.mjs exec sh -lc 'cd /workspace && corepack pnpm vitest run apps/api/tests/query-timeout-regression.test.ts'

# S3/024: снапшот текущего дерева + отдельный образ
node infra/p05-lab/lab.mjs s3image [--rebuild]

# S3/024: disposable БД + команда; по умолчанию `corepack pnpm exec vitest run <args>`
node infra/p05-lab/lab.mjs s3test -- apps/api/tests/p05-role-bridge.test.ts
node infra/p05-lab/lab.mjs s3test --cmd -- sh -lc '…полная командная строка…'

# S3/024: произвольная команда в эфемерном контейнере, БД создаёт/дропает сам вызывающий
node infra/p05-lab/lab.mjs s3run -- sh -lc '…'

# изолированные ledger + trust floor (порты 55433/55434 внутри того же netns)
node infra/p05-lab/lab.mjs ledger up|down|status
```

`s3test` создаёт новую `fixlevelup_p05_s3tlab_<hex>` (owner `fixlevelup_migrator`,
001…024), выставляет `FIXLEVELUP_LAB_DATABASE`/`_OID`, гоняет команду и дропает
именно эту БД по OID при любом exit code. Контейнер `--rm`.

### Opt-in флаги (`s3test` и `engine`)

Ни один reviewed-гейт не включается неявно: нужен явный флаг, и он сначала
проверяет, что соответствующий сервис реально поднят (иначе падение ДО старта
контейнеров, а не тихий `skip`).

| Флаг | Выставляет | Требует |
| --- | --- | --- |
| `--s3` | `FIXLEVELUP_STORAGE_S3_TESTS=1` | `garage up` |
| `--privacy` | `FIXLEVELUP_FILE_PRIVACY_TESTS=1`, `FIXLEVELUP_FILE_PROCESSING_TESTS=1` | `garage up` |
| `--ledger` | `FIXLEVELUP_ISOLATED_FILE_LEDGER_TESTS=1` | `ledger up` |
| `--restore` | `FIXLEVELUP_FILE_RESTORE_TESTS=1`, `FIXLEVELUP_BOOTSTRAP_ISOLATED_DB_TESTS=1` | `ledger up` |
| `--old-binary` | `FIXLEVELUP_P05_OLD_ARCHIVE`, `…_SHA256` | — |

`--old-binary` экспортирует reviewed исторический коммит
`7a60d4c5a84adeb2f6cbec6a0eb1b8723e104a62` через `git archive --format=tar`
(живой `.git` в контейнер НЕ монтируется, worktree/branch не переключаются) в
ignored-кэш стенда, монтирует tarball `--readonly` как `/p05-old-binary.tar` и
передаёт тесту полный SHA-256 ровно тех байт, которые он прочитает.

```powershell
# Workspace-регрессия на PostgreSQL/Garage/ledger; engine suites — отдельными прогонами.
node infra/p05-lab/lab.mjs s3test --old-binary --privacy --ledger --s3 --restore -- --cmd env -u FIXLEVELUP_FILE_PROCESSING_TESTS corepack pnpm exec vitest run --maxWorkers 1 --exclude apps/api/tests/p05-attachment-http.test.ts

# Один реальный PNG на ticket. Не объединять в общий engine-прогон.
node infra/p05-lab/lab.mjs engine -- apps/api/tests/file-lifecycle-s3.test.ts
node infra/p05-lab/lab.mjs engine -- apps/api/tests/p05-ready-attach-live.test.ts -t "admits exactly the published READY file"
node infra/p05-lab/lab.mjs engine -- apps/api/tests/p05-attachment-http.test.ts -t "creates the real request"
node infra/p05-lab/lab.mjs engine -- apps/api/tests/p05-attachment-http.test.ts -t "refuses the HTTP create"
```

### Независимые инстансы стенда

`FIXLEVELUP_LAB_INSTANCE=<имя>` даёт отдельную пару контейнеров PG+runner, свой
state и env при общих кэшах (образы, frozen-дерево, lock'и). Это нужно сюитам с
эксклюзивным guard'ом кластера (например, `db:test-migrations`: любой чужой
backend — отказ), чтобы они не конфликтовали с параллельными прогонами:

```powershell
$env:FIXLEVELUP_LAB_INSTANCE='history'
node infra/p05-lab/lab.mjs up --image=s3      # 024-кластер для этого инстанса
node infra/p05-lab/lab.mjs s3run -- <команда>
```

## Внутриконтейнерные утилиты

- `makedb.mjs` — `node infra/p05-lab/makedb.mjs` (001…024 + pinned history),
  `… empty` (пустая disposable БД под Prisma shadow), `… drop <oid>` (адресный
  drop с проверкой имени и OID).
- `containerenv.mjs` — **явно помеченный lab-only workaround**: пишет
  синтетические `packages/database-tooling/.env` и `infra/dev-postgres/.env`
  ТОЛЬКО в writable layer одноразового контейнера (0600, те же lab-креды,
  которых нет ни в образе, ни в git). Нужен единственному негейтованному
  читателю `.env` в тестах (`form-session-http.test.ts`); правильное
  исправление — гейт на lab-флаг в основном дереве (owner: lead).
- `s3/measure.ts` — измерение fingerprint'ов 024 (`readS3Metadata`,
  `measureSettingsManagement`, `measureCatalogManagement`, `ready`); печатает
  только хеши/booleans/stage ошибки. Компилируется отдельным tsc-проектом,
  чтобы WIP-ошибки в несвязанных файлах не блокировали измерение.
- `/opt/p05-lab/bin/{psql,pg_dump,pg_restore,garage}` + `/opt/p05-lab/lib` —
  pinned клиентские утилиты в S3-образе, извлечённые из ТЕХ ЖЕ pinned-образов
  (`postgres:18.7-bookworm@sha256:1757c628…`, `dxflrs/garage:v2.5.0@sha256:677e…`).
  Digest'ы совпадают с reviewed `tool-digests.txt`: `psql b72cd113…`,
  `pg_dump 49ff3d2b…`, `pg_restore ab7f6e74…`, `garage 2ff66728…`. Нужны
  reviewed lab-ветке `infra/file-restore/lab-resources.mjs`, которая обращается
  к абсолютным путям. Per-run `garage-client.toml` и `garage-node.txt`
  (RPC-секрет и node id текущего прогона) пишет `containerenv.mjs` при старте
  контейнера — в образ они не запекаются.

## Изолированный Garage (S3) в том же netns

Разрешён владельцем 25.11.2026. Reviewed-образ `dxflrs/garage:v2.5.0` (тот же
digest, что в `infra/dev-s3/compose.yaml`), reviewed `infra/dev-s3/garage.toml`
монтируется read-only, данные на tmpfs 512m, **никаких томов и host-портов**,
dev-контейнер и его данные не затрагиваются. Garage входит в тот же private
netns (`--network container:<pg>`), поэтому слушает loopback 3900/3901 внутри
namespace, и runner видит его как `http://127.0.0.1:3900` — ровно тот endpoint,
который пинует reviewed storage config.

```powershell
node infra/p05-lab/lab.mjs garage up       # запуск + bootstrap (bucket + RW/RO ключи)
node infra/p05-lab/lab.mjs garage status
node infra/p05-lab/lab.mjs garage down     # адресно только этот контейнер
```

Bootstrap создаёт только bucket `fixlevelup-dev-private` (имя задано кодом) и две
новые синтетические пары ключей RW/RO; значения попадают только в ignored
env-файл стенда и в `infra/dev-s3/.env` **внутри одноразового контейнера**.
Layout не меняется: `--single-node` уже применяет валидный single-node layout.

## Изолированные ledger + trust floor (P03-04 D)

Нужны reviewed file-restore/file-ledger сюитам. По решению владельца 25.11.2026
поднимаются **без исторических томов**: два одноразовых контейнера
`postgres:18.7-bookworm@sha256:1757c628…` (тот же pinned digest, что в
`infra/file-ledger/compose.yaml`) с данными на `--tmpfs`, без host-портов, в том
же private netns, поэтому внутри namespace они слушают loopback
**55433** (ledger) и **55434** (floor) — ровно те endpoint'ы, которые пинуют
reviewed-фикстуры. Reviewed `infra/file-ledger/*.sql` применяются байт-в-байт
(`ledger.sql` → `writer-roles.sql` → `ledger-writers.sql`; `floor.sql`), секреты
передаются через `\getenv`; `fsync`, `synchronous_commit`, `full_page_writes`
включены.

```powershell
node infra/p05-lab/lab.mjs ledger up       # запуск + reviewed SQL
node infra/p05-lab/lab.mjs ledger status
node infra/p05-lab/lab.mjs ledger down     # адресно только эти два контейнера
```

Восемь синтетических 64-hex паролей генерируются на прогон и живут только в
ignored env-файле стенда и в `infra/file-ledger/.env` **внутри одноразового
контейнера** (0600). Исторические тома `fixlevelup-test-file-ledger-data` /
`-floor-data` не используются и не трогаются; checked-in compose не запускается.

## Reviewed engine bridge (полный C pipeline)

`infra/file-processing/p05-lab-engine-host.mjs` (host, единственное место с Docker
API) + `p05-lab-engine-client.mjs` (внутри тестового контейнера) — reviewed
разделение: обмен только одноразовыми ticketed JSON-файлами через общий каталог,
runner **не получает** Docker socket, контроллер не получает DB-креды, а сам
launcher стартует engine-контейнеры с `--network none`, `--read-only`,
`--cap-drop ALL`, non-root uid. Обёртка:

```powershell
node infra/p05-lab/lab.mjs engine -- apps/api/tests/file-lifecycle-s3.test.ts
```

`engine` требует поднятого `garage up`, сам поднимает host-контроллер, монтирует
exchange-каталог в контейнер по reviewed абсолютному пути, выставляет четыре
opt-in флага (`SYNTHETIC_ORCHESTRATOR`, `BOOTSTRAP_ISOLATED_DB_TESTS`,
`STORAGE_S3_TESTS`, `FILE_PROCESSING_TESTS`) + `FIXLEVELUP_LAB_ENGINE_TICKET` и
`FIXLEVELUP_FILE_PROCESSING_FIXTURE`, после прогона удаляет ровно те
engine-контейнеры, которые создал контроллер (по именам из его вывода), и
exchange-каталог.

Три свойства контракта reviewed host-скрипта, которые обёртка обязана соблюдать
(каждое было отдельным падением, поэтому зафиксировано здесь):

1. `FIXLEVELUP_LAB_ENGINE_EXCHANGE` — **родитель** `…/p05-engine-jobs`
   (host проверяет basename), а не каталог тикета;
2. каталог тикета создаёт **сам host** (`mkdir(join(owner, ticket))`, без
   `recursive`) — обёртка не должна создавать его заранее (иначе `EEXIST`);
3. ожидание `ENGINE_READY` — **асинхронное**: `stdout` наполняется
   stream-колбэком, поэтому синхронный `sleep`-цикл не даёт ему выполниться и
   гарантированно упирается в таймаут. `stderr` контроллера пробрасывается, а не
   глушится.

После прогона очищается только `join(parent, ticket)`; общий родительский каталог
и чужие тикеты не трогаются.

## Синтетические креды

`lab.mjs` генерирует 64-hex пароли в памяти и пишет их только в ignored
`node_modules/.cache/p05-lab/<runId>/env` (0600). В контейнеры они попадают
через `--env-file`, не через argv; в git, образ и отчёты не попадают; пароли не
печатаются.

## Что провижинится (кластер внутри private netns, loopback 127.0.0.1:55432)

- `cluster_name = fixlevelup_p05s4_lab_<runId>` (regex, который проверяют
  `p05-lab-target.ts`, `admission-fixture.ts`, `lab-resources.mjs`),
  `server_version_num = 180007`, `fsync=on`, `synchronous_commit=on`;
- роли `fixlevelup_migrator`, `fixlevelup_runtime` и scoped
  `fixlevelup_lab_orchestrator` (LOGIN CREATEDB NOINHERIT, MEMBER of migrator);
- application DB `fixlevelup_p05_s2lab` (owner migrator) с цепочкой 001…023 и
  pinned `_prisma_migrations` (checksum = sha256 LF-нормализованного SQL);
- control DB `fixlevelup_p05_control_<12hex>` + роль
  `fixlevelup_p05_launcher_<12hex>` с узкими грантами (USAGE, SELECT/INSERT,
  UPDATE(state, consumed_at)); CONNECT для runtime/migrator не выдаётся;
- базы `fixlevelup_dev` в кластере нет и не создаётся.

`up` идемпотентен: сначала `attest.mjs` (read-only), и только если аттестация не
прошла — `provision.mjs` (все CREATE с reuse-guard, повторная провижининг
существующего кластера невозможен).

## Ограничения

- Порт на хост не публикуется by design; psql с хоста невозможен — только через
  `lab.mjs` (`exec`/`s3run`) или `psql` внутри контейнера.
- Образ 023 не пересобирается от правок рабочего дерева: нужен `build --fresh`
  (пересборка frozen-снапшота). S3-образ собирается из текущего дерева.
- Suite-ы, которым нужен Docker API (file-processing launcher, ClamAV/Sharp,
  S3/Garage), этим стендом не покрываются; отсутствие PASS по ним не выдаётся
  за PASS. Исключение — reviewed engine-мост (`engine`), где Docker API остаётся
  только у host-контроллера, а runner получает лишь одноразовый ticket.
- Ledger/floor — это **не** их исторические тома: данные на tmpfs, состояние
  живёт только внутри контейнера; после `ledger down` всё исчезает, и это
  ожидаемо (каждый прогон начинает с reviewed-схемы с нуля).
- Всё, что стенд создал, живёт в контейнерах на tmpfs и исчезает с ними;
  результаты и хеши — в отчётах, логи — в ignored `node_modules/.cache/p05-lab/`.
