# P01-01.11B — isolated local Linux PostgreSQL/S3 integration

Отдельный local Linux stand, не remote CI/deploy. Приложения и существующие
localhost guards не переписываются. Все три контейнера разделяют network namespace
нового PostgreSQL; сервисы слушают только127.0.0.1 внутри namespace. Новая сеть
internal:true, host ports отсутствуют; dev containers/networks/volumes не подключены.

Pinned Node24.22.3+PG18.7+Garage2.5.0 images, exact OpenSSL prerequisites как P0111A.
Runner source-only image не получает host .env/data/node_modules/Docker socket.
Host wrapper/bootstrap явно используют локальный Docker Desktop Linux named-pipe
endpoint (npipe:////./pipe/dockerDesktopLinuxEngine); remote context не выбирается.
Отдельный .env этого каталога содержит только вновь сгенерированные test secrets,
Git ignored; реальные dev credentials не копируются.

## Воспроизведение из корня

```powershell
node infra/linux-integration/init.mjs
# Wrapper pin project и все interpolation values из нового локального .env.
# Прямой --env-file недостаточен: shell env имеет более высокий приоритет.
node infra/linux-integration/compose.mjs validate
node infra/linux-integration/compose.mjs build
node infra/linux-integration/compose.mjs services
node infra/linux-integration/bootstrap-s3.mjs
node infra/linux-integration/compose.mjs run
# Redacted evidence после exit0:
docker --host npipe:////./pipe/dockerDesktopLinuxEngine cp fixlevelup-linux-integration-runner:/workspace/node_modules/.cache/linux-integration node_modules/.cache/linux-integration-evidence
```

Не выводить compose config без --quiet: содержит synthetic secrets. Не публиковать
raw inspect Env/process command lines. Локальный OS/Docker administrator доверенный.
init отказывается overwrite credentials, новый стенд должен создаваться на новых
volumes. Повтор runner отказывается использовать уже bootstrap-нутые env/roles.
Никакой down-v/prune/drop/clean; данные/test DB/container сохраняются для evidence.

## Что выполняет runner

- Linux x64 Node24.22.3/PG18.7 identity, новые credentials только внутри image.
- Frozen offline install без lifecycle scripts; общий lock hash неизменен.
- Synthetic persistence marker в НОВОЙ instance; migration/runtime roles через
  принятый bootstrap, все3 reviewed migrations через реальный Prisma deploy.
- Fresh/upgrade/replay/drift migrations, FK/CHECK/EXCLUDE/same-city/locks proofs.
- Полный pnpm check: lint, typecheck,3builds,ВСЕ Vitest включая реальные PG/S3.
- Runtime isolation и read-only compiled Prisma/adapter connection proof.
- Redacted evidence и проверка empty operational audit/outbox, marker preserved.

Историческое имя БД fixlevelup_dev/порты55432/3900 совпадают с dev контуром только
внутри отдельного namespace; это физически НОВЫЕ PG/S3 volumes. Сеть internal
не имеет egress. Build preparation с сетью выполняется ДО service runtime.

## Фактический результат 20.11.2026

Runner image ID sha256:a0acf2cb131072ba6fa9f36785874f9c95af1e099dadebde45721d711066284b,
linux/amd64 Node24.22.3, exit0. Полный check:261/261tests,16/16files,
lint/typecheck/3builds PASS. Fresh/upgrade/replay/drift PASS,13CHECK/14privilege
отказов; synthetic26SQLSTATE assertions и global technician lock PASS.
Runtime graph120packages isolation и read-only Prisma proof PASS.
Operational audit/outbox0/0,marker1,other busy PGclients0,lock неизменен.
Terminal result.json overallStatus=passed,failedStage=null скопирован в ignored
node_modules/.cache/linux-integration-evidence. Все test DB/volumes сохранены.

Дополнительный restart proof только isolated Garage:
```powershell
node infra/linux-integration/persistence.mjs write
docker --host npipe:////./pipe/dockerDesktopLinuxEngine restart fixlevelup-linux-integration-garage
node infra/linux-integration/compose.mjs services
node infra/linux-integration/persistence.mjs verify
```
Фактически write/verify bytes/SHA256/metadata прошли. Скрипт создаёт temporary
probe container без mounts в namespace isolated PG, ключи передаёт environment,
не args/output; existing marker не перезаписывается. Только этот test probe
контейнер автоматически удаляется (--rm), DB/Garage/resources не удаляются.

## Не заявляется

Remote CI, browser/Playwright launch, image vulnerability scan, production deploy,
Linux backup/restore и OS signal shutdown при действующем in-flight business job.
POSIX signal proof без services выполнен отдельно P0111A. Эти ограничения не
подменяются успешными Vitest или localhost readiness.
