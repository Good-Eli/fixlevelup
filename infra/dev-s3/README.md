# P01-01.10A — локальный dev S3 Garage

Закрытый synthetic-only single-node Garage2.5.0, AGPLv3. Исходники сервера
не модифицируются. Это dev implementation, не выбор production provider и не HA.

Образ dxflrs/garage:v2.5.0 закреплён OCI index digest:
`sha256:677e5b758e4425a325b811c425c026bf35a4bf42f7ddbaa773de3f4fd779a5a5`.
Платформа linux/amd64; platform manifest digest:
`sha256:23b16d34e0348d9aca9b960a7429a7e6d494974b5288bfb8f6c3ab856895f71e`.

## Запуск из корня

```powershell
$env:COREPACK_HOME = Join-Path $env:LOCALAPPDATA 'fixlevelup-tooling\corepack'
$env:COREPACK_ENABLE_AUTO_PIN = '0'
$env:COREPACK_DEFAULT_TO_LATEST = '0'
corepack pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies
corepack pnpm run s3:init
# Docker Desktop Linux Engine должен работать; чужие ресурсы не менять.
docker compose -f infra/dev-s3/compose.yaml config --quiet
docker compose -f infra/dev-s3/compose.yaml up -d --wait
corepack pnpm run s3:bootstrap
corepack pnpm run s3:test
```

init сохраняет уже существующий .env, при первом запуске генерирует отдельные
случайные RPC/access secrets. .env игнорируется Git. Не запускайте обычный
`compose config` без --quiet: развёрнутый вывод содержит RPC secret.
Bootstrap не печатает аргументы/вывод CLI: импорт ключа требует secret в
внутренних Docker CLI args, доступных доверенному OS/Docker administrator.
Не публикуйте process command lines, raw inspect Env, DEBUG или подписанные URLs.

## Ресурсы и доступ

- Compose/container: fixlevelup-dev-s3; сеть fixlevelup-dev-s3-net.
- Volumes: fixlevelup-dev-s3-meta и fixlevelup-dev-s3-data.
- S3 endpoint http://127.0.0.1:3900, path-style, region garage.
- Приватный bucket fixlevelup-dev-private, website endpoint отключён.
- RPC3901/admin3903 слушают только container loopback и не опубликованы.
- Healthcheck /garage status, restart unless-stopped, SQLite metadata,
  metadata_fsync/data_fsync включены; данные/метаданные в отдельных volumes.
- Рабочий ключ имеет read/write только этого bucket, без owner/create-bucket.
  Отдельный read-only key позволяет проверить отказ записи. Ключи не в API/web.
- HTTP допустим только на локальном loopback dev; production требует TLS.

## Управление и persistence proof

```powershell
docker compose -f infra/dev-s3/compose.yaml ps
docker exec fixlevelup-dev-s3 /garage status
node packages/storage-tooling/scripts/persistence.mjs write
docker compose -f infra/dev-s3/compose.yaml restart garage
docker compose -f infra/dev-s3/compose.yaml up -d --wait
node packages/storage-tooling/scripts/persistence.mjs verify
# Остановка без удаления ресурсов/данных:
docker compose -f infra/dev-s3/compose.yaml stop
# Возврат:
docker compose -f infra/dev-s3/compose.yaml start --wait
```

Не выполнять down -v, volume rm или Docker prune. Synthetic test objects
сохраняются для evidence; deletion test удаляет только свой уникальный объект.
Persistence evidence хранится в ignored node_modules/.cache, без credentials.
Backup/restore БД+objects — отдельный подэтап, restart не заменяет restore drill.

## Проверяемый S3 subset

PUT/HEAD/GET bytes+SHA256+metadata, ListObjectsV2 pagination, anonymous и wrong-key
403, read-only PUT403, CreateBucket403, missing key404, delete своего fixture,
SigV4 presigned GET, tampering403 и expiry400 InvalidRequest/Date is too old.
Последнее — фактический протокол Garage2.5.0; AWS status не навязывается серверу.
ETag не используется как универсальный checksum. Клиенты имеют bounded timeouts,
maxAttempts1, явные credentials (без default provider chain).

Garage не реализует AWS bucket policies/ACL, versioning и ObjectLock. Приватность
обеспечивается per-key/per-bucket grants; эти отсутствующие функции не заявляются.
Нет upload API, сканера/карантина, реальных файлов/ПД, frontend или production deploy.

Источники (tagged v2.5.0):
- https://raw.githubusercontent.com/deuxfleurs-org/garage/v2.5.0/LICENSE
- https://raw.githubusercontent.com/deuxfleurs-org/garage/v2.5.0/doc/book/quick-start/_index.md
- https://raw.githubusercontent.com/deuxfleurs-org/garage/v2.5.0/doc/book/reference-manual/s3-compatibility.md
- https://raw.githubusercontent.com/deuxfleurs-org/garage/v2.5.0/src/api/common/signature/payload.rs
