# Storage tooling — P01-01.10A

Private dev-only пакет для реального локального Garage S3 contract.
Не импортируется API/Web/Mini App, не реализует Files business module.

Direct dev dependencies: @aws-sdk/client-s3 и @aws-sdk/s3-request-presigner
строго3.1172.0 (Apache-2.0), внутренний @fixlevelup/tooling. Новый graph26 records,
Apache-2.0/MIT; registry integrity/metadata/engines/scripts/peers проверены,
install hooks отсутствуют. Прежние resolved records/importers не изменены,
новых prerelease исключений нет. Lifecycle scripts не выполняются.

Инфраструктура, источники и команды — ../../infra/dev-s3/README.md.
Из корня: s3:init → compose up → s3:bootstrap → s3:test.
Полный quality gate включает storage tests/typecheck; работающий Garage
и локальные credentials обязательны, как dev PostgreSQL для DB tests.

Scripts:
- init.mjs генерирует локальные secrets один раз, не ротирует существующие.
- bootstrap.mjs ограничен container fixlevelup-dev-s3 с проверкой Compose label;
  bucket/key grants задаются явно, raw CLI args/output не печатаются.
- local.mjs ограничивает endpoint/region/bucket, использует explicit credentials,
  bounded HTTP timeouts/maxAttempts1, не обращается к AWS metadata/default chain.
- persistence.mjs write/verify проверяет synthetic marker после restart.

Contract14 + transport2: bytes/hash/metadata, prefix pagination, anonymous/wrong credentials,
readonly write отказ, no create-bucket, missing key/delete, presign/tamper/expiry.
Synthetic objects сохраняются для evidence кроме своего deletion fixture.
Тесты не выводят signed URLs/XML/keys. ETag не универсальный checksum.
Transport regression tests используют ephemeral loopback HTTP fixture: зависание
до headers и после первого byte body. Принудительный request timeout и socket
inactivity timeout5000ms прерывают запрос; проверяется закрытие sockets до cleanup.

Ограничения: single-node dev без HA, HTTP только loopback, без backup/restore
приёмки, versioning/ObjectLock/policies, upload API/scanner/PII или production.
