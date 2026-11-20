# P01-01.11A — Local Linux reproducibility and runtime smoke

Изолированный local Docker proof на linux/amd64 Node24.22.3, не remote CI,
не production image и не закрытие всего P01. Remote/forge/runner policy не меняется.

## Запуск из корня

```powershell
docker build --file infra/linux-proof/Dockerfile --tag fixlevelup-linux-proof:p0111a-openssl .
# Именованный контейнер сохраняется для evidence; mount source/secrets/socket нет.
docker run --name fixlevelup-linux-proof-p0111a-openssl --network none --cpus 2 --memory 4g fixlevelup-linux-proof:p0111a-openssl
# После успешного завершения, отдельный путь вне Git:
docker cp fixlevelup-linux-proof-p0111a-openssl:/workspace/node_modules/.cache/linux-proof node_modules/.cache/linux-proof-evidence
```

Build использует pinned node:24.22.3-bookworm-slim digest
sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54.
Frozen install скачивает только согласованные lock packages, scripts запрещены.
Corepack использует exact pnpm12.21.0. Только в test image отдельно согласованы системные prerequisites:
openssl/libssl3 3.0.22-1~deb12u2 и ca-certificates20250419~deb12u2.
Lifecycle hooks и новые npm dependencies не включены. Build выполняет явную
Prisma generation для подготовки exact7.10.1 engine до отключения сети;
первый slim-image proof без OpenSSL остановился на попытке engine download.
Windows node_modules/store не копируются.

Root .dockerignore исключает credentials/.env (кроме example), .git, backups,
local-data/private/secrets/uploads, generated client, host builds и caches.
source-check.mjs внутри image повторно проверяет отсутствие таких файлов.
Image содержит только source и freshly installed Linux dependencies, без
реальных ПД/секретов. Это локальный test image; не публиковать в registry.

## Что проверяется с --network none

- Принудительная offline frozen reinstall, lockfile hash неизменен.
- Lint, независимые typecheck, Prisma generation и build API/Web/Mini App.
- Явный allowlist service-independent Vitest files: tooling/DI/HTTP/config/logs/
  lifecycle/Prisma ESM isolation, frontend HTTP/assets/markup, manifest guards,
  timeout fixtures. Tests не skip-аются по ENV и не ослабляются.
- API runtime graph isolation.
- posix-smoke.mjs: actual compiled API и worker entrypoints, реальные OS
  SIGTERM и SIGINT, bounded natural exit и shutdown_completed. API health/live
  HTTP200, readiness503 без DB; synthetic password/canary не попадают в output.

Evidence result.json + posix.json сохраняются только после успешных checks.
Логи команды/exit codes являются actual evidence, не только наличие Dockerfile.
Повторный запуск не должен перезаписывать существующий proof container: используйте
новое имя или отдельно согласованно управляйте старым. Не prune/clean/down-v.

## Фактический результат 20.11.2026

Итоговый image ID: sha256:c3aec6c56012260fef9b1299db657279e0425b53a2c82d465defb513d32c9e7c.
Container fixlevelup-linux-proof-p0111a-openssl завершился exit0, networknone,
mounts[], ports{}, лимиты2CPU/4GiB. Offline reinstall449 packages/downloaded0.
Linux lint/typecheck/build и221 tests в12files прошли. OS signal4cases:
API SIGTERM38ms/SIGINT34ms, worker SIGTERM128ms/SIGINT141ms; code0, signalnull,
stderr0, secret canary отсутствует. Runtime graph120 packages isolation PASS.
Lock SHA256:5c6754b43491729d68755f880944560d18128ae7d33b6ed22d0a9fe5d2488564.
Windows full regression261tests/16files, lint/typecheck/build тоже PASS.
Redacted actual JSON evidence скопирован в ignored node_modules/.cache/linux-proof-evidence.
Первый container fixlevelup-linux-proof-p0111a сохранил неуспешный результат
до согласования OpenSSL prerequisites; он не удалён/не назван passing.

## Не заявляется

Полный Linux PostgreSQL/S3 integration, migrations/restore Linux, browser launch,
Playwright, image vulnerability scan, hosting/CI execution, deploy/HA и production
security. Эти gates остаются отдельными. Windows full regression и dev DB/S3
proofs не заменяют соответствующие Linux integration evidence.
