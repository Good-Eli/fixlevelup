# FixLevelUp

FixLevelUp — платформа для организации заявок на ремонт бытовой техники: клиентский приём заявок, рабочее место менеджера, инструменты мастеров и коммуникация через подключаемые каналы. Проект рассчитан на одну компанию с возможностью последовательно запускать новые города; это не multi-tenant SaaS.

> **Текущее состояние:** технический foundation P01. Репозиторий содержит инфраструктурные заготовки, API/worker entrypoints, технические страницы Web и Mini App, tooling, миграции audit/outbox и CI proofs. Это ещё не готовая клиентская платформа: бизнес-модули, авторизация, каталог, заявки, CRM, расписание, сметы, реальные messenger adapters и production deployment не реализованы.

## Технологический стек

Версии ниже сверены с root/workspace manifests и `pnpm-lock.yaml` на commit `b42e0efa23d7c67b17271cf3a4f489660a95ebe5` (20.11.2026).

| Область | Технологии |
|---|---|
| Runtime / package manager | Node.js 24.22.3, Corepack, pnpm 12.21.0 |
| Язык и качество | TypeScript 6.0.3, ESLint 10.15.0, typescript-eslint 8.73.0, Vitest 5.1.1 |
| Web | Next.js 16.4.6, React / React DOM 19.3.1 |
| API / worker | NestJS 12.5.1, Prisma 7.10.1, `pg` 8.23.1 |
| Mini App foundation | React 19.3.1, Vite 8.3.8, `@vitejs/plugin-react` 6.3.0 |
| Database | PostgreSQL 18.7 для локальной разработки и proofs |
| Object storage | Garage S3-compatible для локальной разработки и proofs |
| Browser proof | Playwright 1.65.1, Chromium / Firefox / WebKit |

Точные версии и весь граф зависимостей задаёт `pnpm-lock.yaml`. Не обновляйте отдельные пакеты вручную в обход lockfile и review.

## Структура репозитория

```text
apps/
  api/          технические NestJS API и worker entrypoints
  web/          минимальный Next.js build/smoke target
  miniapp/      минимальный React/Vite target будущего staff Mini App
packages/
  tooling/             общие TypeScript/tooling настройки
  database-tooling/    Prisma CLI, миграции и DB proofs
  storage-tooling/     S3-compatible dev tooling и backup/restore drill
  browser-tooling/     Playwright browser proof
infra/
  dev-postgres/        изолированная локальная PostgreSQL
  dev-s3/              локальный Garage S3-compatible
  backup/              синтетический backup/restore drill
  linux-proof/         Linux runtime/reproducibility proof
  linux-integration/   Linux PostgreSQL/Garage integration proof
  browser-proof/       browser smoke proof
  ci/                  CI helper scripts и dependency/license gate
docs/                  архитектура, БД, API, решения, Preflight и Roadmap
info/                  исходные материалы проекта
```

Подробные контракты находятся в `docs/ARCHITECTURE.md`, `docs/DATABASE.md`, `docs/API.md` и `docs/DECISIONS.md`.

## Требования

- Windows 11 или Linux для локальной разработки; CI использует `ubuntu-24.04`.
- Node.js **24.22.3** и Corepack.
- pnpm **12.21.0** — версия закреплена в `package.json`.
- Docker Engine / Docker Desktop с Compose для PostgreSQL, Garage и отдельных integration proofs.
- Для интеграционных DB/S3 проверок нужны отдельно созданные локальные credentials. Они не должны попадать в Git.

## Установка и базовые проверки

Пример для PowerShell из корня репозитория:

```powershell
$env:COREPACK_HOME = Join-Path $env:LOCALAPPDATA 'fixlevelup-tooling/corepack'
$env:COREPACK_ENABLE_AUTO_PIN = '0'
$env:COREPACK_DEFAULT_TO_LATEST = '0'
corepack pnpm --version
corepack pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies
```

Установка использует frozen lockfile и не запускает lifecycle scripts зависимостей. Не удаляйте `--ignore-scripts` и `--strict-peer-dependencies` без отдельного review.

Основные root scripts:

```powershell
corepack pnpm run lint
corepack pnpm run typecheck
corepack pnpm run build
corepack pnpm run test
corepack pnpm run check
```

`check` — полный quality gate: lint, typecheck и test (включая build). Часть DB/S3 tests требует подготовленных локальных PostgreSQL/Garage и credentials; сначала прочитайте соответствующие инструкции. Не запускайте destructive cleanup, `docker compose down -v`, `git clean` или сброс баз ради «починки» тестового окружения.

## Локальная инфраструктура

### PostgreSQL

Инструкция: [`infra/dev-postgres/README.md`](infra/dev-postgres/README.md).

Compose-файл: `infra/dev-postgres/compose.yaml`. Для нового окружения скопируйте `infra/dev-postgres/.env.example` в локальный `.env` рядом с compose-файлом и задайте новый случайный пароль. Dev endpoint опубликован только на loopback `127.0.0.1:55432`; база `fixlevelup_dev`. `.env` не коммитить.

### S3-compatible storage

Инструкция: [`infra/dev-s3/README.md`](infra/dev-s3/README.md).

Compose-файл: `infra/dev-s3/compose.yaml`. Секреты создаются локальными storage tooling scripts; шаблон переменных — `infra/dev-s3/.env.example`. Не копируйте реальные ключи в документацию, issues или CI logs.

### Backup / restore proof

[`infra/backup/README.md`](infra/backup/README.md) описывает synthetic logical backup/restore PostgreSQL и объектов. Это локальный тест на синтетических данных, а не production backup, off-host durability, PITR, encryption policy или измерение RPO/RTO.

## Приложения

- **API / worker:** [`apps/api/README.md`](apps/api/README.md). Технические health/readiness entrypoints и outbox infrastructure. Production business handlers отсутствуют. Entrypoints не загружают `.env` автоматически; нужные переменные передаются окружением явно.
- **Web:** [`apps/web/README.md`](apps/web/README.md). Технический Next.js build/smoke target, не клиентский сайт и не CRM.
- **Mini App:** [`apps/miniapp/README.md`](apps/miniapp/README.md). Технический React/Vite target будущего staff Telegram Mini App; Telegram SDK, initData validation и бизнес-интерфейс пока не подключены.

## CI и evidence

Workflow: [`.github/workflows/ci.yml`](.github/workflows/ci.yml). Он запускает Linux proof, Linux PostgreSQL/Garage integration, browser proof и dependency/license/lockfile/secret gates.

На commit `b42e0efa23d7c67b17271cf3a4f489660a95ebe5` GitHub Actions run [44675339571](https://github.com/Good-Eli/fixlevelup/actions/runs/44675339571) завершился успешно: четыре из четырёх jobs — success. Это воспроизводимое evidence конкретного технического commit, а не production certification или приёмка бизнес-функций.

Политика и ограничения dependency/license gate: [`infra/ci/DEPENDENCIES.md`](infra/ci/DEPENDENCIES.md). В частности, technical license inventory не является legal approval; отдельный review текущих исключений находится в [`docs/THIRD_PARTY_LICENSE_REVIEW.md`](docs/THIRD_PARTY_LICENSE_REVIEW.md) (добавлен в подэтапе P01-12B.1).

## Документация и план

- [Architecture](docs/ARCHITECTURE.md)
- [Database model](docs/DATABASE.md)
- [API contracts](docs/API.md)
- [Decisions](docs/DECISIONS.md)
- [Roadmap](docs/ROADMAP.md)
- [P01 Preflight](docs/PREFLIGHT_P01.md)
- [Changelog](CHANGELOG.md)
- [Third-party license review](docs/THIRD_PARTY_LICENSE_REVIEW.md)

## Security / secrets

Не коммитьте `.env`, credentials, database dumps, Garage keys, backups, real customer data или raw CI artifacts. Используйте `.env.example` как список имён переменных, а не как источник credentials. Публичный репозиторий не означает разрешение публиковать дополнительные сведения об операционной среде.

## Roadmap boundary

P02 (Auth and capabilities) не начинается автоматически после P01. Для каждого следующего этапа требуется отдельное разрешение владельца; успешный CI или наличие технического scaffold не заменяет такое разрешение.
