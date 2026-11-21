# FixLevelUp

FixLevelUp — платформа для организации заявок на ремонт бытовой техники: клиентский приём заявок, рабочее место менеджера, инструменты мастеров и коммуникация через подключаемые каналы. Проект рассчитан на одну компанию с возможностью последовательно запускать новые города; это не multi-tenant SaaS.

> **Текущее состояние:** foundation P01, контур сотрудников P02 и принятые подэтапы P03-01 и P03-02. Работа остановлена перед P03-03. Реализованы web-сессии менеджера и администратора, серверная авторизация с ролями и правами, Telegram Mini App exchange для мастера, [управление доступом](docs/RBAC.md) в CRM (`/crm/access`) и внутренний read-only city context. Каталог услуг, заявки, расписание, сметы и клиентские messenger adapters — не часть этой реализации. Production deployment, живые приёмки и реальный Telegram-вход не выполнены.

В [принятом P03-01](docs/SUBTASKS.md#p03--настройки-география-согласия-и-приватные-файлы) появились схема городов, версии настроек и серверное определение единственного активного города. В P03-02 реализованы районы, версии покрытия зон, допуски мастеров и [согласованная матрица управления географией](docs/P03-02-ACCESS.md). Сервер проверяет город при каждой операции. Автоматическая выдача пяти новых прав — только первому подтверждённому администратору; у остальных — явные назначения. Географические команды доступны через защищённый API. В CRM расширен редактор прав, не добавлены формы настройки географии и публичного приёма заявок. Миграции не заполняют реальные города или контакты.

## Статус этапов и приёмки

- **P01 — принят владельцем как технический closeout с ограничениями.** Техническая реализация завершена; F01–F05 и F07 — PASS, F06 — PARTIAL. Это не production approval. Открытые F06 gates перечислены в [Preflight P01](docs/PREFLIGHT_P01.md).
- **P02 — реализация P02-01—P02-06 закоммичена.** P02 принят владельцем в согласованных границах; все шесть подэтапов закоммичены. Приёмка не означает production readiness. Telegram exchange работает только при заранее созданной активной связи; первичная привязка сотрудника и выпуск web credential новому сотруднику ещё не реализованы.
- **P03 — приняты P03-01 и P03-02; работа остановлена перед P03-03.** Город, версии настроек, районы, покрытие зон и территориальные допуски реализованы на synthetic data. Согласия, приватные файлы, CRM-управление настройками и публичный выбор города отсутствуют. `CITY` выдаётся только для пяти географических операций и только вместе с административным назначением сотрудника в город ресурса. Следующий подэтап требует отдельного разрешения владельца.
- **Production/live gates не закрыты:** TTY-проверка bootstrap/recovery, живой Telegram E2E и первичная привязка, доверенная HTTPS proxy-конфигурация и согласование обработки реальных персональных данных. Cutover-миграция 009 необратима в обратную сторону; перед её применением необходимы остановка старых writers и проверяемый backup.

Статусы и границы этапов ведутся в [Roadmap](docs/ROADMAP.md); подробный журнал подэтапов — в [SUBTASKS](docs/SUBTASKS.md). Успешный CI подтверждает только проверенный commit и не заменяет приёмку владельца или production gates.

## Технологический стек

Версии ниже сверены с root/workspace manifests и `pnpm-lock.yaml` на commit `8f0b204333395dcee1a1808b703a4dfbdce9efa9` (21.11.2026). Манифесты и lockfile не менялись с `b42e0ef`, поэтому граф зависимостей прежний.

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
  api/          NestJS API и worker; auth, RBAC, staff-операции и административная география
  web/          Next.js: техническая страница и закрытый раздел CRM /crm/access
  miniapp/      React/Vite target будущего staff Mini App (UI пока не подключён)
packages/
  tooling/             общие TypeScript/tooling настройки
  database-tooling/    Prisma CLI и проверки истории миграций
  storage-tooling/     S3-compatible dev tooling и backup/restore drill
  browser-tooling/     Playwright browser proof и RBAC-сценарий CRM
infra/
  dev-postgres/        изолированная локальная PostgreSQL
  dev-s3/              локальный Garage S3-compatible
  backup/              синтетический backup/restore drill
  linux-proof/         Linux runtime/reproducibility proof
  linux-integration/   Linux PostgreSQL/Garage integration proof
  browser-proof/       browser smoke proof
  ci/                  CI helper scripts и dependency/license/secret gates
docs/                  архитектура, БД, API, решения, RBAC, Preflight, Roadmap, подэтапы
info/                  исходные материалы проекта и отчёты
```

Подробные контракты находятся в `docs/ARCHITECTURE.md`, `docs/DATABASE.md`, `docs/API.md`, `docs/DECISIONS.md` и `docs/RBAC.md`.

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

- **API / worker:** [`apps/api/README.md`](apps/api/README.md). Health/readiness, технический outbox, web-аутентификация, серверная авторизация, staff- и roles-операции, административная география (`/api/v1/geography/*`, `staff.geography.*`) и read-only `/territory` для мастера. Бизнес-маршрутов заявок, каталога и расписания нет; реестр обработчиков outbox по-прежнему пуст. Auth-маршруты существуют только при `WEB_AUTH_ENABLED=1` с полной валидной конфигурацией, иначе `/auth/*` отсутствуют. Entrypoints не загружают `.env` автоматически; нужные переменные передаются окружением явно. Первый администратор создаётся консольной командой `staff:bootstrap`, пароль восстанавливается через `staff:recover`.
- **Web:** [руководство Web](apps/web/README.md). Техническая страница и закрытый раздел CRM `/crm/access` — «Сотрудники и доступ». Серверный HTML раздела только оболочка: данные приходят после проверки CRM-сессии. Для UI и `/api/v1` нужен один HTTPS origin; браузер не подключается к БД, а Next не заменяет серверную авторизацию Nest.
- **Mini App:** [`apps/miniapp/README.md`](apps/miniapp/README.md). Технический React/Vite target. Серверная проверка `initData` и обмен на сессию мастера реализованы в API (P02-05), но сам интерфейс Mini App их пока не вызывает: Telegram SDK и рабочий экран мастера не подключены.

## CI и evidence

Workflow: [`.github/workflows/ci.yml`](.github/workflows/ci.yml). Он запускает Linux proof, Linux PostgreSQL/Garage integration, browser proof и dependency/license/lockfile/secret gates.

На commit `8f0b204333395dcee1a1808b703a4dfbdce9efa9` GitHub Actions run [44815347477](https://github.com/Good-Eli/fixlevelup/actions/runs/44815347477) завершился успешно. Это воспроизводимое evidence конкретного технического commit, а не production certification или приёмка бизнес-функций.

Промежуточные прогоны 12–14 завершились failure: информационные patch-файлы в `info/` срабатывали в secret scan. В проверенном прогоне [44804420059](https://github.com/Good-Eli/fixlevelup/actions/runs/44804420059) единственная упавшая задача — «Scan repository and all available Git history for secrets»; Linux, integration и browser jobs прошли. Патчи удалены, для единственного false positive добавлено исключение, привязанное к commit/path/line/rule и к SHA-256 blob-а, поэтому изменённый или перемещённый контент остаётся находкой.

Политика и ограничения dependency/license gate: [`infra/ci/DEPENDENCIES.md`](infra/ci/DEPENDENCIES.md). В частности, technical license inventory не является legal approval; отдельный review текущих исключений находится в [`docs/THIRD_PARTY_LICENSE_REVIEW.md`](docs/THIRD_PARTY_LICENSE_REVIEW.md) (добавлен в подэтапе P01-12B.1). F06 остаётся PARTIAL до фактического deployment SBOM, notices и legal distribution review.

## Документация и план

- [Architecture](docs/ARCHITECTURE.md)
- [Database model](docs/DATABASE.md)
- [API contracts](docs/API.md)
- [Decisions](docs/DECISIONS.md)
- [RBAC сотрудников](docs/RBAC.md)
- [Матрица доступа P03-02](docs/P03-02-ACCESS.md)
- [Roadmap](docs/ROADMAP.md)
- [Подэтапы проектов](docs/SUBTASKS.md)
- [P01 Preflight](docs/PREFLIGHT_P01.md)
- [Changelog](CHANGELOG.md)
- [Third-party license review](docs/THIRD_PARTY_LICENSE_REVIEW.md)

## Security / secrets

Не коммитьте `.env`, credentials, database dumps, Garage keys, backups, real customer data или raw CI artifacts. Используйте `.env.example` как список имён переменных, а не как источник credentials. Публичный репозиторий не означает разрешение публиковать дополнительные сведения об операционной среде.

## Roadmap boundary

Для P03-01 и P03-02 основание — отдельные поручения владельца, а не завершение P02 или успешный CI. Каждый следующий подэтап и работа с реальными данными требуют собственного решения.
