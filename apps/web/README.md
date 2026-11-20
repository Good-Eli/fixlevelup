# P01-01.3 — Technical Next build target

Главная страница остаётся техническим build/smoke стендом. Отдельный закрытый раздел CRM — `/crm/access` («Сотрудники и доступ»). Серверный HTML раздела — только оболочка: доступ, профили и роли загружаются после проверки CRM-сессии. Next не имеет доступа к БД и не заменяет серверную авторизацию Nest.

### Read-only пример маршрутизации (не deployment)

| Публичный HTTPS origin (пример) | Назначение reverse proxy |
|---|---|
| `https://crm.example.invalid/api/v1/*` | Nest; сохранить полный путь `/api/v1/*`, исходный `Origin`, Cookie/Set-Cookie и security headers, не кешировать |
| остальные пути того же origin | Next; `/crm/access` обслуживает закрытую оболочку |

Web auth origin в Nest должен точно совпадать с публичным HTTPS origin. Не менять `Secure`/`HttpOnly`/`SameSite=Strict` у `__Host-` cookie, не включать cross-origin CORS. Не помещать в клиент `DATABASE_URL`, пароль, session token или статический CSRF token. CSRF поступает из `/auth/me`, живёт в памяти вкладки; логин использует `X-CSRF-Token: login`. Эта таблица ничего не запускает, домен не используется для сетевых запросов. Нет демо-паролей, обхода входа или фальшивых данных при ошибке API.

## Окружение и зависимости

Node 24.22.3, pnpm 12.21.0; Next 16.4.6, React/React DOM 19.3.1.
Types: @types/react и @types/react-dom 19.3.0; внутренний tooling config.
TypeScript 6.0.3 и Node typings24 используются из root workspace.
Root ESLint импортирует standalone @next/eslint-plugin-next 16.4.6.
Полный eslint-config-next не установлен. React Hooks plugin отложен:
7.1.1 подтягивает Babel/gensync beta. Для CRM без новых зависимостей эффект и очистку проверяем тестами и review; автоматические hooks rules остаются отдельной проверкой tooling.

## Команды из корня (PowerShell)

```powershell
$env:COREPACK_HOME = Join-Path $env:LOCALAPPDATA 'fixlevelup-tooling\corepack'
$env:COREPACK_ENABLE_AUTO_PIN = '0'
$env:COREPACK_DEFAULT_TO_LATEST = '0'
corepack pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies
corepack pnpm run check
corepack pnpm --filter @fixlevelup/web start --port 3000
```

Start слушает 127.0.0.1. Это не публикация и не deployment.
Команда test сначала собирает API и web, затем запускает общий Vitest runner.
Build использует Turbopack, не Vite. В конфигурации cpus:2 ограничивает
worker parallelism; Next относит этот параметр к experimental namespace.
Никакие preview-пакеты или experimental TS compiler paths не включены.

scripts/next.mjs включает CI=1 (без автоматической установки отсутствующих
TypeScript deps), NEXT_TELEMETRY_DISABLED=1 и убирает NEXT_TELEMETRY_DEBUG.
На проверенной Windows/x64 он сначала загружает установленный exact native SWC,
чтобы отсутствие binding завершалось ошибкой до Next fallback download.
Lifecycle scripts зависимостей не разрешались; SWC/Sharp доступны в npm artifacts.
Native Sharp/libvips включает LGPL-3.0-or-later; caniuse-lite — CC-BY-4.0.
В графе также есть MIT/Apache/BSD/ISC/BlueOak/MPL и 0BSD. LICENSE busboy и
streamsearch прочитаны отдельно: MIT, хотя registry SPDX-поле отсутствует.
На этом прогоне audit endpoint дважды ответил сетевой TLS handshake EOF;
успешный vulnerability audit для нового графа не заявляется.
Внешних fonts/assets/fetch в приложении нет.

Typecheck выполняет next typegen и отдельный tsc --noEmit. Strict flags и
skipLibCheck:false наследуются; web lib ES2024 нужен Next PromiseWithResolvers.
Next генерирует next-env.d.ts и .next/types, но не переписывал tsconfig.json.

## Что проверяет smoke

Production Next request handler работает в отдельном Node-процессе на
случайном loopback-порту. Проверяются HTML marker/lang, JS assets200,
отсутствие X-Powered-By, robots metadata/X-Robots-Tag noindex, 404 для
неизвестных/business routes и отсутствие synthetic runtime canary в HTML/JS.
Child закрывается по test-only IPC; production shutdown endpoint не добавлен.

Отдельный Vitest suite `apps/web/tests/access-client.test.ts` проверяет публичный HTTP-контракт клиента, получение прав и независимость действий. Playwright suite `packages/browser-tooling/tests/rbac.spec.ts` работает с production Next и перехватывает только синтетические `/api/v1/*`; это проверка реального поведения браузера, не live Nest/HTTPS E2E. Проверки PostgreSQL и авторизации выполняются отдельно на стороне API. Полная визуальная/mobile/a11y-приёмка, реальный HTTPS proxy и production остаются отдельными gates. Noindex не заменяет auth/network isolation.
