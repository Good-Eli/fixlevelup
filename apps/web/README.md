# P01-01.3 — Technical Next build target

Это закрытый технический build/smoke стенд, не клиентский сайт и не CRM.
На странице явно обозначено отсутствие бизнес-функций. Форм, контактов,
прайса, auth, DB/Prisma и provider SDK здесь нет.

## Окружение и зависимости

Node 24.22.3, pnpm 12.21.0; Next 16.4.6, React/React DOM 19.3.1.
Types: @types/react и @types/react-dom 19.3.0; внутренний tooling config.
TypeScript 6.0.3 и Node typings24 используются из root workspace.
Root ESLint импортирует standalone @next/eslint-plugin-next 16.4.6.
Полный eslint-config-next не установлен. React Hooks plugin отложен:
7.1.1 подтягивает Babel/gensync beta, а server-only proof page не использует
hooks. Перед первым client component нужны reviewed hooks rules.

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

Это HTTP production smoke, не браузерный E2E: hydration, accessibility,
визуальная/мобильная приёмка и Playwright ещё не выполнялись. Canary задан
runtime-child; build-time secret embedding этим тестом не доказан.
Noindex не заменяет auth/network isolation; стенд нельзя публиковать клиентам.
Linux/CI и будущие frontend features проверяются на своих подэтапах.
