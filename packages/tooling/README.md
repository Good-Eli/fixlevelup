# Workspace & Tooling — P01-01.1

Этот пакет содержит общие TypeScript-конфигурации и технические proof tests.
Приложений, API, бизнес-модулей и инфраструктуры пока нет.

## Зафиксированное окружение

- Node.js 24.22.3; Corepack 0.36.0; pnpm 12.21.0.
- Один root manifest, один workspace package и один pnpm-lock.yaml.
- Внешние dev dependencies: TypeScript 6.0.3, @types/node 24.19.2,
  ESLint 10.15.0, @eslint/js 10.0.1, typescript-eslint 8.73.0,
  globals 17.14.0, Vite 8.3.8, Vitest 5.1.1.
- Vite явно предоставляет обязательный peer Vitest. React/Next/Nest/Prisma
  и другие будущие зависимости не устанавливаются на этом подэтапе.

## Запуск из корня репозитория в PowerShell

```powershell
$env:COREPACK_HOME = Join-Path $env:LOCALAPPDATA 'fixlevelup-tooling\corepack'
$env:COREPACK_ENABLE_AUTO_PIN = '0'
$env:COREPACK_DEFAULT_TO_LATEST = '0'
corepack pnpm --version
corepack pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies
corepack pnpm peers check
corepack pnpm run check
```

Первый запуск Corepack скачивает точную версию pnpm и native executable;
это bootstrap, а не read-only проверка. В Windows cache размещён вне
workspace: executable, унаследовавший Low integrity label от sandbox
workspace, не может писать в обычный пользовательский operation-lock
каталог даже после переключения сессии в full access. Права Windows,
security labels, Defender и блокировки pnpm не изменялись.
На других системах следует использовать обычный пользовательский cache Corepack.

## Политика зависимостей

- Dependency lifecycle scripts запрещены: ignoreScripts, пустой allowBuilds,
  strictDepBuilds; явные команды lint/typecheck/test разрешены.
- Strict peers, без автоматической установки peers и peer exceptions.
- pmOnFail/error и verifyDepsBeforeRun/error запрещают незаметные download/install.
- pnpmfile, pre/post run scripts, skills linking и side-effects cache отключены.
- TLS и проверки integrity включены; registry — https://registry.npmjs.org/.
- Исключена только optional WASI-ветка Rolldown, которая тянула @emnapi beta.
  Native bindings для Windows/Linux сохранены. WASI не является целевой платформой.
- macOS-only fsevents 2.3.3 имеет install hook; он не запускался и не разрешён.
- Лицензии транзитивного графа включают MIT, Apache-2.0, BSD и ISC,
  BlueOak-1.0.0 и MPL-2.0 (LightningCSS); это dev tooling, не production SBOM.

Typecheck выполняет tsc независимо от Vitest transform. Tests проверяют
strict compiler diagnostics, type-aware ESLint и UTF-8/LF, а не бизнес-функции.
Windows frozen install, offline repeat и forced offline reinstall проверены;
Linux/CI, browser smoke и сборки будущих приложений этим не подтверждаются.
Новые версии и lifecycle approvals требуют отдельного review.
