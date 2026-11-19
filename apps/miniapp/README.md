# P01-01.4 — Mini App Foundation

Минимальный React/Vite build target для будущего staff Telegram Mini App.
Технический экран явно обозначен: это не рабочий интерфейс мастера.
Telegram SDK/initData, auth, backend calls, заказы, расписание, формы,
платежи и другие бизнес-функции пока отсутствуют.

## Dependencies

Runtime: React/React DOM 19.3.1.
Dev: Vite 8.3.8, @vitejs/plugin-react 6.3.0, @types/react и
@types/react-dom 19.3.0, внутренний @fixlevelup/tooling.
TypeScript 6.0.3 и test runner Vitest5.1.1 используются из root.
Plugin использует default automatic JSX, без optional Babel/React Compiler.
Hooks plugin остаётся отложенным из-за Babel/gensync beta; этот экран не
содержит hooks. Перед stateful/client business UI нужен отдельный review правил.
Dependency lifecycle scripts запрещены, strict peers и TLS сохранены.

## Запуск из корня (PowerShell)

```powershell
$env:COREPACK_HOME = Join-Path $env:LOCALAPPDATA 'fixlevelup-tooling\corepack'
$env:COREPACK_ENABLE_AUTO_PIN = '0'
$env:COREPACK_DEFAULT_TO_LATEST = '0'
corepack pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies
corepack pnpm run check
corepack pnpm --filter @fixlevelup/miniapp dev
# Только локальный просмотр готового dist, не production server:
corepack pnpm --filter @fixlevelup/miniapp preview
```

Dev/preview слушают 127.0.0.1, strictPort не позволяет молча менять занятый порт.
HTML имеет viewport/lang/robots noindex; preview добавляет X-Robots-Tag.
Noindex не является контролем доступа. Standalone preview не Telegram live test.

## Проверки

Отдельные TypeScript-контексты: src — browser/bundler без Node types;
config/tests — NodeNext. ESLint запрещает Node globals, bare/node: imports,
Nest/Prisma/AWS SDK и API imports в src. Будущие серверные пакеты не должны
попадать в browser graph. Artifact string scan — дополнительная проверка,
не самостоятельное доказательство любых транзитивных зависимостей.

Build wrapper добавляет unprefixed synthetic MINIAPP_SERVER_CANARY перед Vite
build; tests проверяют отсутствие его значения в готовых assets. Это конкретный
build-time canary proof, не разрешение хранить секреты в frontend env.
VITE_* переменные публичны; текущий src не читает env и не вызывает backend.
Source maps отключены. Внешние fonts/assets не используются.

Vitest Node renderer проверяет markup App; preview smoke проверяет реальные
built HTML/JS по HTTP и закрытие listener. Browser mount/createRoot, hydration,
визуальная/mobile/a11y приёмка, Telegram auth/SDK и Playwright не проверялись.
Linux/CI/deployment остаются следующими отдельными gates.
