# P01-01.11C — Browser Technical Smoke

Локальная browser-проверка только технических production Web/Mini App страниц.
Без бизнес-flow, Telegram/initData, user data, публикации и remote CI.

Matching pair: @playwright/test/playwright/core1.65.1 и
mcr.microsoft.com/playwright:v1.65.1-noble digest
sha256:1507cbfc550a63a6b7396791ca4f00df17beb56342d2447b3f106c306f525579.
Upstream image Node26.13.1 не считается проверкой выбранного runtime. Derived
image копирует exact Node24.22.3 distribution из pinned Node image; PATH отдаёт
ему приоритет. Серверы, сборки и test runner работают на Node24.22.3.
Новые apt/runtime packages не устанавливаются. Browser binaries/system libs
взяты только из matching upstream image; browser downloads/scripts отключены.

## Запуск из корня

```powershell
docker --host npipe:////./pipe/dockerDesktopLinuxEngine build -f infra/browser-proof/Dockerfile -t fixlevelup-browser-proof:p0111c .
docker --host npipe:////./pipe/dockerDesktopLinuxEngine run --name fixlevelup-browser-proof-p0111c --network none --cpus 2 --memory 4g --shm-size 1g fixlevelup-browser-proof:p0111c
# После успешного exit0, только redacted evidence/screenshots:
docker --host npipe:////./pipe/dockerDesktopLinuxEngine cp fixlevelup-browser-proof-p0111c:/workspace/test-results node_modules/.cache/browser-proof-test-results
docker --host npipe:////./pipe/dockerDesktopLinuxEngine cp fixlevelup-browser-proof-p0111c:/workspace/node_modules/.cache/browser-proof node_modules/.cache/browser-proof-evidence
```

Имена не перезаписывать: если контейнер существует, используйте новое имя.
Без mounts/socket/host ports/dev service networks. Runtime networknone; source
context исключает .env/backups/node_modules/build artifacts. Не prune/clean.

## Checks

Frozen install без lifecycle hooks и offline runtime install; lock hash неизменен.
Production build API/Web/MiniApp, browser tooling lint/typecheck. Два tests на
каждом Chromium/Firefox/WebKit × desktop1280x800/mobile viewport390x844 =12cases.
Mobile viewport — не настоящие телефоны/Telegram, device emulation не заявляется.
Web HTTP200/langru/noindex/no-powered-by, Mini пустой исходный root→JS-mounted
heading/output. Loaded JS success, reload stability, no page/console errors,
no failed/external network, no horizontal overflow, technical screenshots.
No skip/retry/reuseExistingServer; Playwright и Vitest отдельные runners.

## Фактический результат 20.11.2026

Итоговый derived image ID sha256:f0032e1812d4e047d3050de6821f5387fc9a5e544b1e383b4e12d192432feecb.
Container fixlevelup-browser-proof-p0111c завершился exit0; inspect подтвердил
networknone,mounts[],ports{}. Node24.22.3,Playwright1.65.1;12passed,
0unexpected/0skipped/0flaky,12screenshots. Matching Chromium/Firefox/WebKit
фактически запускались. Browser tooling strict typecheck использует DOM lib
только своего пакета; общий Node config не ослаблен.
Windows full gate261tests/16files PASS, frozen/offline install451packages
скачано0,peers/audit чистые; прежние graph records не изменены.
Redacted JSON/screenshots скопированы в ignored node_modules/.cache/browser-proof-*
каталоги; screenshots технических страниц без ПД просмотрены выборочно.

Browser test network routing разрешает только127.0.0.1:4170/4171,data/blob.
Screenshots/JSON находятся в ignored test-results; traces/video отключены,
реальные credentials/ПД отсутствуют. Full visual/a11y acceptance, production
business readiness, browser vulnerability/image scan и remote CI не заявляются.
Контейнер root применяется только к доверенным локальным synthetic страницам;
это не sandbox для чужих сайтов. Browser sandbox policy не обещает production
security и не переиспользуется для пользовательского контента.
