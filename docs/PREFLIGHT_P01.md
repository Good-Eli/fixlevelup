# Preflight P01 — Foundation (на явное утверждение)

**Ревизия R3.2, дата19.11.2026. Документ подготовлен только в Этапе0. P01 НЕ НАЧАТ.** Подтверждённые owner facts/MAX assumption/будущие города одной компании — [DECISIONS §20](DECISIONS.md#20-решения-владельца-r32); стек ниже exact candidates, не установленная проверенная комбинация. Никаких manifests, installs, генерации lock/DDL, Docker containers, CI registration, коммитов или messenger registrations этой работой не выполняется. [Архитектура](ARCHITECTURE.md), [БД](DATABASE.md), [API](API.md), [план P01](ROADMAP.md#p01--foundation-git-ci-proof-ограничений), [решения и audit disposition](DECISIONS.md#19-ограниченные-исправления-после-заключительного-аудита-r3).

Слова «утверждённый стек» не присваиваются предложениям автоматически: ТЗ/владелец уже задали модульный монолит, единую PostgreSQL/общую бизнес-логику, три равноправных клиентских канала и staff TG Mini App. Конкретные frameworks/версии/CI/публичный author и старт P01 ниже требуют отдельного approval. Молчание/пропуск вопроса не согласие.

## A. Точный scope P01 и критерии

P01 — **только технический foundation**, не первый business slice. Модель [географии DB§3.8](DATABASE.md#38-география-одной-компании-основа-будущих-городов-r32) зафиксирована **до первых доменных миграций**: city_id/FKs/version snapshots/prices/technician scopes позже не добавляются задним числом. В P01 лишь documentary contract+synthetic constraint proof, никаких public city selectors/CRM/geography domain tables/реального города. После отдельного разрешения допустимы:

| ID | Результат / ожидаемые scopes | Измеримая приёмка |
|---|---|---|
| F01 | pnpm workspace/tooling: корневые manifests+lock/TS strict/lint/test configs, apps/api, apps/web, apps/miniapp, packages/tooling; минимальные boot/build targets | Один exact packageManager, clean clone+frozen lock повторяемы Windows dev/Linux CI; no незадокументированных engine/peer conflicts и Preview packages |
| F02 | API/worker технические entrypoints, health/live/ready, graceful shutdown, config validation и structured redacted logs | Live не зависит от Telegram/VK/MAX; ready проверяет БД/schema; missing required tech secret/config → ясный отказ без dummy secret; trace/errors без токенов/ПД; нет request/customer endpoints |
| F03 | Локальные dev infra Compose PostgreSQL18/S3-compatible, отдельные project name/ports/volumes/network, secrets вне Git; выбранные immutable images | Только согласованные новые ресурсы проекта, ничего из существующих6 контейнеров не останавливается/переименовывается/удаляется. БД/admin endpoints не открыты внешней сети; documented start/stop без down -v как default |
| F04 | Migration workflow/roles+**технические** audit/outbox без customer schema; SQL proof fixtures FK/CHECK/EXCLUDE+same-city/version географии | Fresh/upgrade/replay migrations на PG18; transaction rollback audit+outbox, runtime role не UPDATE/DELETE audit; btree_gist/negative mixed FK/overlap работают; synthetic2 cities не требуют фундаментального ALTER, но это test proof schema, не бизнесмиграции/реальный мультигород UI. Test-only proof schema не скрытое утверждение всех domain migrations |
| F05 | Фоновый технический worker/outbox claim/retry/lease proof с fake sender только в tests (без platform adapters) | Crash before/after tx, bounded retry/fencing, duplicate business test command→один эффект; нет реальных сообщений/внешних токенов/«демоуведомлений» |
| F06 | CI pipeline и reproducibility/security gates, .env.example/README/CHANGELOG, backup/restore runbook+synthetic drill | Actual lint/typecheck/unit+real-PG integration/build checks с сохранённым redacted evidence; зависимости и licenses reviewed, secret scan; DB+objects synthetic backup restored и checksums проверены, не одна инструкция |
| F07 | История Git после согласования безопасного автора/коммиттера и отдельного разрешения на commit | Review index/source/docs, нет личного email/секретов/реальных ПД; approved identity matches effective author+committer, code/docs commits малы и воспроизводимы. **Сейчас commit запрещён**; не скрывать этот gate |

**Вне P01:** Auth/users/role business policy (P02), legal/customer/files/intake UI (P03/P05), каталог/деньги/сметы, WF-R2 approval/реальные заявки/расписание, templates/evidence commands S1 и админка каналов (P07-ADM), Telegram/VK/MAX adapters/регистрации/live calls, production deploy/домен/реальные ПД. Нельзя ради foundation создать все бизнес-таблицы окончательно или seed фиктивный прайс/мастеров. Скелет apps не выдаётся за рабочий функционал, пустой UI не публикуется.

P01 можно разрешить независимо от Q02–Q25, кроме собственных инфраструктурных решений PF01–PF08. Не нужно ждать MAX token, цен, реквизитов, UX макетов или полного legal launch conclusion, если только synthetic данные/закрытая dev среда. Общие69 business acceptance scenarios сохраняются в плане, но **не обязаны пройти на P01**; у F01–F07 свой evidence, не подмена PASS всех69.

## B. Стек и версии — полный exact baseline R3.2

**Дата проверки каждой строки:19.11.2026.** Официальные release/docs/tagged sources и npm registry exact metadata прочитаны read-only; наличие/engines/peers не означает фактически успешную сборку проекта. Все комбинации ниже — **сборочные кандидаты P01**, пакеты не установлены. Список direct dependencies конечный: workspace packages тоже direct, но внутренние (`workspace:*`), не npm latest. Транзитивные зависимости задаются будущим lockfile, не объявляются собственными direct deps. В дальнейшем новый прямой импорт требует отдельной строки exact version/reason/review.

Локально наблюдались Node24.22.3/npm11.19.1/Git2.53.0/Docker CLI29.2.1/Compose5.0.2/Corepack0.36; pnpm/psql отсутствуют в PATH. **Утверждены бизнес-архитектура и направление, не этот набор версий/разрешение installs.**

### B1. Runtime, production dependencies и база

| Direct package / инструмент | Exact candidate / место | Официальный источник (проверен19.11) и rationale |
|---|---|---|
| Node.js | **24.22.3 LTS**, dev/CI/app runtime | [Release](https://nodejs.org/en/blog/release/v24.22.3), [support](https://nodejs.org/en/about/previous-releases). LatestLTS26.13.1 исследован, не выбран автоматически:24 поддерживается и удовлетворяет всем выбранным engines; security patch актуален. Major24 обязателен для выбранной proof matrix, переход26 — новый gate |
| npm | **11.19.1** только bootstrap/metadata, не второй project package manager | [Exact](https://registry.npmjs.org/npm/11.19.1), Node^20.17\|\|>=22.9; локально наблюдался, не нужен dependency manifests |
| pnpm | **12.21.0**, packageManager pin root | [Release](https://github.com/pnpm/pnpm/releases/tag/v12.21.0), [exact](https://registry.npmjs.org/pnpm/12.21.0), [install](https://pnpm.io/installation). Current default stable channel12; native executables Windows/Linux, bootstrapNode>=18. Более новый12.22.0 non-prerelease находится **next-12**, не выбран вместо default stable ([tags](https://registry.npmjs.org/-/package/pnpm/dist-tags)).10.34.9 прежний major больше не baseline |
| next | **16.4.6**, apps/web runtime | [Release](https://github.com/vercel/next.js/releases/tag/v16.4.6), [exact](https://registry.npmjs.org/next/16.4.6), Node>=20.9, React19 peer. Turbopack build, не Vite |
| react / react-dom | **19.3.1 /19.3.1**, web+miniapp runtime | [React release](https://github.com/facebook/react/releases/tag/v19.3.1), [React exact](https://registry.npmjs.org/react/19.3.1), [DOM exact](https://registry.npmjs.org/react-dom/19.3.1), paired peer^19.3.1 |
| @nestjs/core / @nestjs/common / @nestjs/platform-express | **12.5.1 /12.5.1 /12.5.1**, api/worker | [Release](https://github.com/nestjs/nest/releases/tag/v12.5.1), [core](https://registry.npmjs.org/@nestjs/core/12.5.1), [common](https://registry.npmjs.org/@nestjs/common/12.5.1), [platform](https://registry.npmjs.org/@nestjs/platform-express/12.5.1). ESM/Node>=20, common/core peers12; Express5.3.0 transitive exact у platform, не redundant direct если не импортирован |
| @nestjs/config | **12.1.1**, api/worker runtime | [Exact](https://registry.npmjs.org/@nestjs/config/12.1.1), common11/12+rxjs7.1 peers; typed custom config validation P01 без бизнесDTO |
| reflect-metadata / rxjs | **0.2.2 /7.8.2**, api/worker runtime | [Reflection](https://registry.npmjs.org/reflect-metadata/0.2.2), [RxJS](https://registry.npmjs.org/rxjs/7.8.2), обязательные Nest peers. Reflection загружать до decorated classes, CJS export interop проверить |
| @prisma/client / @prisma/adapter-pg | **7.10.1 /7.10.1**, api runtime | [Client](https://registry.npmjs.org/@prisma/client/7.10.1), [adapter](https://registry.npmjs.org/@prisma/adapter-pg/7.10.1), Node^20.19\|\|^22.12\|\|>=24+TS>=5.4; Prisma7 ESM/new generator output+adapter+env explicit |
| pg | **8.23.1**, api runtime+technical DB tooling | [Exact](https://registry.npmjs.org/pg/8.23.1), Node>=16/ESM-CJS; adapter range^8.16.3 удовлетворён, pg-native не нужен; pool/timeouts задавать явно |
| PostgreSQL | **18.7**, `postgres:18.7-bookworm` proposed tag (digest до P01 pull) | [Support/release policy](https://www.postgresql.org/support/versioning/), [Prisma7 supported DB](https://www.prisma.io/docs/orm/v7/reference/supported-databases). Latestmajor19.0 вышел19.11, но еще не выбранная tested ORM/hosting matrix;18 поддерживается до2030. dev/CI/prod одинmajor18, minor security upgrade допустим по gates |

**Логирование P01:** встроенный Nest12 ConsoleLogger JSON+allowlist/redaction ([tagged source](https://raw.githubusercontent.com/nestjs/nest/v12.5.1/packages/common/services/console-logger.service.ts)), без дополнительных logger dependencies. String/error/stack могут содержать ПД даже при path-redact: тестировать safe schema и sanitization, не логировать arbitrary body/secret messages. Pino не нужен foundation и не добавляется по привычке.

### B2. Полный direct dev dependency inventory P01

| Direct dev dependency | Exact | Источник/проверка compatibility |
|---|---:|---|
| typescript | **6.0.3** | [Stable release](https://github.com/microsoft/TypeScript/releases/tag/v6.0.3), [exact](https://registry.npmjs.org/typescript/6.0.3). Обновлён5.9.3; lateststable7.0.2 рассмотрен, см.B4 |
| @types/node | **24.19.2** | [Exact](https://registry.npmjs.org/@types/node/24.19.2), [maintained24 source](https://raw.githubusercontent.com/DefinitelyTyped/DefinitelyTyped/master/types/node/v24/package.json); TS>=5.6, typings24 соответствуют runtime24, не latest26 |
| @types/react / @types/react-dom | **19.3.0 /19.3.0** | [React types](https://registry.npmjs.org/@types/react/19.3.0), [DOM types](https://registry.npmjs.org/@types/react-dom/19.3.0), TS>=5.6, DOM peer react-types^19.3 |
| @types/pg | **8.23.1** | [Exact](https://registry.npmjs.org/@types/pg/8.23.1), TS>=5.6, Prisma adapter range^8.16 удовлетворён |
| prisma (CLI) | **7.10.1** | [Stable release](https://github.com/prisma/orm/releases/tag/7.10.1), [exact](https://registry.npmjs.org/prisma/7.10.1), client/adapter pin тот же. **8.0.0-rc.34 из latest отвергнут** |
| vite | **8.3.8** | [Release](https://github.com/vitejs/vite/releases/tag/v8.3.8), [exact](https://registry.npmjs.org/vite/8.3.8), Node^20.19\|\|>=22.12, ESM/Oxc/Rolldown. Miniapp сборка+Vitest host, не Next bundler |
| @vitejs/plugin-react | **6.3.0** | [Exact](https://registry.npmjs.org/@vitejs/plugin-react/6.3.0), Vite^8 и Node ranges совпадают; ReactCompiler/Babel peers optional, не включаем |
| vitest | **5.1.1** | [Release](https://github.com/vitest-dev/vitest/releases/tag/v5.1.1), [exact](https://registry.npmjs.org/vitest/5.1.1), Node^22.12\|\|^24\|\|>=26, Vite^6.4/7/8; обновляет4.1.12, **единственный основной runner** |
| @vitest/coverage-v8 | **5.1.1** | [Exact](https://registry.npmjs.org/@vitest/coverage-v8/5.1.1), exactVitest5.1.1; включаем для технического coverage/evidence, не dynamic install prompt |
| @nestjs/testing | **12.5.1** | [Exact](https://registry.npmjs.org/@nestjs/testing/12.5.1), Nest core/common12 и runner independent |
| supertest / @types/supertest | **7.3.2 /7.2.1** | [Runtime](https://registry.npmjs.org/supertest/7.3.2), [types](https://registry.npmjs.org/@types/supertest/7.2.1), Node>=14.18/TS>=5.6. Backend HTTP integration в Vitest node project |
| eslint / @eslint/js | **10.15.0 /10.0.1** | [ESLint release](https://github.com/eslint/eslint/releases/tag/v10.15.0), [exact](https://registry.npmjs.org/eslint/10.15.0), [JS](https://registry.npmjs.org/@eslint/js/10.0.1), Node^20.19/^22.13/>=24; latest10 supported |
| typescript-eslint | **8.73.0** | [Exact](https://registry.npmjs.org/typescript-eslint/8.73.0), peers ESLint8.57/9/**10**, TypeScript>=4.8.4 **<6.1**. Уже приносит parser/plugin/utils согласованно, без redundant direct packages |
| eslint-plugin-react-hooks | **7.1.1** | [Exact](https://registry.npmjs.org/eslint-plugin-react-hooks/7.1.1), Node>=18+ESLint10 peer |
| globals | **17.14.0** | [Exact](https://registry.npmjs.org/globals/17.14.0), Node>=18; browser/node/test scopes раздельно |
| @next/eslint-plugin-next | **16.4.6** | [Exact](https://registry.npmjs.org/@next/eslint-plugin-next/16.4.6), [official lint integration](https://raw.githubusercontent.com/vercel/next.js/v16.4.6/docs/01-app/03-api-reference/05-config/03-eslint.mdx). **Standalone**, не полный eslint-config-next. Почему —B4 |
| @aws-sdk/client-s3 / @aws-sdk/s3-request-presigner | **3.1172.0 /3.1172.0** | [Client](https://registry.npmjs.org/@aws-sdk/client-s3/3.1172.0), [presigner](https://registry.npmjs.org/@aws-sdk/s3-request-presigner/3.1172.0), Node>=20. P01 dev/test tooling subset; runtime files adapter импортирует их позднее по тому же reviewed version либо approved update |
| @playwright/test | **1.65.1** | [Release](https://github.com/microsoft/playwright/releases/tag/v1.65.1), [exact](https://registry.npmjs.org/@playwright/test/1.65.1), Node>=20, browser E2E отдельно от Vitest. P01 technical health/UI smoke, business journeys позже |

Это все **выбранные direct P01 npm deps**: root/shared+app runtime groupsB1 и devB2. NestCLI, ts-node/tsx, Jest/ts-jest, SWC, Express standalone, DTO libs, routers/state libraries, S3 lib-storage, Pino/pretty, testcontainers не скрытые обязательные пакеты. Backend build — `tsc` rootTS6.0.3 NodeNext/ESM, startup —compiled Node; не npx/CLI latest. В P01 не нужны workspace генераторы/Turbo/Nx.

### B3. Известные будущие direct deps и infra images

Следующие пакеты **не устанавливаются в P01**, но каждому предполагаемому позднему прямому импорту дана exact reviewed candidate. Перед своим модулем снова проверить security/engines; существование строки не разрешение installs.

| Поздний прямой dependency | Exact / этап | Официальный источник и причина |
|---|---|---|
| @testing-library/react / @testing-library/dom | **16.3.3 /10.4.2**, P08A/P10 UI tests | [React](https://registry.npmjs.org/@testing-library/react/16.3.3), [DOM](https://registry.npmjs.org/@testing-library/dom/10.4.2): Node>=18, React18/19 peers, DOM^10 required |
| @testing-library/jest-dom / @testing-library/user-event / jsdom | **8.0.0 /14.6.13 /31.0.1**, P08A/P10 | [Assertions](https://registry.npmjs.org/@testing-library/jest-dom/8.0.0), [user](https://registry.npmjs.org/@testing-library/user-event/14.6.13), [jsdom](https://registry.npmjs.org/jsdom/31.0.1). Jest-dom name **не** требует Jest: импорт /vitest, peerVitest>=5<6; jsdom Node24>=24.15, наш24.22.3 подходит |
| argon2 | **0.45.2**, P02/Auth, не foundation | [Stable release](https://github.com/ranisalt/node-argon2/releases/tag/v0.45.2), [exact](https://registry.npmjs.org/argon2/0.45.2), Node>=16.17/developer tested22+, Native N-API8 install hook/prebuild Windows/Linux. Argon2id по умолчанию, no @types; P02 allowlist native install+hash/verify tests обязательны |
| class-validator / class-transformer | **0.15.1 /0.5.1**, P02/P03 API DTO | [Validator](https://registry.npmjs.org/class-validator/0.15.1), [transformer](https://registry.npmjs.org/class-transformer/0.5.1), Nest optional peers; foundation config custom validate не требует DTO libs |
| @nestjs/swagger | **12.1.2**, module API/OpenAPI | [Exact](https://registry.npmjs.org/@nestjs/swagger/12.1.2): Nest12, TypeScript^5.5\|\|^6, неTS7; foundation health smoke может без Swagger |
| @types/express | **5.0.6**, если исходник прямо импортирует Express types | [Exact](https://registry.npmjs.org/@types/express/5.0.6), TS>=5.2; runtime Express5.3.0 уже dependency Nest platform |
| @vitest/ui | **5.1.1**, optional DX позднее | [Exact](https://registry.npmjs.org/@vitest/ui/5.1.1), exact runner peer; не prerequisite CI |
| unplugin-swc / @swc/core | **2.0.0 /1.16.22**, **только conditional replacement** backend-test transform | [Plugin](https://registry.npmjs.org/unplugin-swc/2.0.0), [core](https://registry.npmjs.org/@swc/core/1.16.22), [Nest recipe](https://raw.githubusercontent.com/nestjs/docs.nestjs.com/master/content/recipes/swc.md); не baseline, если Oxc metadata proof fails — report/approved substitution, не второй runner |

| Infra / проверено19.11 | Предложение | Официальное evidence и фактический предел |
|---|---|---|
| Docker Compose | Target **5.8.0** stable, локально **5.0.2** можно оставить до upgrade approval | [Release17.11](https://github.com/docker/compose/releases/tag/v5.8.0). P01 использует services/healthchecks/volumes, **не** new jobs requiring Engine29.10+. Engine29.2.1 recorded; команды5.0.2 compatibility prove. Compose update не выполняется автоматически |
| Node runtime image | `node:24.22.3-bookworm-slim` candidate | Exact patch+glibc облегчает compatibility; manifest/digest/architecture/scan фактически проверяются до разрешённого pull/buildP01, сейчас digest не выдуман |
| PostgreSQL image | `postgres:18.7-bookworm` candidate | Official version18.7 verified; same major dev/CI/prod, availability/digest+btree_gist run proofP01 |
| **Local S3** | **Garage2.5.0**, `dxflrs/garage:v2.5.0` candidate | [Release24.10](https://git.deuxfleurs.fr/Deuxfleurs/garage/releases/tag/v2.5.0), [tagged quickstart](https://raw.githubusercontent.com/deuxfleurs-org/garage/v2.5.0/doc/book/quick-start/_index.md), [DockerHub active tag](https://hub.docker.com/v2/repositories/dxflrs/garage/tags/v2.5.0/), [AGPLv3](https://raw.githubusercontent.com/deuxfleurs-org/garage/v2.5.0/LICENSE). Exact local implementation предложена, owner approve license/dev policy; no create/pull now |
| Playwright browser image | **mcr.microsoft.com/playwright:v1.65.1-noble**, matching package1.65.1 | [Tagged Noble Dockerfile](https://raw.githubusercontent.com/microsoft/playwright/v1.65.1/utils/docker/Dockerfile.noble), [Docker guide](https://playwright.dev/docs/docker). MCR exact manifest ответил OCI Accept mismatch, полноценный digest/pull/launch proof не получен. OCI index/digest/architecture проверить P01; нет подмены image1.64.1 под package1.65.1 |

Garage — **dev single-node**, private access-key/bucket grants, не prod provider/не обещание HA. [S3 subset](https://raw.githubusercontent.com/deuxfleurs-org/garage/v2.5.0/doc/book/reference-manual/s3-compatibility.md) содержит SigV4/PUT/GET/HEAD/LIST/presigned/multipart, но bucket policies/ACL/versioning/ObjectLock ограничены/нет. Поэтому P01 contract проверяет denied anonymous/wrong key, PUT/GET/HEAD/list/presigned expiration/content checksum и synthetic export/restore/checksum, не предполагает ObjectLock/versioning. SHA256 сравнивать по фактическим bytes, не ETag как универсальному checksum. Backups: отдельно data+metadata/config/access mapping и restore в изолированном окружении, synthetic only; production РФ provider выбирается позднее и проходит свой subset contract.

**Почему не прежний MinIO по умолчанию:** [official repo](https://api.github.com/repos/minio/minio) archived и [README](https://raw.githubusercontent.com/minio/minio/master/README.md) предупреждает no longer maintained; archived binaries не новый secure baseline. SeaweedFS4.54 maintained, но [critical advisory](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-25hp-4mw7-9c75) имеет нерешённую mapping patched range на дату research, потому не выбран без уточнения security. LocalStack current commercial account/token conditions лишние для локального S3 subset. Это reasoned dev selection, не повторный поиск бизнес-правил MAX.

### B4. Совместимость: что доказано metadata, что проверяется только сборкой

- **TS5.9.3→6.0.3:** выбран новый поддерживаемый JS compiler API path. Lateststable **7.0.2** существует ([release](https://github.com/microsoft/TypeScript/releases/tag/v7.0.2)), но typescript-eslint8.73 требует<6.1 и Swagger12 peersTS5/6. [Next TS7 CLI path](https://nextjs.org/docs/app/api-reference/config/next-config-js/useTypeScriptCli) экспериментальный/not recommended production; [Next16.4.6 compiler-API source](https://raw.githubusercontent.com/vercel/next.js/v16.4.6/packages/next/src/lib/verify-typescript-setup.ts) использует TS^6 API. **Не утверждаем ошибочно, чтоTS7 не умеет decorators**; причина — экосистема/compilerAPI, не отсутствие metadata. NestCLI не нужен; он сам используетTS~6, не надо добавлять второй компилятор.
- **Vitest4.1.12→5.1.1:** актуальный major подходит Node24/Vite8 и будущему jest-dom8(Vitest>=5<6). Один runner projects `node` (backend/shared/PG) и `jsdom` позднее(frontend), Supertest не runner; Playwright real browser отдельно. Jest/ts-jest не нужны и удалены из предлагаемого baseline, не библиотечное дублирование logic.
- **Nest12/Vite8 Oxc:** [официальный Nest12.5.1 config](https://raw.githubusercontent.com/nestjs/nest/v12.5.1/vitest.config.mts) уже использует Oxc `legacy`+`emitDecoratorMetadata`, reflect-metadata setup. Это upstream pattern, **не** passing build проекта. [Vite metadata caveat](https://vite.dev/guide/features#emitdecoratormetadata): частичная type inference. P01 proof constructor+parameter decorators/design metadata/ESM.js imports/Prisma generation и node shutdown; явные DI tokens/factory providers уменьшают dependence on inference. Если Oxc не проходит — conditional SWC pairB3 по отчёту/утверждению, runner остаётся Vitest. Не описывать esbuild default у Vite8.
- **ESLint10:** поддерживаемый10.15, **не downgrade EOL9** ([support table](https://eslint.org/version-support/)). Полный eslint-config-next16.4.6 документирован для10, но transitive react/import/jsx-a11y metadata peers пока<=9. Выбран standalone official Next plugin+JS/TS/hooks/globals без peer override; это **не** полный React/import/a11y preset. UI a11y проверяется component/manual/Playwright, дополнительные rules позже exact reviewed deps; если полный preset обязателен — узкое documented peer exception только по approval+lint fixture proof, не blanket legacy-peer-deps.
- **Prisma7.10.1:** [official release status](https://www.prisma.io/docs/orm/release-status) подтверждает8 покаRC, даже если latest; не ставить RC/не переносить v8 CLI workflow на7. Поддержка7 ещё18 месяцев после8GA;6 security закончилась19.11. ESM/generated output/env config/pg adapter/pool+timeout budget explicit. [Feature matrix7](https://www.prisma.io/docs/orm/v7/reference/database-features) и [custom SQL workflow](https://www.prisma.io/docs/orm/v7/prisma-migrate/workflows/unsupported-database-features): CHECK/EXCLUDE и часть индексов reviewed SQL migrations, Preview не включать по умолчанию, tests на настоящемPG18.
- **Playwright:** matching exact pair и glibc, не Alpine. Upstream image содержит Node26: app production smoke остаётся выбранный24 runtime; тестовый browser runner image Node26 документируется как отдельный test process либо ставится approved24 runner/remote browser. Нельзя считать image проверенным по существованию Dockerfile; actual launch/headless package matching proofP01.
- **Production/dev imports:** API NodeNext ESM, Next/Vite bundler modes раздельные tsconfigs; common contract package не импортирует Prisma/providers/server secret deps в frontend. tsc `--noEmit` отдельный quality gate, Vitest transpile не typecheck. Next build не заменяет отдельный lint. Browser async Server Components покрывает Playwright, не jsdom unit «по обещанию».

### B5. Фиксация и обновление, обязательные pins и заменяемые кандидаты

**Lockfile сейчас не создаётся** по запрету installs/implementation. В разрешённом P01: exact direct versions без^/~, pnpm12.21 в packageManager, один полный pnpm-lock.yaml с integrity/transitive graph; CI только `pnpm install --frozen-lockfile`, lifecycle scripts явным allowlist. Corepack/native pnpm bootstrap scripts/optional binaries на Win/Linux separately reviewed. No `npx latest`, no independent per-app lock, no auto peer override/auto install test prompt. Runtime images — approved digest, архитектура и provenance/scan evidence.

Обязательны для выбранного baseline proof: Node major24/type defs24, pnpm major12+один lock format, TS6(JS API), Nest packages major12 согласованно, React/DOM pair19.3.1, Prisma CLI/client/adapter **одинаковые7.10.1 stable**, PGmajor18, Vitest/coverage same5.1.1, Playwright package/image same1.65.1, no prerelease/Preview. Это requirement proposed candidate set, не запрет обновлений навсегда.

Заменяемые **только по documented compatibility/security proofP01 и approval**: security patch в этих majors, native pnpm patch default stable, Oxc→SWC conditional transformer, optional logger integration/UI kit, exact image digest/OS patch, S3 dev implementation если Garage license/subset не принимается. Нельзя молча выбратьTS7/PrismaRC/ESLint9/другую DB или исключить канал/географию ради passing build. Если владелец явно делегирует patch-resolution, отчёт фиксирует before/after+reason+tests, иначе повторно предъявляется только изменённый version выбор, не owner facts/MAX assumption.

Обновления: отдельный PR dependency graph/lock diff+release/security notes+license/peer/engines review; routine stable patches пакетами одной группы, major — ADR+полная relevant tests matrix. Security critical patch ускоряется, но не обходится compatibility/lock/backup. Exact install resolution не доказан до install, manifests/lock/actual CI — будущий P01, не текущая документация.

## C. Docker Engine: безопасный план, не ремонт вслепую

Текущие [записи окружения](DECISIONS.md#121-доступ-к-docker-engine-из-сессии) содержат успешную внешнюю проверку19.11.2026: Desktop4.61.0, Engine29.2.1 linux/amd64,6 работающих контейнеров. Это dated recorded observation, не заново выполненный сейчас Engine probe. Root перепроверил лишь CLI/Compose versions. Confined DSH не открывает named pipes, поэтому permission denied внутри сессии **не доказывает поломку Docker**.

1. После approval только read-only `docker context show`, `docker version`, `docker info` (узкие server fields) из обычного PowerShell пользователя либо exact approved unconfined command. Не менять context/ACL и не делать restart без доказанной причины.
2. Если сервер отвечает: recovery не нужен; выбрать существующий Linux context (без самовольного переключения), проверить ресурсы/порты и отдельный Compose project name. Не трогать6 существующих контейнеров/volumes/images, не запускать prune/reset/down-v.
3. Если недоступен и вне sandbox: проверить Desktop status/правильный context, WSL version/status и требования Windows virtualization, service state. Пользователь запускает/перезапускает Desktop по отдельному согласию с предупреждением о влиянии на существующие containers. Не включать unauthenticated TCP2375, не менять pipe ACL, не обходить запрет capture/spawn.
4. Установка/обновление WSL/Docker, смена groups/context/startup/network/ресурсов, elevated действия — отдельно согласуемые операции, не чтение/не текущее поручение.
5. Повторяем version/info, фиксируем actual server evidence, затем только разрешённый запуск scoped dev Compose. Контейнерные pulls/builds/run — будущие изменения, не команды текущего preflight.

**Временный вариант, не согласованный по умолчанию:** локальная native PostgreSQL18.7 на отдельной instance/database/service account/loopback port + btree_gist/отдельные migration/runtime roles, synthetic only. CI всё равно Linux PostgreSQL18.7 и реальный S3 contract. S3 dev Garage2.5.0 предложен §B3 и должен быть одобрен/получен в разрешённой среде; успешная native БД не закрывает всё P01, Docker/Linux image build/backup+object restore proof остаётся gate (можно на одобренном remote CI runner). SQLite/in-memory DB не заменяют PostgreSQL integration. Перед native install — approval installer/license/admin/service/path/port/backups/removal plan; ничего не устанавливается сейчас.

## D. CI: варианты и решения владельца

| Вариант | Плюсы | Ограничения / решения |
|---|---|---|
| **Private GitHub + hosted Linux Actions** (рекомендация при допустимости размещения кода) | Стандартный PR/required checks, isolated service containers, no-reply account, простой reproduce | Owner approve private remote/organization/region/code-transfer policy/лимиты расходов, runner/image/action SHAs. Никаких ПД/production/provider credentials. Current hosted runner availability/cost не обещаются |
| **Private GitLab / self-hosted GitLab runner в выбранном регионе** | Контроль хранения кода/runner, возможно РФ размещение | Нужны repository/server/runner owner+budget/security updates/network/секреты; installation/registration не часть docs. Privileged Docker socket на runner требует изоляции/явного risk approval |
| **Согласованный isolated self-hosted runner для выбранного forge** | Контроль ресурсов/региона/доступа к Docker | Не общий Desktop с6 рабочими контейнерами без изоляции. Untrusted PR не получает secrets/docker socket; ephemeral workspace/lease cleanup/maintenance owner |

Proposed pipeline: checkout (minimal permissions) → pinned Node/pnpm → `install --frozen-lockfile` с утверждённой lifecycle allowlist → lint отдельно (Next16 build lint не выполняет) → typecheck → unit → real-PG technical migration/constraints/tx+role tests → S3 contract → builds Next/API/MiniApp → technical smoke/backup restore → artifact+license/dependency/secret scans. Playwright/browser full flows позже, foundation smoke только если scope согласован; package/image совпадают. Cache без credentials, artifacts redacted/time-limited, deploy job отсутствует. Fork PR не использует environment secrets; actions/images pin by immutable reference. CI external network к messenger hosts отключён по необходимости tests.

Owner должен выбрать forge/visibility/region, hosted vs isolated runner, бюджет/квоты, обязательные checks/merge policy, artifact retention и кто управляет доступами. Пока этих решений нет, можно лишь подготовить план; **actual CI evidence не заявлять полученным**. Отсутствие CI конфига сейчас нормально (P01 ещё не начат), не ошибка Этапа0.

## E. Безопасные Git author и committer

Факт: local user.name и user.email заданы; значения личного email не публикуем. Сейчас не меняем global/local config и не создаём commit/remote. Владелец должен отдельно утвердить exact public identity:

1. Предпочтительно хостинг-выданный **точный** no-reply address выбранного аккаунта (у GitHub в настройках email, формат зависит от аккаунта; не генерировать числовой ID из предположения) + согласованный display name.
2. Либо служебный project address, которым владелец вправе пользоваться. Выдуманный robot mailbox не является no-reply и не принимается как факт.
3. Согласовать **оба** author и committer, CI bot identity/commit signing при необходимости. Даже локальный commit с личным email может позднее стать публичным; `.mailmap`, privacy toggle профиля и удаление строки из docs не меняют историю автоматически.
4. Перед первым отдельно разрешённым commit приватно проверить local/effective config и env overrides; в evidence выводить только `configured/matches-approved`, не email. Проверить рабочие docs **и index**: index сейчас содержит предыдущие staged версии, `git diff --cached` нельзя коммитить вслепую; обновление staging/коммит только после approval. Если требуются public privacy cleanup старой уже существующей истории — отдельная задача (сейчас commits0).

Ни «identity существует», ни подготовленный Preflight не закрывают permission на публичные метаданные, commit или push. Текущим поручением они запрещены.

## F. Команды проверки окружения до реализации

Ниже **список на выполнение после разрешения**, не batch, который уже был запущен. Все команды read-only, кроме отсутствующих здесь install/config/container create операций; результаты с PII/connection names редактируются перед публикацией. Из рабочего каталога `C:\LocalAI\fixlevelup`:

```powershell
Get-Location
Get-Command node,npm,corepack,git,docker -ErrorAction SilentlyContinue | Select-Object Name,Source
node --version
npm --version
corepack --version
# pnpm --version только если уже установлен/вне auto-download shim;
# Corepack enable/prepare/use и install НЕ являются проверкой.
git --version
git rev-parse --show-toplevel
git -c core.quotepath=false status --short --branch
git diff --check
# Приватно проверить config/overrides, в общую выдачу — только boolean:
$nameLocal = git config --local --get user.name 2>$null
$mailLocal = git config --local --get user.email 2>$null
$mailEffective = git config --get user.email 2>$null
Write-Output ('local-name-configured=' + [bool]$nameLocal)
Write-Output ('local-mail-configured=' + [bool]$mailLocal)
Write-Output ('effective-mail-configured=' + [bool]$mailEffective)
Write-Output ('author-env-override=' + [bool]$env:GIT_AUTHOR_EMAIL)
Write-Output ('committer-env-override=' + [bool]$env:GIT_COMMITTER_EMAIL)
# Значение remote может содержать credential: не печатать remote -v автоматически.
$remotes = @(git remote)
Write-Output ('remote-configured=' + ($remotes.Count -gt 0))
docker --version
docker compose version
```

Обычный PowerShell пользователя / exact approved unconfined read-only command (не бессмысленные повторы через обход confinement):

```powershell
docker context show
docker version --format 'client={{.Client.Version}} server={{.Server.Version}} os={{.Server.Os}} arch={{.Server.Arch}}'
docker info --format 'server={{.ServerVersion}} os={{.OSType}} arch={{.Architecture}} containers={{.Containers}} running={{.ContainersRunning}}'
wsl --version
wsl --status
Get-Service com.docker.service -ErrorAction SilentlyContinue | Select-Object Status,Name
Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free
# Чтение занятых listening ports, чтобы не выбрать конфликтующий dev port:
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess
```

Если выбран native PostgreSQL и **он уже установлен/доступен**, без создания service/DB/schema:

```powershell
Get-Command psql,pg_isready,pg_dump,pg_restore -ErrorAction SilentlyContinue | Select-Object Name,Source
psql --version
# PGHOST/PGPORT/PGUSER/PGDATABASE задаёт согласованная локальная среда;
# пароль не в командной строке/Git, -w не вызывает интерактивный prompt.
pg_isready -t 5
psql -X -w -c "SHOW server_version;"
psql -X -w -c "SHOW server_encoding;"
psql -X -w -c "SELECT name, default_version FROM pg_available_extensions WHERE name='btree_gist';"
```

Metadata перед будущим install можно читать по exact approved registry URLs из §B (HTTPS JSON), проверив version/engines/peerDependencies/deprecated/license/integrity; `npm install`, `npx`, `corepack prepare`, `pnpm install --lockfile-only`, `docker pull/run/compose up`, `CREATE EXTENSION`, Git config/commit/push **не preflight read-only**. Новые сетевые host/registry/proxy permissions при необходимости согласуются отдельно. Не выводить raw .npmrc/.env/credentials/`docker inspect` env и личные Git identities в отчёт.

## G. Решения, требующие явного ответа владельца

| ID | Требуется утвердить | Рекомендация, не молчаливое согласие |
|---|---|---|
| PF01 | Разрешить **только P01** с scope F01–F07 и запретами §A? | Да, отдельным сообщением после проверки этого документа; current request only docs |
| PF02 | Полный exact runtime/dev inventory §B R3.2, единый Vitest5, TS6/ESM/Prisma7, approved patch-resolution mode | Подтвердить список либо явно делегировать stable patches с reports/peer review, не arbitrary latest |
| PF03 | Разрешить install/lifecycle scripts/build/images в следующем P01, какой registry/network и approvals scripts? | После exact list/security review, pnpm allowlist, не глобальный enable всех scripts |
| PF04 | Разрешённая dev execution среда: existing Linux Docker Desktop с точечными unconfined командами или native PG temporary? | Не ремонтировать живой Engine; сначала узкая read-only проверка. Native PG лишь явная временная альтернатива, не отказ от Docker/CI proof |
| PF05 | Garage2.5.0 dev/AGPLv3/S3 subset+backup contract, exact image tags/digests/ports/project volumes | Явно утвердить кандидат/условия либо заменить reviewed implementation; production РФ provider позже, существующие containers/volumes не трогать |
| PF06 | CI forge/private remote/region/runner/budget/access owner/required checks/retention | Private hosted Linux при допустимости либо controlled isolated runner; не выполнять регистрацию сейчас |
| PF07 | Exact public author+committer name/no-reply или service address, отдельное разрешение staging/первого commit/push | Current local personal email не approval; первый docs/foundation commit только после explicit permission |
| PF08 | Кто принимает F01–F07 evidence и согласует альтернативу при несовместимости/Engine failure? | Владелец+техлид, без автоматического downgrade major/scope |

Самозанятость/РФ-резидентство, равноправие3 каналов/админка, AS-MAX-01 и будущие города одной компании **уже утверждены и не переспрашиваются**. Открыты только реальные city values/coverage/операционные параметры и PF infrastructure/stack/scope. Module choices S1/Q24/Q25 details/деньги/WF/UX и отложенное live MAX подключение **не** prerequisite P01; до их модулей решения обязательны. Повторный полный архитектурный аудит не требуется по заключению Claude и подтверждению владельца. **После отчёта остановиться. Не начинать P01 до явного разрешения.**
