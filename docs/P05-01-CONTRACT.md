# P05-01 — контракт среза: модель, версии, криптография, базовый fence

Срез P05-01 по [P05-PLAN.md v0.4](P05-PLAN.md) §2 (строка P05-01). База: `main 6ac2049`
(поверх `7a60d4c`). Решением владельца 23.11.2026 полный инфраструктурный wiring
launch proof/admission перенесён в P05-01 (все runtime DB-consumers, fail-closed;
P05-03 сохраняет Bridge B поверх защищённой инфраструктуры; миграционные CLI —
отдельный операторский контур). Документ фиксирует реализованный scope, проектные
решения среза и фактические доказательства. Это отчёт о выполненном, не пересмотр плана.

## 1. Scope среза

- **Миграция 022** `20261123000100_request_intake_foundation` (schema profile **S1**), строго
  additive поверх 021: `request_policy_packages`, `customers`, `requests` (агрегат с
  immutable city/intake-версией, workflow/policy FK, `row_version` от БД, generated
  `is_waiting_link` STORED NOT NULL), `request_payload_cells` (versioned ciphertext:
  wrapped DEK + 96-bit nonce + GCM tag + AAD context, отдельная от provenance-строк),
  типизированная история `request_contact/address/appliance/preference_revisions` +
  `request_faults` (fault ID/version + category match + «другая неисправность»),
  `request_events` (append-only, UNIQUE(principal,operation,idempotency_key)), sequence
  `request_public_numbers`. Миграция пуста в data-части; версии и условия
  provisioned тестовым stand.
- **GEO/CFG fence (§5.1)**: единый ключ `(734305,1)`; `BEFORE INSERT OR UPDATE OR DELETE
  OR TRUNCATE FOR EACH STATEMENT` SECURITY INVOKER guards (`geo_cfg_fence_guard`,
  `search_path=pg_catalog`, без EXECUTE у runtime/PUBLIC) на девяти relations:
  business_settings_versions, service_cities, service_city_versions,
  administrative_districts, service_areas, service_area_versions,
  service_area_district_coverage, reference_entries, reference_entry_versions.
  Guard: проверка собственного granted ExclusiveLock в pg_locks (exact two-int key,
  objsubid=2) → реентрантный `pg_try_advisory_xact_lock` → иначе отказ 42501.
  Solo-писатель без fence отказывается сразу (try-lock не выдаёт fence без
  предварительного X; strict-пруф в миграционных тестах).
- **Совместимый writer**: все 15 write-команд catalogCommands берут X первым statement
  `run()` через `lockCompanySettings` (reentrant с cityActivate/SetPrimary/Deactivate);
  `createReferenceEntry`/`publishReferenceVersion`/`archiveReferenceEntry` берут fence
  сразу после assertCallerTransaction; company publisher уже под тем же ключом.
  Порядок «fence до первого domain read/row lock» соблюдён (writer-map фиксировал
  прежние точки входа).
- **Криптомодуль** `apps/api/src/requests/crypto/`: keyring (versioned, PAYLOAD_KEK /
  IDEMPOTENCY_HMAC, active/historical по keyId, missing → отказ), AES-256-GCM
  payload-cipher (random DEK на payload, wrap отдельным AEAD-доменом
  `p05/wrap/v1/...` vs payload `p05/payload/v1/...`, AAD из env/schema/kind/request/
  revision, 60000-byte cap), HMAC-SHA-256 идемпотентности с домен-префиксом
  `p05/idem/v1/` и constant-time compare.
- **WF registry** `apps/api/src/requests/workflow/registry.ts`: pure total
  `decide()` по паре (workflow_version, command, actor, status, type, branch);
  13 строк матрицы §6.1 (CreateCallback/Repair, StartReview, ConvertCallback,
  ChangeDetails, RecordCoverageAssessment, ChangeContact, ChooseCallback (F-only),
  WithdrawPhonePermission, ReadyForDispatch PHONE/MESSENGER (AWAIT_DEPENDENCY P07),
  CancelRequest F/S). Неизвестная версия → DENIED(UNKNOWN_WORKFLOW_VERSION).
- **Readiness-предикат S1** `RuntimeDatabase.requestIntakeReady()`: SHA-256
  fingerprint 022-объектов (таблицы/колонки/constraints/indexes/triggers/тела
  guard-функций + точные grants + sequence ACL) с пиннингом exact hash; отдельный
  гейт, legacy-readiness от него не зависит (по образцу P04).
- **Launch proof §7 + admission** `apps/api/src/infrastructure/admission/`:
  подписанный Ed25519 proof (issuerGeneration, launchNonce, consumerKind, instanceId,
  channelId, artifactDigest, targetIdentity, profile, historyManifestDigest,
  physicalContractDigest, witness, expiresAt), контрольный реестр
  `launch_control.launch_proofs` с guard-переходом ISSUED→CONSUMED (одноразовый CAS,
  immutability), witness session-lock (отдельный namespace 557001, не 734305/77304),
  admission gate с per-connection проверкой (exact DB/OID/role/schema + live witness).
- **Restore guard §5.3** `apps/api/src/files/file-restore/p05-inventory.ts`
  + `p05-attestation.ts` + интеграция в `rescrub.ts`: закрытый перечень
  P05-таблиц, `P05_EMPTY_AFTER_DRAIN` / `P05_SCHEMA_ABSENT_AFTER_DRAIN` /
  `PARTIAL_SCHEMA`-отказ; source-bound trusted callback `readP05SourceState`
  вызывается на обоих handoff'ах (pre-copy и внутри pre-ACTIVE транзакции) с
  разными challenge-nonce; манифест-профиль — ТОЛЬКО REVIEWED HEADS (S0: ровно
  021 `20261122000700_catalog_management`; S1: ровно 022), любой другой head
  (ранний неизвестный, поздний неизвестный, malformed) → RESTORE_AUTHORITY;
  TARGET-факт сверяется с профилем манифеста (S0→SCHEMA_ABSENT, S1→EMPTY) на
  обоих вызовах; любое несоответствие → RESTORE_AUTHORITY (не RESTORE_CLOSED).

## 2. Проектные решения среза (в границах плана)

- **PHONE events, submit edge, receipts, attachments, RBAC P05-codes — НЕ в S1**:
  переносятся в S2/S3 по §2 (submit-edge «добавляются/активируются в 03», CITY-коды
  RBAC с bridge — S3). S1 не открывает routes и не добавляет permissions.
- **`public_number`** — bigint из sequence `request_public_numbers` (стабильный
  идентификатор; форма отображения — забота DTO будущих срезов).
- **Current-указатели** requests→истории — composite FK (id, rev_id)→(request_id, id)
  + UNIQUE(id, rev) на стороне requests: mixed-parent невозможен на уровне FK.
- **payload read-grant** runtime — только метаданные колонок (id, request_id, kind,
  revision, key_id, created_at): байты шифротекста runtime в S1 не читает; INSERT
  полный. Расширение read — с первым decrypt-consumer (P05-03).
- **admission wiring** (решение владельца 23.11.2026): полное инфраструктурное
  подключение launch proof ко ВСЕМ runtime DB-consumers выполнено в P05-01 (см.
  §1 и §3); P05-03 сохраняет Bridge B (ролевой writer, retention interlock,
  предметная интеграция) поверх этой защищённой инфраструктуры — без повторной
  реализации или альтернативного механизма допуска. Миграционные CLI
  (staff-bootstrap/staff-recover) — отдельный операторский контур, не гейтится.
- **Симвметричная правка пруфов 013/014** (trigger count ±2 fence-триггера на
  reference-таблицах, по имени и функции) и хардкода длины цепочки в issuer-пруфе
  021 — задокументированная S1-дельта, не ослабление: все прочие сверки byte-exact.

## 3. Доказательства (выполненные прогоны)

- Baseline §5.1 до DDL: `apps/api/tests/p05-baseline-locks.test.ts` — 6/6 PASS на
  изолированном 021 (оба порядка fenced writers, unfenced city publish gap,
  независимость ключей 734305/77304, rollback-вариант, pre-guard факт direct DML;
  capped-021 S0-evidence, не S1-пруф).
- Миграционный оркестратор `pnpm run db:test-migrations` (полный exit 0): вся
  цепочка 001–022 fresh/upgrade/replay/drift, 334 CHECK, + пруфы 022: inert
  start, колоночные grants, строгий fence (соло-отказ, writer/reader-first,
  fenced pass), guards (DELETE/identity/intake-policy immutable/payload
  same-request FK/row_version), v1-создание с указателем одной транзакцией
  (deferred FK, row_version=1), district: same-city current-revision, partial
  pair отказ, non-current отказ, foreign-city отказ, rename-after-history НЕ
  блокируется (id-FK + recorded-version provenance), appliance: live-published
  category/model, model-pair CHECK, model-category guard, faults:
  category-match + live + «другая».
- Readiness S1-гейт: `runtime-database.test.ts` — позитив + 14 негативов
  (disabled legacy fence trigger, no-op fence body, disabled requests_guard,
  CHECK(true), GRANT DELETE, PUBLIC SELECT (P05), dropped fence trigger,
  UNLOGGED persistence, runtime GRANT UPDATE (P05), runtime GRANT TRUNCATE
  (fence relation с уже выданным DELETE — индивидуальные привилегии в
  fingerprint), PUBLIC SELECT на fence relation, third-role column SELECT на
  ciphertext через уникальную NOLOGIN probe-роль, runtime GRANT
  UPDATE(display_name) на fence relation service_city_versions, upgrade
  существующего DELETE до WITH GRANT OPTION на fence relation — grantability
  per-privilege в fingerprint); fingerprint включает relpersistence, raw
  sequence ACL, индивидуальные table-привилегии (5
  отдельных boolean), table+column ACL для всех 19 relations, PUBLIC ACL
  (relacl+attacl) на 19 relations, third-party ACL, fence_column_grants.
- Юнит WF: независимый литеральный статус-инвентарь (19) + сверка с рантаймом;
  39 600 клеток, CreateRepair F/S split; policy-pair classifyPolicyPair:
  historical vs current, unsupported vs stale-ETag (503 ≠ 412), двухпакетный
  сценарий с изъятием historical.
- Крипто: 35 тестов — length-prefixed AAD (неоднозначность компонентов
  исключена), wrap AAD связан с kind/revision (same-request cross-kind и
  cross-revision DEK swap отказ), wrap-domain diagnostic
  (unwrapDekForProof: неверные kind/revision/request падают на unwrap-этапе
  независимо от payload-домена), границы 16/59984/59985/60000
  (SQL-min-aligned), кросс-purpose материальное переиспользование запрещено,
  rotation bound 2^20, HMAC.
- Admission: 16 тестов на реальном PG с ОТДЕЛЬНОЙ одноразовой control DB
  (fixlevelup_p05_control_*), выделенным control-OWNER (fixlevelup_p05_ctlowner_*,
  НЕ application migrator — CONNECT migrator/runtime отказан) и launcher-ролью
  (LOGIN; USAGE + SELECT/INSERT + UPDATE(state,consumed_at) только; DELETE/
  TRUNCATE/DDL/guard-EXECUTE → 42501; launch_control отсутствует на app-БД);
  полная обязательная привязка AdmissionBinding (endpoint, generation, nonce,
  consumer, instance, channel, три digest, witnessHolderPid) с per-fact
  mismatch тестами; expires_at в строке, synchronous_commit=on, concurrent
  consume single-winner.
- Admission WIRING (решение владельца, перенесено в P05-01): все 5 runtime-пулов
  (RuntimeDatabase+PrismaPg, web-auth, telegram-auth, authz, outbox-store)
  создаются через GuardedPool (Proxy над реальным pg.Pool; проверка на каждом
  acquire; провал → release(true) + типизированная AdmissionRequiredError,
  детали драйвера не протекают). LAUNCHER-ПРОТОКОЛ §7 (child НИКОГДА не
  потребляет свой proof): entrypoints api.ts/worker.ts грузят
  loadRuntimeAdmission из LAUNCH_* env (consumer-kind: api только API-proof,
  worker только WORKER-proof; endpoint факт == host:port конфигурации;
  digest DERIVED из верифицированного токена — proofDigestOf(payload), не из
  env), затем admitProcess: (1) live-верификация witness+binding на реальном
  соединении + ТОЧНЫЙ PHYSICAL PROFILE (S1 → requestIntakeReady fingerprint,
  S0 → legacy ready) на guarded-соединении; (2) handshake по приватному
  IPC-каналу (process.send) к launcher'у; launcher (launcher.ts,единственный
  владелец control-credentials) сверяет handshake с ДОВЕРЕННЫМИ ожиданиями
  (ExpectedChild: instance/nonce/consumer/digest — не self-reported факты),
  затем witness-гейт, одноразовый CAS ISSUED→CONSUMED, привязанный к
  digest+consumer+instance+channel верифицированного токена (expiry из
  строки), post-COMMIT witness re-check + DB-clock expiry re-check
  (clock_timestamp < expires_at строки), и шлёт РОВНО один approve
  победившему child с bounded ожиданием activation ACK; (3) child принимает approve
  (связанный с его instance+nonce), делает финальную live witness + DB-clock
  проверку непосредственно перед стартом и шлёт activation ack. Без
  приватного канала (standalone) → admission_denied, ни листенера, ни тика.
  Witness-ключ PER-INSTANCE (sha256(instanceId) в namespace 557001).
  createApi/createWorker/ModuleRegister бросают ConfigurationError без
  admission; web-auth cleanup-таймер стартует только после whenAdmitted.
  Тесты: requests-admission-wiring.test.ts 10/10 (loader + consumer-kind +
  factories + guarded pool/Prisma + launcher-протокол: drift-профиль
  отказывает до handshake и CAS; winner допущен ровно одним approval + ACK;
  forged-instance → BINDING-отказ без DB; replay проигрывает CAS без
  approval; dead-witness child отказывает на первой live-проверке, строка
  остаётся ISSUED); compiled.test.ts: standalone-entrypoint →
  admission_denied, started недостижим.
- Launcher E2E на РЕАЛЬНЫХ скомпилированных child-процессах
  (launcher-harness.ts): parent = launcher (держит witness, выдаёт
  one-time row, отвечает на handshake production decideLaunch по настоящему
  Node IPC), child = реальный dist/bootstrap/{worker,api}.js. Доказано:
  worker- и api-entrypoint достигают `started` ТОЛЬКО после single approval
  + activation ACK, затем чисто гаснут по SIGTERM (shutdown_completed, exit
  0, без утечки credentials); child с испорченной доверенной привязкой
  launcher'а → production decideLaunch отказывает на BINDING-гейте без DB
  (admission_denied, строка остаётся ISSUED); ProcessAuthorization-граница
  IDENTITY-BOUND (WeakMap marker↔admission; validateAuthorization на каждой
  DB-consumer границе): offline RuntimeAdmission структурно не принимается,
  marker в паре с ЧУЖИМ admission отклоняется, скомпилированный wrapper-
  shape (JS-caller) отклоняется factories; launcher: ExpectedChild пиннит
  instance/nonce/consumer/digest/issuerGeneration/witnessHolderPid/channel,
  bounded ACK (silent child → approved:unacked); physical profile ПОЛОЖИТЕЛЕН
  в обе стороны (S0 = legacy ready + P04 catalog + отсутствие всех объектов
  022 через preIntakeProfileAbsent; damaged-022 — не профиль вообще).
- Old-binary rollback floor (план §7, пара 3): p05-old-binary-s1.test.ts —
  detached worktree ровно 7a60d4c5a84a… компилируется текущим TypeScript;
  старый areaCoverage writer на изолированной S1-БД получает 42501 'GEO/CFG
  basis writes require the unified writer fence' на первом DML (DELETE),
  транзакция abort (25P02), ноль строк coverage/receipt/audit/outbox;
  положительный контроль — текущий fenced writer коммитит ровно одну строку
  на тех же данных. Компилированный старый код проверен на отсутствие fence
  и наличие старого SQL.
- Restore guard: p05-inventory (0/partial/full + PARTIAL_SCHEMA отказ),
  attestation fact⟺profile; rescrub: trusted callback readP05SourceState на
  обоих handoff'ах (разные challenge-nonce, факт/профиль сверяются с точным
  REVIEWED профилем манифеста — unreviewed head → RESTORE_AUTHORITY; цель
  также проверяется с equality факта) — активация с P05-строками или
  профилем-несоответствием невозможна. 10/10 на реальном PG (включая
  target-mismatch S1/S0 и S0/S1 с RESTORE_AUTHORITY, epoch non-ACTIVE,
  CONNECT withheld, и mutation-proof: удаление сравнения ломает тесты).
- S3 restore E2E: file-restore.test.ts 1/1 на реальных Garage+ledger — полная
  цепочка на S1-профиле (022), source-callback выполнился на обоих handoff'ах
  с двумя различными challenge (assert в тесте).
- Регрессия: все затронутые suites зелёные (management-runner reference-fence
  до первого чтения references; фикстуры под fence).
- S1 hash pinned: `6626dcc51bf6f5c59da82b1d1d5e05e55bb7757d77ce9963d1b182d90d3dde27`
  (fingerprint включает 10 таблиц + 9 fence-relations: owner/kind/persistence/
  RLS, колонки, constraints, indexes, триггеры, тела guard-функций, колоночные
  grants (10 P05) + fence_column_grants (9 fence-relations), индивидуальные
  table-привилегии (5 отдельных boolean), PUBLIC ACL (relacl+attacl) на 19
  relations, third-party ACL, raw sequence ACL).

## 4. Ограничения / переносы

- P05-03 Bridge B (ролевой writer для P05 codes, retention interlock, предметная
  интеграция) строится поверх защищённой инфраструктуры допуска этого среза.
- Полная подпись P05-аттестации в records.ts authority record (интеграция
  attestation в подписанный authority) — с операторским handoff Bridge B в
  P05-03; здесь source-bound callback + reviewed-profile + target equality.
- Session-lock→xact-фиксация fence: SHOULD (не блокирующий) — приложение
  использует только xact-API; session-lock holders конвертируются guard'ом.
- Рабочие миграции/деплой не выполнялись; изолированные одноразовые БД
  p017a_*/p05_check_* созданы и оставлены (retained) как в прежних срезах.
