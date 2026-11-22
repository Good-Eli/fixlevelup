# P03-04 — приватные файлы и приватность: план и границы

P03-03 принят владельцем 21.11.2026 и зафиксирован локально как `9116812e6dfa8f4f506b34d66d1382e1efde1096` (48 файлов, без push). Поручение начать следующий подэтап дано отдельно. До реализации по прямому запросу владельца план проверил субагент `plusvibe/gpt-6.2-astra`, reasoning high. Ревью было read-only; это техническая проверка плана, не приёмка кода и не согласование Q02/Q12/Q13/Q16.

**Текущий статус (22.11.2026):** A принят (`7d92122`), B1+B2 приняты и опубликованы (`e44fae8`), C/D/E приняты владельцем и зафиксированы в `dd87cb4` (полный Astra A→E — PASS, 22.11.2026); [актуальный статус P03-04 и evidence](P03-04CDE-CONTRACT.md#6-current-status-and-evidence). Владелец разрешил commit/push после полного Astra A→E и поручил остановиться после GitHub; P03-05 не начинать. Весь P03-04 принят владельцем во внутреннем synthetic scope; P03 — 80% (4 из 5 приняты).

## Итог проверки Astra

Первый synthetic срез допустим до выбора scanner/численных production квот: **резервирование без передачи байтов**, без новых зависимостей, HTTP и IO. Отсутствие policy останавливает операцию до создания intent; отсутствие scanner позднее оставляет уже принятый объект в карантине. Эти отказы нельзя смешивать. Первый срез не завершает весь P03-04.

Обязательные поправки к полному плану:

1. Один порядок блокировок, явный READ COMMITTED до data access и повторная проверка DB clock/основания после последней блокировки. Intent привязан к точному GIVEN и версии документа; `GIVEN → REVOKED → GIVEN` не оживляет прежнюю попытку.
2. DB lease не отменяет внешний PUT. Каждый raw/sanitized PUT получает предварительно зарегистрированный новый immutable attempt key. Старый PUT, пришедший после DELETE, не становится выдаваемым объектом; физическое удаление нельзя объявлять завершённым до повторной сверки неопределённых записей. Timeout/403 не равно «объект отсутствует». Hold и необратимое удаление должны иметь явную точку сериализации.
3. Граница stream revoke — допуск одной bounded порции к отправке: после committed revoke следующая не допускается, но уже допущенная может быть доставлена позже. Ни locks, ни DB connection не удерживаются на медленном network send. Metadata/status проверяются не слабее содержимого. Signed URL не выпускается до решения Q12/TTL.
4. Restore использует старый согласованный DB+objects snapshot и отдельно актуальный ledger с проверяемой границей полноты; ledger внутри старого backup недостаточен. Без полного ledger выдача после restore закрыта. Это file-specific proof, не уничтожение всех ПД/резервных копий.

## Последовательность P03-04

| Срез | Что реализуется | Что блокирует переход / доказательство |
|---|---|---|
| **A — intent/reservation** | Migration 014, реальные FK владельца, обязательная typed policy, точный consent basis, идемпотентность/квоты, закрытый internal API | Fresh/013→014/replay/drift, чужой/revoked/expired proof, последний слот/байты конкурентно, audit/outbox rollback. Ни byte IO, ни READY, ни выдачи |
| **B — upload/quarantine** | Реальный private S3 adapter, bounded streaming, immutable зарегистрированные attempt keys, проверка actual bytes/hash, safe finalize | Отдельно согласованные runtime зависимости/конфигурация; crash/orphan/late PUT proof, не HEAD/ETag как checksum |
| **C — processing/access** | Реальный fail-closed scanner, resource-limited decoding/sanitization, verdict exact served bytes, backend stream reauthorization | Явный synthetic профиль: JPEG/PNG/WebP без анимации — единственные кандидаты на READY, PDF остаётся в карантине, видео не допускается. Live formats/resources/engine ops требуют отдельной политики. No fake production scanner. EXIF/size/signature/slow-stream/revoke tests |
| **D — delete/restore** | File-specific retention/hold/delete checkpoints/ledger и isolated restore/rescrub | В synthetic профиле — отдельный ledger и monotonic floor, copy-only restore с текущей authority; Q13 durations/owner/production completeness остаются открытыми; late PUT/delete/hold race. Полные privacy cases/customer/finance jobs остаются P13P |
| **E — интеграция/приёмка** | Full migration+PG/S3 tests, lint/typecheck/build/security и документация | Только реально пройденные пути; P03-04 не закрывается одним срезом A |

Публичная F-сессия/intake — P05; staff management HTTP/CRM — P03-05. Здесь нет новых UI/capability grants. Не создаются `request_files/diagnostic_files/report_files/message_files` без реальных parent tables (они появятся на своих этапах). Существующие identities — `request_sessions` и `staff`, не несуществующая `users`.

## Срез A: исторический интерфейс принятого среза (21.11.2026)

### Ограничения

Только internal synthetic-ready механика. Никакого чтения/записи S3, scanner, sanitize, download, stream ticket или production activation. Никаких dependency/lockfile/image изменений. Новых production квот, TTL, retention duration не задаём; все численные значения в тестах — явно synthetic fixtures. Если policy отсутствует/неполна — `NOT_CONFIGURED`, **до любых intent/audit/outbox INSERT**.

В этом срезе реализован только F-owned reserve: реальный raw session proof + текущее согласие `REQUEST_PROCESSING`. Staff-owner FK присутствует в схеме для будущего workflow, но reservation port явно отказывает staff-варианту (`UNSUPPORTED_OWNER`) до отдельной команды с настоящей авторизацией; staff id из body не credential. Это не обход проверки прав через «доверенный UUID».

### Таблица `foundation.file_upload_intents` (migration `20261121000500_file_upload_reservations`, 014)

Поля: `id uuid PK`, `owner_request_session_id uuid nullable FK request_sessions`, `owner_staff_id uuid nullable FK staff`, XOR exactly-one; `consent_record_id uuid nullable`, `consent_document_version_id uuid nullable`, `consent_purpose varchar(32)` = REQUEST_PROCESSING для F; `policy_version_id uuid NOT NULL`, `policy_source_ref text NOT NULL`, `policy_sha256 varchar(64) NOT NULL`, `allowed_mime_types jsonb NOT NULL` (bounded closed known MIME vocabulary: application/pdf, image/jpeg, image/png, image/webp; не разрешение реальной загрузки), `max_file_bytes bigint`, `max_owner_bytes bigint`, `max_owner_files integer`, `policy_expires_at timestamptz`, `declared_mime varchar(100)`, `declared_bytes bigint`, `expires_at timestamptz`, `created_at timestamptz default clock`, `idempotency_key uuid`, `body_sha256 varchar(64)`, `state varchar(16)` строго RESERVED/CANCELLED, `cancelled_at nullable`, `row_version integer default1`.

Consent принадлежит тому же session/version/purpose и является GIVEN: composite FK target на consent_records `(id,session_id,document_version_id,purpose)` + trigger. Для staff consent refs NULL; для F refs/purpose обязательны. Identity/owner/policy/declared bytes/mime/idempotency/hash/expiry стабильны. Единственный mutable переход RESERVED→CANCELLED со stamped DB clock, row_version OLD+1; UPDATE иных полей/DELETE/TRUNCATE запрещены. `created_at` и initial state/version задаёт БД. Partial unique owner+idempotency indexes (session/key и staff/key). Нет key объекта и нет file READY: до первой внешней записи срез B добавит реальную зарегистрированную attempt/key структуру, а не фальшивую готовность.

Policy snapshot хранится полями, не произвольным settings JSON. Поля целые положительные safe bounded значения; bytes bigint в БД, в JS допустимы только safe integers. `declared_bytes <= max_file_bytes <= max_owner_bytes`, допустимый MIME входит в snapshot allowlist, `created_at < expires_at <= policy_expires_at` и `expires_at <= owner session expires_at`. Точное hash рассчитывает сервер из canonical typed snapshot/input, без токена и без raw PII. `policy_sha256` от canonical policy snapshot; idempotency payload включает policyId/hash/mime/bytes/expiry + точный basis. Хеши не являются полномочием.

### Internal ports `apps/api/src/files/reservations/`

- `reserveFileUpload(client, {session:{sessionId,token}, policy, declaredMime,declaredBytes,expiresAt,idempotencyKey})`.
- `readFileUploadIntent(client,{session,id})` — тот же proof/basis/liveness и safe DTO без токена/хеша секрета/базы юридического текста.
- `cancelFileUploadIntent(client,{session,id,expectedVersion})` — owner proof и live anchor, однонаправленный CAS; отмена не требует нового согласия и не удаляет доказательство. Только minimal receipt intentId/CANCELLED/rowVersion/cancelledAt/replayed, не read metadata и не доступ к файлу.

`policy` — обязательный closed typed object из trusted reviewed configuration (не публичного запроса): versionId/sourceRef/allowedMimeTypes/maxFileBytes/maxOwnerBytes/maxOwnerFiles/expiresAt. В приложении нет default policy. Неподдерживаемый owner/purpose/MIME/input/нечисловая квота отклоняется. Runtime validation выполняется самим port, parser нельзя забыть.

Порядок reserve/replay/read: legal RC guard → `request_sessions FOR UPDATE` + raw secret proof → `legal_documents FOR UPDATE` через `currentPurposeConsent` → existing owner intent row при read/replay → recheck clock anchor/policy/intent expiry после последнего ожидания → проверить **точный GIVEN** и current document (не любое позднее согласие) → quota sum/count → INSERT/receipt+audit+outbox. Session lock сам сериализует все owner reservations и consent revoke; отдельный quota mutex для F не нужен. Нет обратного file→session lock. В revoke порядок прежний session→document.

Quota: считаются только state=RESERVED и expires_at>DB clock, включая pending reservations; идентичный replay не расходует вторую квоту, изменённый input под тем же owner/key даёт `IDEMPOTENCY_CONFLICT`. Для новых intent все активные reserved bytes/count сравниваются с переданной policy snapshot (новая более строгая policy может блокировать новые intent, но не переписывает старые). Replay после committed revoke не возвращает успех; revoke→new GIVEN не перепривязывает старый intent. Expired/cancelled intent не оживляется. NO IO/READY/access ports в срезе A.

Read/replay должны брать те же auth/basis guards, не выдавать existence oracle чужому owner; одна безопасная typed NOT_FOUND для missing/foreign. Read exact bound policy/source ids и rowVersion, не object credentials. Audit/outbox только ids/state/bytes/enum, без токенов/текста/имён/ссылок. Ошибка audit/outbox откатывает intent вместе с caller transaction.

DB guard является второй линией: F insert отказывает не-READ-COMMITTED транзакции, проверяет live session/current doc/exact unrevoked GIVEN, DB clock и quota под session→document locks; duplicate idempotency/owner quotas enforcement независимо от TS. Triggers SECURITY INVOKER fixed search_path, no public/runtime EXECUTE; runtime column SELECT/INSERT и UPDATE(state) только, no delete/truncate, narrow privileges. Guard не принимает CALL client READY.

### Разделение записи и evidence

1. schema agent — Prisma + migration014.
2. application agent — `apps/api/src/files/reservations/**` и unit tests input/hash.
3. integration agent — `apps/api/tests/file-reservations*.ts`, real PG fixture и concurrency tests.
4. DB-proof agent — migration chain/fixture inventory, new independent `test-file-reservations-migration.mjs`; проверка ACL/fresh/upgrade/replay/drift, без лишнего копирования огромного readiness каталога.
5. lead — интеграция, ревью, docs/final gate. Пишущие scopes непересекающиеся, shared contract выше.

### Приёмочные тесты среза A

- Нет policy/пустой allowlist/невалидные квоты: ноль новых intents/audit/outbox.
- Чужой token/session/id, expired/revoked anchor, нет consent/stale doc/revoked GIVEN: deny.
- Два соединения конкурентно занимают последнее место и последние bytes: ровно один committed success. Pending учитывается, одинаковый replay — одна строка и одна audit/outbox пара.
- Idempotency key тот же + изменённый payload: conflict; replay проверяет текущий proof и точный старый basis; revoke→new GIVEN не оживляет intent.
- После ожидания document lock либо owner/file lock — DB clock expiry не пропускает запись/чтение.
- Статус нельзя сменить на READY/другой owner/expiry/policy; DB-owned row_version, one-way cancel; snapshot и FK отрицательные сценарии.
- Audit/outbox failure/ROLLBACK — никаких partial reservations.
- Fresh, populated 013→014, capped replay/history/drift, runtime ACL; все прежние proofs остаются применимы на своей capped версии.
- Full PostgreSQL Vitest/lint/typecheck/production builds/secrets/diff на неизменном source snapshot; рабочая dev БД не мигрируется.

## Открытые live-решения (не закрыты synthetic реализацией)

- **Q02/Q16:** основания/момент сохранения вложений; типы/фото/видео/документы, квоты и resource limits, реальные scanner/базы/ops/обновления; runtime SDK и image-processing зависимости. Не импортировать транзитивный Sharp как неявную прямую dependency.
- **Q12:** staff/request/assignment окно, политика metadata и chunk-admission revoke; signed URL только при отдельном TTL/разрешении. Staff-owned upload не означает право мастера на заказ.
- **Q13:** retention/orphan/quarantine horizons, hold и irreversible delete point, актуальный durable ledger вне откатываемого backup и полнота, rescrub/reopen approval, реальные тексты/оператор/РФ-hosting/PII.

Без этих решений не открываются production, реальные ПД и публичные файлы. Реализованный internal F-путь не регистрирует HTTP/DI, signed URL, staff grants или customer intake. После copy-only restore чтение/удаление ограничены скопированными объектами; новые B/C записи требуют исходной epoch 1 (legacy B без runtime row допускается на полной схеме). Не добавляются placeholders parent records, новые business defaults или разрешение реальных ПД.
