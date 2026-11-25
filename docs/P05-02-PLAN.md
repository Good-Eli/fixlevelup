# P05-02 — рабочий план среза

Внутренний план координатора. Не меняет [P05-PLAN.md](P05-PLAN.md) v0.4 и не является отчётом о приёмке.

## База

- HEAD `8a3e316` — owner-approved preflight поверх `f2caab0`.
- Preflight-коммит фиксирует историческую приёмку P05-01. Сводные документы актуализированы по отдельному поручению владельца; это не приёмка P05-02.
- Миграции 001…022 побайтно неизменны.

## В scope

Изолированный контур F до submit. Клиентов, заявок, submit-edge, receipts, phone events, staff routes и callback/repair HTTP **нет** — это P05-03/P05-04.

1. **Схема S2** — новая миграция `20261124000100_form_session_foundation` (023), только additive:
   - `foundation.form_browser_groups` — opaque group id, SHA-256 secret hash, DB `created_at`/`expires_at`. Нет PII, нет cookie value.
   - `foundation.form_session_group_memberships` связывает группу с `foundation.request_sessions` из 013. Селектор, хеш секрета, сроки и отзыв принадлежат одному существующему якорю; второй якорь не создаётся. Срок якоря не превышает срока группы.
   - `foundation.form_throttle_buckets` — bounded счётчики source/global/per-F: kind, key hash, window, count. Не policy и не PII.
   - CSRF **не** хранится строкой: stateless HMAC (`P05_F_MUTATE`) от selector+secret+expiry. Durable CSRF-таблица не нужна.
2. **Readiness S2.** `formSessionReady()` проверяет метаданные и действующие ограничения 023. Для допуска на S2 дополнительно нужны точные legacy/P04 и S1. Таблицы 023 не входят в базовый отпечаток 022.
3. **Restore.** На S1 в инвентаре десять таблиц 022, на S2 — те же десять и все три таблицы 023. Любая строка в инвентаре блокирует файловое восстановление. Пустое состояние сверяют на закрытом источнике до чтения полномочий и ещё раз перед активацией цели. Полная подпись дополнительных полей P05 относится к Bridge B в P05-03.
4. **HTTP** (Nest, тестовая композиция), префикс `/api/v1`:
   - `POST /public/form-session/browser` — `{}`; same-origin; выдаёт или подтверждает `__Host-fixlevelup_fgroup`.
   - `POST /public/form-sessions` — `{}`; требует доказанную group cookie; выдаёт `__Host-fixlevelup_f_<uuid>` + `X-Form-Session-Id` + CSRF; city из SINGLE_CITY resolver, не из body.
   - `POST /public/form-session/csrf` — read-only reissue для живой своей F; не продлевает anchor.
   - `POST /public/form-session/revoke` — закрывает proof; повтор без disclosure после expiry/revoke.
   - `GET /public/legal-documents/{kind}` — только текущие опубликованные REQUEST_PROCESSING `POLICY`/`CONSENT_FORM`.
   - `POST /public/form-session/consents` — GIVEN/REVOKED через существующие legal ports; только REQUEST_PROCESSING.
   - `POST /public/coverage/check` — district id того же city; ответ только `AREA_REVIEW_REQUIRED` и подсказки. Никогда `IN_ZONE`. Адрес в сыром теле — отказ, не проверка адреса.
5. **Протокол §4.1.** Caps: 4 живых F на group, ≤8 cookies префикса `__Host-fixlevelup_f_`, Cookie ≤8 KiB до parse. Source/global/per-F лимиты — configured test budgets, без живых default. Origin exact, no CORS, duplicate security headers → отказ. No-store на всех ответах. `Max-Age` по DB TTL; DB clock — власть. Revoke/точная просроченная cookie → `Max-Age=0` только ей. Staff/CRM/TG bearer и F-proof в body не принимаются как F.

## Вне scope (записать, не делать)

Submit, callback, repair, request-session GET, phone, cancel, staff bridge, OpenAPI typed client всего P05, RBAC codes и точная оценка покрытия. Отдельная актуализация сводных документов не расширяет границы реализации.

## Зависимости

Схема S2 → readiness hash (после реального прогона) → HTTP, который пишет в эти таблицы → HTTP-тесты. Контракт ошибок и DTO можно писать параллельно со схемой, не трогая её файлы.

## Критерии приёмки среза

Реальные HTTP+PG: живой/чужой/revoked/expired anchor, две вкладки, caps, Origin/CSRF, duplicate JSON, no-store, смена city/version и live document во время ожидания, PII/адрес до согласия не обрабатываются, безопасные ошибки. Клиенты и заявки не создаются.
