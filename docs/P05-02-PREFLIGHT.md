# P05-02 preflight: admission ISSUED-proof lifecycle

Владелец 24.11.2026, пункт 4 preflight. Модель жизненного цикла proof-строк
`launch_control.launch_proofs` (P05-01, commit f2caab05). Проверено чтением
registry.ts/launcher.ts/process-admission.ts; нарушение одноразовости НЕ
обнаружено — документ фиксирует семантику и остаточные ограничения.

## Состояния и переходы

Единственный автомат: `ISSUED → CONSUMED` (guard-триггер `guard_transition`,
SQLSTATE 23514 на любую другую форму INSERT/UPDATE; все колонки, кроме
`state`/`consumed_at`, immutable). DELETE/TRUNCATE/DDL запрещены грантами;
роль launcher имеет только SELECT/INSERT + UPDATE(state, consumed_at).
Строки без owner-оператора не создаются и не исчезают.

## TTL (expires_at)

- Expiry хранится В СТРОКЕ и подписан в payload токена. Guard требует
  future-dating при INSERT.
- Просроченная строка **остаётся ISSUED навсегда**: условный CAS-UPDATE
  требует `clock_timestamp() < expires_at`, поэтому expired-proof не может
  быть потреблён никем (в т.ч. повторно). TTL — не переход, а вечный отказ.
- Тройная проверка окна: offline (loader, payload.expiresAt) → CAS (строка)
  → post-COMMIT (launcher, строка) + финальная (child, DB-clock vs payload).
- Операционное требование (не дефект): issuer обязан синхронизировать
  expires_at строки с payload; расхождение лишь сужает окно допуска
  (fail-closed в обе стороны), повторного допуска не создаёт.

## Повторное предъявление после BINDING-refusal

BINDING-отказ происходит в launcher'е ДО любых обращений к БД (сверка с
доверенными ожиданиями). Строка остаётся ISSUED, CAS не выполняется.
Семантика: proof действителен до потребления или истечения — неуспешные
попытки не расходуют его. Одноразовость означает ровно один успешный
допуск (consumption), а не одно предъявление. Тот же токен может быть
предъявлен снова; при совпадении доверенных ожиданий он будет допущен
(в пределах TTL) — это единственный intent оператора.

## Инвалидирование

Явного отзывa (revoke) до TTL нет — по плану §7 proof короткоживущий
(минуты). Раннее аннулирование = истечение TTL или перевыпуск generation.
Повторный INSERT того же (issuer_generation, launch_nonce) невозможен:
23505 → `ALREADY_ISSUED`; перевыпуск требует нового nonce.

## `approved:unacked`

CAS уже закоммичен (строка CONSUMED, durable: synchronous_commit=on), child
получил ровно один approve, но не подтвердил активацию за ack-окно
launcher'а. Семантика: **proof потрачен** — перезапуск того же proof
невозможен (CAS проиграет), требуется новый issue. Ограничение (не дефект
одноразовости): unacked НЕ доказывает смерть child — он мог просто не
успеть ответить. Supervisor обязан сам разрешить исход (остановить child
или принять его живым); второй child запускается только новым proof.
Допуск каждого proof ≤ одного process.

## Проверенные инварианты

- Один consumption на строку: FOR UPDATE + условный UPDATE + commit
  (single-winner; replay → rowCount 0 → false, повторного допуска нет).
- Child никогда не потребляет свой proof (control-credentials только у
  launcher-контура; BINDING-гейт до БД).
- Marker авторизации identity-bound: одного consumed proof недостаточно для
  чужого admission (WeakMap marker↔admission).
- Отказ по witness/expiry не потребляет строку (witness-гейт и post-COMMIT
  проверки до/после CAS; отказ оставляет строку ISSUED либо уже CONSUMED —
  промежуточных состояний нет).

## Остаточные ограничения

1. Нет отзыва до TTL — короткое окно по плану; расширение вне scope P05.
2. `approved:unacked` требует операционной политики supervisor'а (выше).
3. Registry на app-БД в тестовом контуре (production — отдельная control-БД,
   изоляция доказана в requests-admission.test.ts).
