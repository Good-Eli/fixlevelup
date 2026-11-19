# P01-01.7B — Synthetic SQL proofs

constraints.sql — test-only PostgreSQL fixture, НЕ Prisma migration и НЕ
реализация business/geography tables. Скрипт db:test-constraints создаёт новую
БД fixlevelup_p017b_proof_<12hex> в существующем devPG18.7 FixLevelUp, только
127.0.0.1:55432. Имя проверяется allowlist, существующая БД не перезаписывается.
btree_gist создаётся только в новой proof DB; dev extension/schema не меняются.

```powershell
corepack pnpm run db:test-constraints
```

Нужны ранее созданные локальные credentials migrator/runtime и bootstrap
admin. Секреты читаются из ignored .env, не из command arguments. Test DB
сохраняются; автоматический DROP/reset/volume cleanup отсутствует.

Проверяется 26 негативных statements с точным SQLSTATE:
NOT NULL23502/FK23503/CHECK23514/partialUNIQUE23505/EXCLUDE23P01/immutable42501.
Каждый негативный statement отдельный autocommit: предыдущая ошибка не
маскируется25P02. Коллизии fixtures с unrelated UNIQUE исключены.

Положительные assertions: callback имеет city/version без address, два
synthetic city без ALTER фундаментальной схемы, samecity concrete/composite
file/report/quote/plan links, две quote revisions одного request не смешиваются
в одном report. District/zone mapping city-scoped; FULL/PARTIAL лишь labels,
не алгоритм покрытия. Price exclusion(city,item,range) допускает crosscity
одинаковые периоды и adjacent[), отвергает overlap/empty/negativeamount.

Copied city/zone/timezone/acceptedamount остаются прежними после новых версий,
rename/rezone и изменения цены. Update/delete истории запрещены triggers.
UTC-сессия фиксирована, city IANA snapshots дают разные UTC instants.
Два независимых подключения доказывают общий transaction advisory key по
technician ID независимо от city: второй trylockfalse, другой techtrue,
после COMMIT тот же key доступен. Это не implementation capacity/scheduling.

Fixture runtime имеет DML специально для отрицательных тестов triggers/FKs;
это не изменения runtime grants foundation/dev. Доменная безопасность,
активация второго города, availability/ценовые политики/UI здесь не реализованы.

Первые два прогона выявили коллизии тестовых PRIMARY/partial UNIQUE с FK
negative cases. Fixtures исправлены, критерии SQLSTATE не ослаблялись.
Неполные proof DB оставлены для evidence, dev data не затрагивались.
