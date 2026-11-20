# P01-01.10B — synthetic logical backup/restore drill

Закрытый локальный drill, не production backup и не обещание RPO/RTO/HA.
Не выполняет reset/clean/drop, не восстанавливает поверх fixlevelup_dev или
основного Garage. Все тестовые ресурсы/артефакты сохраняются, очистки нет.

## Воспроизведение из корня

Требуются работающие принятые dev PostgreSQL18.7 и Garage2.5.0, локальные
ignored credentials, разрешённый Docker Engine и Node24/pnpm12 dependencies.

```powershell
$env:COREPACK_HOME = Join-Path $env:LOCALAPPDATA 'fixlevelup-tooling\corepack'
$env:COREPACK_ENABLE_AUTO_PIN = '0'
$env:COREPACK_DEFAULT_TO_LATEST = '0'
corepack pnpm run backup:drill
corepack pnpm run check
```

Runner отказывается запускаться, если порт13900 уже опубликован контейнером,
существуют выбранные случайные DB/container/volumes/network или dump artifacts.
При неудаче сохраняет их и сообщает безопасный stage/suffix. Не запускайте его
повторно ради «исправления» старых ресурсов; новый запуск создаёт новый suffix.
После успешного запуска restore Garage остаётся на13900; перед новым drill
нужно отдельно согласованно остановить только предыдущий restore container.
Не останавливайте dev Garage3900 или чужие сервисы, не удаляйте volumes.

## Протокол

1. Создать уникальный suffix12hex и локальный ignored backups/p0110b-<suffix>.
2. Записать3 новых объекта только в synthetic/restore/<suffix>/ текущего dev
   bucket:0,4096,196608 bytes. Другие objects не меняются. Экспортировать bytes,
   Content-Type/metadata/SHA256. Сохранить строгий manifest без keys/secrets.
3. Прочитать фактические bucket website flag и per-key grants через Garage JSON
   RPC, сохранить redacted semantic role mapping. Исходные ключи не экспортировать.
   Сохранить source/target config и immutable image reference без secrets.
4. Создать две новые БД fixlevelup_p0110b_source_<suffix> и
   fixlevelup_p0110b_restore_<suffix>, owner fixlevelup_migrator, PUBLIC database
   privileges/CREATE public отозваны. Обе в существующем FixLevelUp container;
   отдельные базы, не отдельная физическая PG instance.
5. В source применить3 reviewed SQL migration с pin SHA256, создать только test
   restore_proof tables и4 synthetic audit/outbox пары+rollback fixture. Manifest
   объектов хранится в БД для DB↔S3 сверки. Это не новые production migrations.
   Применение прямого SQL отмечено migration_evidence, без fake Prisma history.
6. pg_dump custom format source → container temp → host database.dump. Проверить
   SHA256. Вернуть именно host artifact в отдельный container restore file,
   сверить hash и выполнить pg_restore --exit-on-error только в новую target DB.
   Не использовать --clean/--no-owner/--no-acl; globals/passwords не выгружаются.
7. PG18.7 dump/restore переписывает array casts двух CHECK status/error. Только
   на новой target DB runner проверяет точные известные source/roundtrip формы,
   затем транзакционно восстанавливает те же2 канонических reviewed constraints
   с прежними именами. Это schema DDL новой цели, не удаление данных. Остальные
   catalog differences запрещены. Проверяются реальные CHECK23514 отказы.
   Сравнить полные canonical table snapshots (microseconds timestamps и bigint
   >JS safe int сохранены строками), catalogs/constraints/indexes/defaults/owners/
   ACL, semantic DB grants и normalized schema-only dump. Под runtime-role
   проверить чтение, worker-field update с rollback и запрещённые operations.
8. Создать отдельный Garage fixlevelup-restore-s3-<suffix> с новыми metadata/data
   volumes/network и новым RPC secret. Только127.0.0.1:13900 опубликован,
   RPC/admin container-loopback. Pinned image как у dev, restart=no.
9. Создать приватный bucket с прежним alias и НОВЫМИ key IDs/secrets по mapping
   readwrite/readonly, без owner/create-bucket. Новый bucket внутренне новый ID.
10. Заново прочитать manifest и все host files, проверить count/size/hash ДО
    импортирования objects. PUT в пустую цель, затем GET bytes/SHA256/metadata,
    HEAD length и LIST соответствие. Readonly GET работает, readonly PUT403,
    CreateBucket403, anonymous403, прежний source key403.
11. Сохранить redacted evidence.json и database-evidence.json. Интегрирующий
    агент отдельно сравнивает baseline прежних Docker resources/dev DB/объектов;
    это внешняя проверка, не встроенная гарантия runner. Удалений/автоочистки нет.

## Артефакты и ограничения

Ignored backups/p0110b-<suffix> содержит database.dump, три .bin, manifest.json,
access-mapping.json, config copies, redacted evidence и локальный .env с НОВЫМИ
restore secrets. Секреты не попадают в Git/отчёт/CLI output. Внутренний key import
использует Docker process args, доступные доверенному OS/Docker administrator.
Не публикуйте command lines, .env, raw inspect Env, pg configs/DEBUG или dump.

Артефакты локальные и НЕ зашифрованы: допустимы только synthetic данные. SHA256
проверяет целостность сравнения, но не аутентифицирует злонамеренную замену
manifest вместе с файлами. Production требует отдельного key management,
шифрования, retention, off-host copy, restore authorisation и измеренных RPO/RTO.
Протокол не создаёт atomic cross-system snapshot для параллельных business writes:
fixtures неизменны на время экспорта. Production consistency/quiesce/backup epochs
требуют отдельного решения. Нет PITR/WAL, physical instance restore, удаления ПД
после восстановления, automated schedules или off-host drill.

Garage export — логические objects+metadata+config/access mapping, не копия live
SQLite/blocks. Внутренние bucket/node/key IDs не сохраняются, secrets ротируются.
Physical Garage meta snapshot/data recovery — отдельный операционный протокол.
PostgreSQL роли уже существуют в текущем container: восстановление в чистый
cluster с созданием ролей и передача их secrets этим drill НЕ доказаны.
