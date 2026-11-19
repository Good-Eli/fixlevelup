# FixLevelUp dev PostgreSQL — P01-01.5

Изолированная локальная PostgreSQL для технической разработки. Без Prisma,
миграций, бизнес-таблиц и подключения приложений.

## Подключение

- Host: `127.0.0.1`
- Port: `55432`
- Database/user: `fixlevelup_dev`
- Password: только локальный `.env` рядом с compose.yaml (исключён из Git).
- Image: официальный `postgres:18.7-bookworm`, linux/amd64.
- OCI index digest: `sha256:1757c628698dd1ca67ff7a5fc386bfd91040afc62a45484c346c788b0cbe5402`.
- Container/project: `fixlevelup-dev-postgres`.
- Network: `fixlevelup-dev-postgres-net`.
- Volume: `fixlevelup-dev-postgres-data`, mount `/var/lib/postgresql`
  (PostgreSQL18 PGDATA находится в `/var/lib/postgresql/18/docker`).

Пароль сгенерирован криптографическим генератором, 32 случайных байта.
Не выводите `docker compose config`/inspect environment в отчёты: они могут
содержать пароль. Для валидации используйте `config --quiet`.
Официальный POSTGRES_USER является bootstrap superuser; это только dev,
не будущая runtime role приложений. Отдельные migration/runtime roles позже.

## Управление из корня репозитория

```powershell
docker compose --project-directory infra/dev-postgres -f infra/dev-postgres/compose.yaml config --quiet
docker compose --project-directory infra/dev-postgres -f infra/dev-postgres/compose.yaml up -d --wait --wait-timeout 120 postgres
docker compose --project-directory infra/dev-postgres -f infra/dev-postgres/compose.yaml ps
docker compose --project-directory infra/dev-postgres -f infra/dev-postgres/compose.yaml restart postgres
docker compose --project-directory infra/dev-postgres -f infra/dev-postgres/compose.yaml stop postgres
# Повторный запуск сохраняет данные volume:
docker compose --project-directory infra/dev-postgres -f infra/dev-postgres/compose.yaml start postgres
# Интерактивный psql внутри контейнера (без пароля в аргументах):
docker compose --project-directory infra/dev-postgres -f infra/dev-postgres/compose.yaml exec postgres psql -U fixlevelup_dev -d fixlevelup_dev
```

Healthcheck использует pg_isready; состояние healthy означает готовность
сервера принимать подключения, не проверку прикладной схемы или backup.
restart policy: unless-stopped. Порт публикуется только на loopback.
Контейнер не подключён к сетям Immich/Nextcloud и не использует их volumes.

Для нового окружения скопируйте .env.example в .env и задайте новый случайный
пароль до первого старта. Изменение .env после инициализации volume само по
себе НЕ меняет пароль PostgreSQL. Ротация требует отдельной контролируемой
операции; существующие данные не переинициализировать.

Техническая persistence-проверка использует schema `p01_technical` и таблицу
`persistence_probe` с синтетической записью, не бизнес-данные. Volume не удалять;
Docker cleanup/prune и команды удаления volumes в штатный процесс не входят.
Это локальный dev-стенд, не production и не резервная копия.
