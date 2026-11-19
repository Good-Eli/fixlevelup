import { defineConfig } from 'prisma/config';

export default defineConfig({
  schema: '../../prisma/schema.prisma',
  migrations: { path: process.env['FIXLEVELUP_MIGRATIONS_DIR'] ?? '../../prisma/migrations' },
  ...(process.env['FIXLEVELUP_MIGRATION_URL']
    ? { datasource: {
      url: process.env['FIXLEVELUP_MIGRATION_URL'],
      ...(process.env['FIXLEVELUP_SHADOW_URL'] ? { shadowDatabaseUrl: process.env['FIXLEVELUP_SHADOW_URL'] } : {}),
    } }
    : {}),
});
