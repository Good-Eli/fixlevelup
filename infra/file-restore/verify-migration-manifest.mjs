import { verifyReviewedMigrationManifest } from './reviewed-expressions.mjs';

const manifest = verifyReviewedMigrationManifest();
if (manifest.count !== 24) {
  throw new Error(`Expected the reviewed S3 migration set (24), got ${manifest.count}`);
}
process.stdout.write(`Reviewed restore SQL set verified: ${manifest.count} migrations, SHA-256 ${manifest.sha256}\n`);
