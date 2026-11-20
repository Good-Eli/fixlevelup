import { spawnSync } from 'node:child_process';
import { loadStorageConfig } from './local.mjs';

// CLI secrets remain inside this process; never print raw args/output. A trusted
// local Docker/OS administrator can inspect process arguments (same trust as DB tooling).
function docker(args) {
  const result = spawnSync('docker', args, { encoding: 'utf8', timeout: 20_000 });
  if (result.error || result.status !== 0) { throw new Error('Garage bootstrap command failed; raw output suppressed'); }
  return result.stdout;
}
function command(args) { return docker(['exec', 'fixlevelup-dev-s3', '/garage', ...args]); }

try {
  const scope = docker(['inspect', '--format', '{{index .Config.Labels "com.docker.compose.project"}}', 'fixlevelup-dev-s3']).trim();
  if (scope !== 'fixlevelup-dev-s3') { throw new Error('Unexpected Garage container identity'); }
  const writer = loadStorageConfig(), reader = loadStorageConfig(true);
  const bucket = writer.bucket;
  const buckets = command(['bucket', 'list']);
  if (!buckets.includes(bucket)) { command(['bucket', 'create', bucket]); }
  for (const [name, config, write] of [['fixlevelup-dev-rw', writer, true], ['fixlevelup-dev-ro', reader, false]]) {
    const keys = command(['key', 'list']);
    if (!keys.includes(config.accessKeyId)) {
      command(['key', 'import', '--yes', '-n', name, config.accessKeyId, config.secretAccessKey]);
    }
    command(['key', 'deny', '--create-bucket', config.accessKeyId]);
    // Revoke any prior owner/write access before restoring the explicit subset.
    command(['bucket', 'deny', '--read', '--write', '--owner', '--key', config.accessKeyId, bucket]);
    command(['bucket', 'allow', '--read', ...(write ? ['--write'] : []), '--key', config.accessKeyId, bucket]);
  }
  console.log('Garage private bucket and separate read/write + read-only grants configured; secrets suppressed.');
} catch {
  console.error('Garage bootstrap failed safely; no credentials or CLI output printed.');
  process.exitCode = 1;
}
