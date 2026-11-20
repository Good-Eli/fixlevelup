import { createLocalDocker } from '../linux-integration/docker.mjs';

// All CI Docker commands use the same fail-closed local-daemon/environment policy
// as integration orchestration. No context selection or host fallback.
try {
  const docker = createLocalDocker();
  const result = docker.run(process.argv.slice(2), { stdio: 'inherit', timeout: 1_200_000 });
  process.exitCode = result.status ?? 1;
} catch { console.error('CI local Docker command failed safely.'); process.exitCode = 1; }
