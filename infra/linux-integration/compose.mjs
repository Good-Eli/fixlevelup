import { readFileSync } from 'node:fs';
import { createLocalDocker, integrationProject } from './docker.mjs';

// --env-file alone does not beat shell precedence. Explicitly set every
// interpolated secret from this NEW stand's ignored env, never ambient dev values.
const source = readFileSync(new URL('.env', import.meta.url), 'utf8');
const patterns = {
  POSTGRES_PASSWORD: /^[a-f0-9]{64}$/,
  GARAGE_RPC_SECRET: /^[a-f0-9]{64}$/,
  S3_ACCESS_KEY_ID: /^GK[a-f0-9]{24}$/,
  S3_SECRET_ACCESS_KEY: /^[a-f0-9]{64}$/,
  S3_READONLY_ACCESS_KEY_ID: /^GK[a-f0-9]{24}$/,
  S3_READONLY_SECRET_ACCESS_KEY: /^[a-f0-9]{64}$/,
};
const isolatedEnv = {};
for (const [name, pattern] of Object.entries(patterns)) {
  const value = new RegExp(`^${name}=([^\\r\\n]+)$`, 'm').exec(source)?.[1];
  if (!value || !pattern.test(value)) {
    throw new Error('Invalid isolated integration credentials');
  }
  isolatedEnv[name] = value;
}
const commands = {
  validate: ['config', '--quiet'],
  // Ignore a persisted Buildx selection as well as ambient builder overrides.
  build: ['build', '--builder', 'default', 'runner'],
  services: ['up', '-d', '--wait', '--wait-timeout', '90', 'postgres', 'garage'],
  run: ['up', '--no-deps', '--abort-on-container-exit', '--exit-code-from', 'runner', 'runner'],
};
const operation = process.argv[2];
const docker = createLocalDocker();
if (operation === 'restart-garage') {
  docker.restartGarage();
  console.log('Isolated Garage container restarted after identity verification.');
} else {
  const args = commands[operation];
  if (!args) {
    throw new Error('Unsupported isolated integration Compose command');
  }
  docker.run(['compose', '--project-name', integrationProject, '-f', 'infra/linux-integration/compose.yaml', ...args], {
    cwd: new URL('../../', import.meta.url),
    env: isolatedEnv,
    stdio: 'inherit',
    // The full check includes nine serial 15-minute CITY matrix slices.
    timeout: operation === 'run' ? 9_600_000 : 1_200_000,
  });
}
