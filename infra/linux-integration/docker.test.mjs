import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assertIntegrationContainer, assertLocalLinuxEngine, createLocalDocker,
  integrationImage, integrationProject, isolatedDockerEnv, localDockerHost,
} from './docker.mjs';

const engine = {
  ID: 'synthetic-engine-id', OSType: 'linux', ServerVersion: '29.0.0',
  OperatingSystem: 'Docker Desktop', Platform: { Name: 'Docker Engine - Community' },
  Components: [{ Name: 'Engine', Version: '29.0.0' }],
};
const id = 'a'.repeat(64);
const container = (service = 'garage') => ({
  Id: id, Name: `/${integrationProject}-${service}`, Platform: 'linux',
  Image: `sha256:${'b'.repeat(64)}`, State: { Running: true },
  Config: { Labels: {
    'com.docker.compose.project': integrationProject,
    'com.docker.compose.service': service,
    'com.docker.compose.oneoff': 'False',
  } },
});
const ok = (stdout = '') => ({ status: 0, stdout, stderr: '' });
const linuxEngine = { ...engine, OperatingSystem: 'Ubuntu 24.04.3 LTS' };
function fixture({ platform = 'linux', env = {}, responses = [], identity = platform === 'linux' ? linuxEngine : engine } = {}) {
  const calls = [];
  const docker = createLocalDocker({
    platform, env,
    execute(command, args, options) {
      calls.push({ command, args, options });
      if (args[2] === 'version') {
        return ok(JSON.stringify({ Components: identity.Components, Platform: identity.Platform }));
      }
      if (args[2] === 'info') {
        return ok(JSON.stringify(identity));
      }
      return responses.shift() ?? ok();
    },
  });
  return { docker, calls };
}

test('only the two pinned local platform endpoints are supported', () => {
  assert.equal(localDockerHost('win32'), 'npipe:////./pipe/dockerDesktopLinuxEngine');
  assert.equal(localDockerHost('linux'), 'unix:///var/run/docker.sock');
  for (const platform of ['darwin', 'freebsd', '', 'remote']) {
    assert.throws(() => localDockerHost(platform), /Unsupported local Docker platform/);
    assert.throws(() => createLocalDocker({ platform }), /Unsupported local Docker platform/);
  }
  assert.equal(integrationProject, 'fixlevelup-linux-integration');
  assert.equal(integrationImage, 'fixlevelup-linux-integration:p0111b');
});

test('environment sanitization removes every Docker, Compose, Buildx and Buildkit override without mutation', () => {
  const source = Object.freeze({
    PATH: 'synthetic-path', S3_ACCESS_KEY_ID: 'synthetic-isolated-key',
    DOCKER_HOST: 'tcp://remote.invalid:2376', DOCKER_CONTEXT: 'remote',
    DOCKER_TLS_VERIFY: '1', DOCKER_CERT_PATH: 'synthetic-secret-path',
    DOCKER_CONFIG: 'foreign-config', DOCKER_API_VERSION: '1.1', DOCKER_DEFAULT_PLATFORM: 'windows/amd64',
    COMPOSE_FILE: 'foreign-compose', COMPOSE_PROJECT_NAME: 'foreign-project', COMPOSE_ENV_FILES: 'foreign-env',
    COMPOSE_PROFILES: '*', BUILDX_BUILDER: 'remote', BUILDKIT_HOST: 'tcp://remote.invalid:1234',
    docker_context: 'case-insensitive-windows-override',
  });
  assert.deepEqual(isolatedDockerEnv(source), { PATH: source.PATH, S3_ACCESS_KEY_ID: source.S3_ACCESS_KEY_ID });
  assert.equal(source.DOCKER_CONTEXT, 'remote');
});

test('Engine identity accepts only a Linux Docker Engine and Desktop on Windows', () => {
  assert.doesNotThrow(() => assertLocalLinuxEngine(linuxEngine, 'linux'));
  assert.doesNotThrow(() => assertLocalLinuxEngine({ ...linuxEngine, Platform: { Name: 'Docker Engine - Enterprise' } }, 'linux'));
  assert.doesNotThrow(() => assertLocalLinuxEngine(engine, 'win32'));
  const invalid = [
    null, {}, { ...linuxEngine, OSType: 'windows' }, { ...linuxEngine, ID: '' },
    { ...linuxEngine, ServerVersion: '' }, { ...linuxEngine, Components: [] },
    { ...linuxEngine, Platform: { Name: 'Docker Desktop' } },
    { ...linuxEngine, Platform: { Name: 'Podman Engine' } },
    { ...linuxEngine, OperatingSystem: 'Docker Desktop Linux' },
    { ...linuxEngine, OperatingSystem: 'Podman machine' },
    { ...linuxEngine, Components: [{ Name: 'Podman Engine', Version: '5.0.0' }] },
    { ...linuxEngine, Components: [{ Name: 'Engine' }] },
  ];
  for (const info of invalid) {
    assert.throws(() => assertLocalLinuxEngine(info, 'linux'), /Unexpected local Linux Docker Engine/);
  }
  assert.throws(() => assertLocalLinuxEngine({ ...engine, OperatingSystem: 'Other runtime' }, 'win32'), /Unexpected/);
});

for (const platform of ['linux', 'win32']) {
  test(`${platform} runs preflight before an operation on the pinned endpoint with isolated env`, () => {
    const env = { PATH: 'original', DOCKER_CONTEXT: 'remote', DOCKER_HOST: 'ssh://remote.invalid' };
    const { docker, calls } = fixture({ platform, env, responses: [ok('synthetic-output')] });
    assert.equal(calls.length, 0, 'construction/import does not contact Docker');
    const result = docker.run(['compose', 'config', '--quiet'], {
      env: { PATH: 'override', COMPOSE_FILE: 'foreign', DOCKER_HOST: 'tcp://remote.invalid', S3_ACCESS_KEY_ID: 'isolated' },
      cwd: '/synthetic-root', timeout: 1234, encoding: 'utf8', stdio: 'pipe',
    });
    assert.equal(result.status, 0);
    assert.equal(result.stdout, 'synthetic-output');
    assert.equal(calls.length, 3);
    assert.deepEqual(calls.map(call => call.args[2]), ['version', 'info', 'compose']);
    for (const call of calls) {
      assert.equal(call.command, 'docker');
      assert.deepEqual(call.args.slice(0, 2), ['--host', localDockerHost(platform)]);
      assert.equal(call.options.env.DOCKER_HOST, undefined);
      assert.equal(call.options.env.DOCKER_CONTEXT, undefined);
      assert.equal(call.options.env.COMPOSE_FILE, undefined);
    }
    assert.equal(calls[2].options.env.S3_ACCESS_KEY_ID, 'isolated');
    assert.equal(calls[2].options.env.PATH, 'override');
    assert.equal(calls[2].options.cwd, '/synthetic-root');
    assert.equal(calls[2].options.timeout, 1234);
    assert.equal(env.DOCKER_CONTEXT, 'remote');
    docker.run(['version']);
    assert.equal(calls.length, 4, 'successful preflight is cached only within this helper instance');
  });
}

test('no remote global flag can replace the pinned host, even after a command root', () => {
  const { docker, calls } = fixture();
  for (const args of [
    ['--host', 'tcp://remote.invalid', 'info'], ['--context=remote', 'info'],
    ['info', '--host=tcp://remote.invalid'], ['info', '-Hssh://remote.invalid'],
    ['info', '--context', 'remote'], ['info', '-cremote'], ['info', '--config=foreign'], ['info', '--tlsverify'],
    ['system', 'prune'], [], null, ['info', null],
  ]) {
    assert.throws(() => docker.run(args), /Unsupported isolated Docker command/);
  }
  assert.equal(calls.length, 0);
});

test('build commands require exactly the default local builder, never persisted or remote selections', () => {
  for (const args of [
    ['build', '.'], ['build', '--builder', 'remote', '.'],
    ['build', '--builder=default', '--builder=remote', '.'],
    ['compose', 'build', 'runner'], ['compose', 'build', '--builder', 'remote', 'runner'],
    ['image', 'build', '--builder', 'remote', '.'],
  ]) {
    const { docker, calls } = fixture();
    assert.throws(() => docker.run(args), /require the default local builder/);
    assert.equal(calls.length, 0);
  }
  for (const args of [
    ['build', '--builder', 'default', '.'], ['build', '--builder=default', '.'],
    ['compose', '--project-name', integrationProject, 'build', '--builder', 'default', 'runner'],
  ]) {
    const { docker, calls } = fixture();
    assert.equal(docker.run(args).status, 0);
    assert.equal(calls.length, 3);
  }
});

test('unavailable Docker fails closed and suppresses raw errors without running the requested command', () => {
  for (const result of [
    { status: 1, stdout: 'SYNTHETIC_SECRET', stderr: 'SYNTHETIC_SECRET' },
    { status: null, error: new Error('SYNTHETIC_SECRET') },
    { status: 0, signal: 'SIGTERM' }, ok('invalid JSON SYNTHETIC_SECRET'), null,
  ]) {
    const calls = [];
    const docker = createLocalDocker({ platform: 'linux', execute(...args) { calls.push(args); return result; } });
    assert.throws(() => docker.run(['compose', 'up']), error =>
      /unavailable or unexpected/.test(error.message) && !error.message.includes('SYNTHETIC_SECRET'));
    assert.equal(calls.length, 1);
  }
});

test('a throwing Docker executable is redacted', () => {
  const docker = createLocalDocker({ platform: 'linux', execute() { throw new Error('SYNTHETIC_SECRET'); } });
  assert.throws(() => docker.run(['info']), error => !String(error).includes('SYNTHETIC_SECRET'));
});

test('unexpected Engine stops the operation after identity queries', () => {
  const { docker, calls } = fixture({ identity: { ...engine, OSType: 'windows' } });
  assert.throws(() => docker.run(['compose', 'up']), /Unexpected local Linux Docker Engine/);
  assert.equal(calls.length, 2);
});

test('failed command status or timeout throws a redacted error', () => {
  for (const result of [
    { status: 17, stdout: 'SYNTHETIC_SECRET', stderr: 'SYNTHETIC_SECRET' },
    { status: null, error: new Error('SYNTHETIC_SECRET') },
  ]) {
    const { docker } = fixture({ responses: [result] });
    assert.throws(() => docker.run(['exec', id, 'synthetic-command']), error =>
      /operation failed/.test(error.message) && !String(error).includes('SYNTHETIC_SECRET'));
  }
});

test('container identity requires exact project/service/name, Linux, running state and immutable IDs', () => {
  for (const service of ['postgres', 'garage', 'runner']) {
    assert.equal(assertIntegrationContainer(container(service), service), id);
  }
  const info = container();
  for (const value of [
    { ...info, Name: '/foreign-garage' }, { ...info, Id: 'name-not-id' },
    { ...info, Image: 'unidentified' }, { ...info, Platform: 'windows' },
    { ...info, State: { Running: false } }, { ...info, Config: {} },
    { ...info, Config: { Labels: { ...info.Config.Labels, 'com.docker.compose.project': 'foreign' } } },
    { ...info, Config: { Labels: { ...info.Config.Labels, 'com.docker.compose.service': 'postgres' } } },
    { ...info, Config: { Labels: { ...info.Config.Labels, 'com.docker.compose.oneoff': 'True' } } },
  ]) {
    assert.throws(() => assertIntegrationContainer(value, 'garage'), /Unexpected integration container identity/);
  }
  assert.throws(() => assertIntegrationContainer(info, 'foreign'), /Unexpected/);
});

test('scoped Garage restart inspects the exact integration service then restarts only its immutable ID', () => {
  const { docker, calls } = fixture({ responses: [ok(JSON.stringify(container())), ok(id)] });
  docker.restartGarage();
  assert.deepEqual(calls[2].args.slice(2), ['inspect', '--format', '{{json .}}', `${integrationProject}-garage`]);
  assert.deepEqual(calls[3].args.slice(2), ['restart', '--time', '10', id]);
  assert.equal(calls[3].options.timeout, 30_000);
});

test('scoped Garage restart refuses mismatched or unavailable container without mutation', () => {
  for (const result of [
    ok(JSON.stringify(container('postgres'))), ok('invalid inspect SYNTHETIC_SECRET'),
    { status: 1, stderr: 'SYNTHETIC_SECRET' },
  ]) {
    const { docker, calls } = fixture({ responses: [result] });
    assert.throws(() => docker.restartGarage(), error => !String(error).includes('SYNTHETIC_SECRET'));
    assert.equal(calls.length, 3);
    assert.equal(calls.some(call => call.args[2] === 'restart'), false);
  }
});

test('unsupported container service is rejected without contacting Docker', () => {
  const { docker, calls } = fixture();
  assert.throws(() => docker.assertContainer('foreign'), /Unsupported integration service/);
  assert.equal(calls.length, 0);
});

test('evidence copy is supported with a successful result contract', () => {
  const { docker, calls } = fixture({ responses: [ok()] });
  const result = docker.run(['cp', `${integrationProject}-runner:/workspace/synthetic-evidence`, '/synthetic-temp'], {
    encoding: 'utf8', stdio: 'pipe', timeout: 30_000,
  });
  assert.equal(result.status, 0);
  assert.equal(calls[2].args[2], 'cp');
});
