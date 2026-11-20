import { spawnSync } from 'node:child_process';

export const integrationProject = 'fixlevelup-linux-integration';
export const integrationImage = 'fixlevelup-linux-integration:p0111b';
const services = new Set(['postgres', 'garage', 'runner']);
const commands = new Set(['compose', 'build', 'inspect', 'exec', 'run', 'cp', 'restart', 'info', 'version', 'image']);
const linuxEngineNames = new Set(['Docker Engine - Community', 'Docker Engine - Enterprise']);

export function localDockerHost(platform = process.platform) {
  if (platform === 'win32') {
    return 'npipe:////./pipe/dockerDesktopLinuxEngine';
  }
  if (platform === 'linux') {
    return 'unix:///var/run/docker.sock';
  }
  throw new Error('Unsupported local Docker platform');
}

// Docker's explicit --host must not inherit context/TLS/config/Compose/Buildx
// overrides. Keep unrelated variables (including the isolated credentials), but
// never mutate the caller's environment or consult an ambient remote context.
export function isolatedDockerEnv(source = process.env) {
  return Object.fromEntries(Object.entries(source).filter(([name]) =>
    !/^(?:DOCKER|COMPOSE|BUILDX|BUILDKIT)_/i.test(name)));
}

export function assertLocalLinuxEngine(info, platform = process.platform) {
  localDockerHost(platform);
  if (!info || info.OSType !== 'linux' || typeof info.ID !== 'string' || !info.ID.trim()
    || typeof info.ServerVersion !== 'string' || !info.ServerVersion.trim()
    || !Array.isArray(info.Components)
    || !info.Components.some(component => component?.Name === 'Engine'
      && typeof component.Version === 'string' && component.Version.trim())
    || (platform === 'linux' && (!linuxEngineNames.has(info.Platform?.Name)
      || typeof info.OperatingSystem !== 'string' || !info.OperatingSystem.trim()
      || /docker desktop|podman/i.test(info.OperatingSystem)))
    || (platform === 'win32' && info.OperatingSystem !== 'Docker Desktop')) {
    throw new Error('Unexpected local Linux Docker Engine');
  }
}

export function assertIntegrationContainer(info, service) {
  if (!services.has(service) || !info || info.Name !== `/${integrationProject}-${service}`
    || !/^sha256:[a-f0-9]{64}$/.test(info.Image ?? '')
    || !/^[a-f0-9]{64}$/.test(info.Id ?? '')
    || info.Platform !== 'linux' || info.State?.Running !== true
    || info.Config?.Labels?.['com.docker.compose.project'] !== integrationProject
    || info.Config?.Labels?.['com.docker.compose.service'] !== service
    || info.Config?.Labels?.['com.docker.compose.oneoff'] !== 'False') {
    throw new Error('Unexpected integration container identity');
  }
  return info.Id;
}

// No import-time Docker calls. `execute` is injectable for fixture-only tests.
// All real invocations use the pinned local endpoint and a fresh isolated env;
// errors never include captured Docker output (inspect/exec may contain credentials).
export function createLocalDocker({ platform = process.platform, env = process.env, execute = spawnSync } = {}) {
  const host = localDockerHost(platform);
  const baseEnv = isolatedDockerEnv(env);
  let engineChecked = false;

  function invoke(args, { env: extraEnv = {}, stdio = 'pipe', timeout = 20_000, cwd, encoding = 'utf8' } = {}) {
    let result;
    try {
      result = execute('docker', ['--host', host, ...args], {
        env: isolatedDockerEnv({ ...baseEnv, ...extraEnv }), encoding,
        stdio, timeout, cwd, maxBuffer: 4 * 1024 * 1024,
      });
    } catch {
      throw new Error('Local Docker operation failed; details suppressed');
    }
    if (!result || result.error || result.signal || result.status !== 0) {
      throw new Error('Local Docker operation failed; details suppressed');
    }
    return result;
  }

  function checkEngine() {
    if (engineChecked) {
      return;
    }
    let info;
    try {
      info = JSON.parse(invoke(['version', '--format', '{{json .Server}}']).stdout);
    } catch {
      throw new Error('Local Docker Engine unavailable or unexpected; details suppressed');
    }
    // version reports Engine components but not OSType/ID; info supplies the
    // server identity. Both calls must succeed against the same pinned socket.
    let identity;
    try {
      identity = JSON.parse(invoke(['info', '--format', '{{json .}}']).stdout);
    } catch {
      throw new Error('Local Docker Engine unavailable or unexpected; details suppressed');
    }
    assertLocalLinuxEngine({ ...identity, Platform: info?.Platform, Components: info?.Components }, platform);
    engineChecked = true;
  }

  function run(args, options) {
    // Global Docker flags can redirect even an explicit host. Permit only known
    // command roots, never a generic `docker [caller-supplied global flags]`.
    if (!Array.isArray(args) || !commands.has(args[0]) || args.some(arg => typeof arg !== 'string'
      || /^(?:--(?:host|context|config)(?:=|$)|--tls|-H|-c)/.test(arg))) {
      throw new Error('Unsupported isolated Docker command');
    }
    const isBuild = args[0] === 'build' || (['compose', 'image'].includes(args[0]) && args.includes('build'));
    const builders = args.flatMap((arg, index) => arg === '--builder' ? [args[index + 1]]
      : arg.startsWith('--builder=') ? [arg.slice('--builder='.length)] : []);
    if ((isBuild && builders.length !== 1) || builders.some(builder => builder !== 'default')) {
      throw new Error('Isolated Docker builds require the default local builder');
    }
    checkEngine();
    return invoke(args, options);
  }

  function assertContainer(service) {
    if (!services.has(service)) {
      throw new Error('Unsupported integration service');
    }
    let info;
    try {
      info = JSON.parse(run(['inspect', '--format', '{{json .}}', `${integrationProject}-${service}`]).stdout);
    } catch {
      throw new Error('Integration container unavailable or unexpected; details suppressed');
    }
    return assertIntegrationContainer(info, service);
  }

  function restartGarage() {
    // Restart an inspected immutable ID, not an arbitrary CLI target or a name
    // that might be rebound between the identity check and the restart call.
    const id = assertContainer('garage');
    run(['restart', '--time', '10', id], { timeout: 30_000 });
  }

  return Object.freeze({ host, run, assertContainer, restartGarage });
}
