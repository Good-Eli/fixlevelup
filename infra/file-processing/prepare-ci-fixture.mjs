// Restore the exact Astra-reviewed scanner/decoder OCI images and prepare a
// fresh, signed ClamAV definitions snapshot for isolated P05 engine tests.
// Fails closed on archive, OCI descriptor, platform, runtime or digest drift; never changes pins.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { DECODER_CONFIG_SHA, DECODER_PLATFORM_SHA, SCANNER_CONFIG_SHA, SCANNER_PLATFORM_SHA,
  syntheticSnapshotDigest } from './docker-test-launcher.mjs';

const root = resolve(import.meta.dirname, '../..');
const cacheRoot = resolve(root, 'node_modules/.cache/p0304cde');
const baseImage = 'clamav/clamav:1.4.7_base@sha256:21622d96b8a7080af7974d99ca60a9e061eff5ff831ed6986d00953fc19ff67f';
// Immutable Release assets exported from the original Astra-reviewed OCI images.
const fixtureRelease = 'https://github.com/Good-Eli/fixlevelup/releases/download/p03-04cde-oci-fixtures-v1/';
const scannerArchiveSha256 = '781a35a36a26cbe33fe69c0c46851a3395db814a69f1519dad0836fd1b371eb5';
const decoderArchiveSha256 = '61fb5af102aea942ec86d7a5048fef9105c344040590275dcfac6a3a88b4b56b';
const patchFiles = [
  'f3acb0a3328046741479482c51cec815839e1b05',
  'c8f6d04f8e6d40b1bf83334e4a2ec9daf5943a3d',
  '9491b0d9cc7950af1f3dc89499bd5433b9cd4f43',
  '468c287cf451a834b370b69ab321b8ffdfac23aa',
  '1c65edebefa0dd11aa41cb1a31078ecd9c79d472',
];
const runId = String(process.env.GITHUB_RUN_ID ?? ('local-' + process.pid)).replace(/[^a-zA-Z0-9-]/gu, '-');
mkdirSync(cacheRoot, { recursive: true });
const work = mkdtempSync(join(cacheRoot, 'engine-ci-' + runId + '-'));
const updateDir = join(work, 'definitions-update');
const snapshotDir = join(cacheRoot, 'snapshot-ci-' + runId);
const descriptorDir = join(cacheRoot, 'engines-ci-' + runId);
const descriptorPath = join(descriptorDir, 'worker-fixture-backport-v1.json');
const scannerTag = 'fixlevelup-p05-clamav-ci:' + runId;
const decoderTag = 'fixlevelup-p05-decoder-ci:' + runId;
const scannerOciTarPath = join(work, 'scanner-original.docker.tar');
const decoderOciTarPath = join(work, 'decoder-original.docker.tar');
const scannerLayoutPath = join(work, 'scanner-oci-layout');
const decoderLayoutPath = join(work, 'decoder-oci-layout');
const updaterName = 'fixlevelup-p05-defs-' + runId;

let scannerImageId;
let decoderImageId;
mkdirSync(updateDir, { recursive: true });
chmodSync(updateDir, 0o777); // FreshClam runs as UID 65534, not as root.
mkdirSync(snapshotDir, { recursive: true });
mkdirSync(descriptorDir, { recursive: true });
let updaterCreated = false;
let complete = false;

function command(name, args, options = {}) {
  const result = spawnSync(name, args, {
    cwd: options.cwd ?? root,
    encoding: 'utf8',
    stdio: options.inherit ? 'inherit' : 'pipe',
    maxBuffer: 8 * 1024 * 1024,
    env: options.env ?? process.env,
  });
  if (result.error || result.status !== 0 || result.signal) {
    const failure = options.safeFailure ?? (name + ' exited unsuccessfully');
    const detail = options.includeStderr
      ? String(result.stderr ?? '').trim().replace(/[\r\n\t]+/gu, ' ')
        .replace(/(authorization|token|password|secret)(\s*[:=]\s*)\S+/giu, '$1$2[REDACTED]')
        .slice(0, 600)
      : '';
    throw new Error(detail ? failure + ': ' + detail : failure);
  }
  return String(result.stdout ?? '');
}
function download(url, output) {
  command('curl', ['--fail', '--silent', '--show-error', '--location', '--proto', '=https',
    '--tlsv1.2', '--output', output, url], {
    safeFailure: 'Verified HTTPS download failed: ' + new URL(url).hostname,
  });
  if (statSync(output).size < 1) { throw new Error('Empty pinned input download'); }
}
function docker(args, options = {}) { return command('docker', args, options); }
function exactImage(imageIdentity, tag, runtimeCheck) {
  const actual = docker(['image', 'inspect', '--format', '{{.Id}} {{.Os}}/{{.Architecture}}', tag], {
    safeFailure: 'Docker local image inspection failed for the restored reviewed engine image',
    includeStderr: true,
  }).trim().split(/\\s+/u);
  if (actual[0] !== imageIdentity || actual[1] !== 'linux/amd64') {
    throw new Error('Restored engine image identity mismatch: ' + JSON.stringify({
      expectedImageIdentity: imageIdentity, actualImageIdentity: actual[0] ?? null,
      actualPlatform: actual[1] ?? null,
    }));
  }
  if (runtimeCheck !== undefined) {
    const containerName = 'fixlevelup-p05-runtime-probe-' + process.pid;
    const copiedFile = join(work, 'runtime-file-probe');
    let created = false;
    try {
      docker(['create', '--name', containerName, '--network', 'none', tag], {
        safeFailure: 'Could not create an inert container for reviewed runtime hash verification',
      });
      created = true;
      docker(['cp', containerName + ':' + runtimeCheck.path, copiedFile], {
        safeFailure: 'Could not copy the reviewed runtime file for hash verification',
      });
      const actualRuntimeSha256 = createHash('sha256').update(readFileSync(copiedFile)).digest('hex');
      if (actualRuntimeSha256 !== runtimeCheck.sha256) {
        throw new Error('Restored scanner runtime SHA-256 differs from Astra-reviewed evidence');
      }
    } finally {
      if (created) {
        try { docker(['rm', '-f', containerName]); }
        catch { process.stderr.write('P05 runtime probe cleanup failed\\n'); }
      }
      rmSync(copiedFile, { force: true });
    }
  }
  return actual[0];
}
function clamscan(args) {
  if (!scannerImageId) { throw new Error('Verified scanner image ID is unavailable'); }
  return docker(['run', '--rm', '--network', 'none', '--read-only', '--user', '65532:65532',
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    '--mount', 'type=bind,source=' + snapshotDir + ',target=/defs,readonly',
    '--entrypoint', '/usr/bin/clamscan', scannerImageId, '--database=/defs', ...args]);
}

try {
  if (process.platform !== 'linux' || process.arch !== 'x64' || process.version !== 'v24.22.3') {
    throw new Error('Engine fixture preparation requires Linux x64 and Node 24.22.3');
  }
  command('docker', ['version', '--format', '{{.Server.Version}}']);
  // Release assets are immutable and pinned by archive SHA-256 below. OCI
  // index, platform manifest, config and every layer are verified before load.
  
  // Preserve the exact Astra-reviewed pins; no image is rebuilt or repinned.
  const review = JSON.parse(readFileSync(resolve(root, 'infra/file-processing/oci-review-evidence.json'), 'utf8'));
  if (review.scanner?.indexSha256 !== SCANNER_CONFIG_SHA.slice(7)
      || review.scanner?.linuxAmd64ManifestSha256 !== SCANNER_PLATFORM_SHA.slice(7)
      || review.decoder?.indexSha256 !== DECODER_CONFIG_SHA.slice(7)
      || review.decoder?.linuxAmd64ManifestSha256 !== DECODER_PLATFORM_SHA.slice(7)
      || review.scanner?.libcrypto?.runtimeSha256 !== 'ffe3c003b7685b0d589c94b4ba58df70a1d6d792e3b08a85f17bbd9b97bd429a') {
    throw new Error('Pinned OCI identities/runtime do not match the reviewed OCI evidence');
  }
  download(fixtureRelease + 'scanner-original.docker.tar', scannerOciTarPath);
  download(fixtureRelease + 'decoder-original.docker.tar', decoderOciTarPath);
  for (const [file, expected] of [[scannerOciTarPath, scannerArchiveSha256], [decoderOciTarPath, decoderArchiveSha256]]) {
    const actual = createHash('sha256').update(readFileSync(file)).digest('hex');
    if (actual !== expected) { throw new Error('Reviewed OCI fixture archive SHA-256 mismatch'); }
  }
  mkdirSync(scannerLayoutPath, { recursive: true });
  mkdirSync(decoderLayoutPath, { recursive: true });
  command('tar', ['-xf', scannerOciTarPath, '-C', scannerLayoutPath]);
  command('tar', ['-xf', decoderOciTarPath, '-C', decoderLayoutPath]);
  // Authenticate every OCI descriptor/blob before Docker imports either image.
  const verifyArchive = (imageIdentity, platform, layoutPath) => {
    const layout = JSON.parse(readFileSync(join(layoutPath, 'oci-layout'), 'utf8'));
    const rootIndex = JSON.parse(readFileSync(join(layoutPath, 'index.json'), 'utf8'));
    if (layout.imageLayoutVersion !== '1.0.0' || rootIndex.schemaVersion !== 2
        || rootIndex.mediaType !== 'application/vnd.oci.image.index.v1+json'
        || !Array.isArray(rootIndex.manifests)) throw new Error('Reviewed OCI archive root layout is invalid');
    const blob = (digest, size, label) => {
      if (!/^sha256:[0-9a-f]{64}$/u.test(digest)) throw new Error(label + ' digest invalid');
      const bytes = readFileSync(join(layoutPath, 'blobs', 'sha256', digest.slice(7)));
      if (bytes.length !== size || 'sha256:' + createHash('sha256').update(bytes).digest('hex') !== digest) {
        throw new Error(label + ' blob digest/size mismatch');
      }
      return bytes;
    };
    const nested = rootIndex.manifests.filter(x => x.digest === imageIdentity
      && x.mediaType === 'application/vnd.oci.image.index.v1+json');
    if (nested.length !== 1) throw new Error('Reviewed nested OCI index descriptor missing/ambiguous');
    const inner = JSON.parse(blob(nested[0].digest, nested[0].size, 'nested OCI index').toString('utf8'));
    if (inner.schemaVersion !== 2 || inner.mediaType !== 'application/vnd.oci.image.index.v1+json'
        || !Array.isArray(inner.manifests)) throw new Error('Nested OCI index is invalid');
    const manifests = inner.manifests.filter(x => x.digest === platform
      && x.mediaType === 'application/vnd.oci.image.manifest.v1+json'
      && x.platform?.os === 'linux' && x.platform?.architecture === 'amd64');
    if (manifests.length !== 1) throw new Error('Reviewed linux/amd64 manifest missing/ambiguous');
    const manifest = JSON.parse(blob(manifests[0].digest, manifests[0].size, 'platform manifest').toString('utf8'));
    if (manifest.schemaVersion !== 2 || manifest.mediaType !== 'application/vnd.oci.image.manifest.v1+json'
        || !manifest.config || !Array.isArray(manifest.layers)) throw new Error('Platform manifest invalid');
    const configBytes = blob(manifest.config.digest, manifest.config.size, 'image config');
    const config = JSON.parse(configBytes.toString('utf8'));
    if (config.os !== 'linux' || config.architecture !== 'amd64') throw new Error('Image config platform mismatch');
    for (const layer of manifest.layers) blob(layer.digest, layer.size, 'image layer');
  };
  verifyArchive(SCANNER_CONFIG_SHA, SCANNER_PLATFORM_SHA, scannerLayoutPath);
  verifyArchive(DECODER_CONFIG_SHA, DECODER_PLATFORM_SHA, decoderLayoutPath);
  docker(['load', '--input', scannerOciTarPath], { inherit: true });
  docker(['load', '--input', decoderOciTarPath], { inherit: true });
  docker(['tag', 'fixlevelup-file-processing-clamav:1.4.7-crypto-backport-v1', scannerTag]);
  docker(['tag', 'fixlevelup-file-processing-decoder:p0304cde-musl-v1', decoderTag]);
  scannerImageId = exactImage(SCANNER_CONFIG_SHA, scannerTag, {
    path: '/usr/lib/libcrypto.so.3',
    sha256: review.scanner.libcrypto.runtimeSha256,
  });
  decoderImageId = exactImage(DECODER_CONFIG_SHA, decoderTag);

  // FreshClam is a one-shot updater and the only container here with network access.
  // All actual scanner/decoder workers remain network=none, read-only and non-root.
  docker(['pull', baseImage], { inherit: true });
  docker(['create', '--name', updaterName, '--network', 'bridge', '--read-only',
    '--user', '65534:65534', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    '--pids-limit', '32', '--cpus', '1', '--memory', '1024m', '--memory-swap', '1024m',
    '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m',
    '--mount', 'type=bind,source=' + updateDir + ',target=/defs',
    '--mount', 'type=bind,source=' + resolve(root, 'infra/file-processing/freshclam.conf') + ',target=/tmp/freshclam.conf,readonly',
    '--entrypoint', '/usr/bin/freshclam', baseImage, '--config-file=/tmp/freshclam.conf', '--verbose']);
  updaterCreated = true;
  command('docker', ['start', '--attach', updaterName], { inherit: true });
  // Lock the fresh update directory after FreshClam has exited successfully.
  chmodSync(updateDir, 0o700);

  const expectedFiles = ['bytecode.cvd', 'daily.cvd', 'main.cvd'];
  const actual = readdirSync(updateDir).sort();
  for (const file of expectedFiles) {
    if (!actual.includes(file) || statSync(join(updateDir, file)).size <= 512) {
      throw new Error('FreshClam did not produce the exact signed CVD file set');
    }
    copyFileSync(join(updateDir, file), join(snapshotDir, file));
  }
  if (readdirSync(snapshotDir).sort().join(',') !== expectedFiles.join(',')) {
    throw new Error('Unexpected files entered the immutable engine definitions snapshot');
  }
  // The pinned scanner's sigtool must authenticate every CVD signature.
  for (const file of expectedFiles) {
    const info = docker(['run', '--rm', '--network', 'none', '--read-only', '--user', '65532:65532',
      '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
      '--mount', 'type=bind,source=' + snapshotDir + ',target=/defs,readonly',
      '--entrypoint', '/usr/bin/sigtool', scannerImageId, '--info', '/defs/' + file]);
    if (!/Verification OK\./u.test(info)) { throw new Error('ClamAV signature verification failed for ' + file); }
  }
  const version = clamscan(['--version']).trim();
  const match = /^ClamAV 1\.4\.7\/(\d+)\/([A-Z][a-z]{2} [A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2} \d{4})$/mu.exec(version);
  if (!match?.[1] || !match[2]) { throw new Error('Pinned scanner returned an unknown definitions epoch'); }
  const builtAtMs = Date.parse(match[2] + ' UTC');
  if (!Number.isFinite(builtAtMs)) { throw new Error('ClamAV definitions build timestamp is invalid'); }
  const defsSha256 = await syntheticSnapshotDigest(snapshotDir);
  const descriptor = {
    snapshotDir,
    epoch: {
      engineVersion: '1.4.7',
      engineImageSha256: SCANNER_PLATFORM_SHA.slice(7),
      defsSha256,
      defsBuiltAt: new Date(builtAtMs).toISOString(),
    },
    imageIdentity: {
      scannerConfigSha256: SCANNER_CONFIG_SHA.slice(7),
      scannerPlatformSha256: SCANNER_PLATFORM_SHA.slice(7),
      decoderConfigSha256: DECODER_CONFIG_SHA.slice(7),
      decoderPlatformSha256: DECODER_PLATFORM_SHA.slice(7),
    },
    scannerImageId,
    decoderImage: decoderImageId,
    scanner: {
      cpuMilli: 1000, memoryMiB: 1200, pids: 32, tmpfsMiB: 32, wallMs: 45000,
      maxFileBytes: 1048576, maxScanBytes: 8388608, maxFiles: 64, maxRecursion: 8,
      dailyRevision: Number(match[1]),
    },
    decoder: { cpuMilli: 1000, memoryMiB: 512, pids: 32, tmpfsMiB: 32, wallMs: 10000 },
  };
  const descriptorBytes = JSON.stringify(descriptor, null, 2) + '\n';
  writeFileSync(descriptorPath, descriptorBytes, { mode: 0o600 });
  const descriptorSha256 = createHash('sha256').update(descriptorBytes).digest('hex');
  const githubEnv = process.env.GITHUB_ENV;
  if (githubEnv) {
    writeFileSync(githubEnv, 'FIXLEVELUP_LAB_ENGINE_DESCRIPTOR=' + descriptorPath + '\n'
      + 'FIXLEVELUP_LAB_ENGINE_DESCRIPTOR_SHA256=' + descriptorSha256 + '\n', { flag: 'a', mode: 0o600 });
  }
  command(process.execPath, [resolve(root, 'infra/file-processing/preflight.mjs'), descriptorPath], { inherit: true });
  complete = true;
  process.stdout.write('P05 engine fixture prepared and preflighted; descriptor SHA-256 ' + descriptorSha256 + '\n');
  process.stdout.write('P05 engine definitions SHA-256 ' + defsSha256 + '; timestamp ' + descriptor.epoch.defsBuiltAt + '\n');
} finally {
  if (updaterCreated) {
    try { command('docker', ['rm', '-f', updaterName]); }
    catch { process.stderr.write('P05 FreshClam updater cleanup failed\n'); }
  }
  rmSync(updateDir, { recursive: true, force: true });
  rmSync(work, { recursive: true, force: true });
  if (!complete) {
    rmSync(snapshotDir, { recursive: true, force: true });
    rmSync(descriptorDir, { recursive: true, force: true });
  }
}
