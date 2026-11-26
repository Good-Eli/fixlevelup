// Rebuild the exact reviewed scanner/decoder OCI images and prepare a fresh,
// signed ClamAV definitions snapshot for the isolated P05 engine tests.
// Fails closed on ANY image/platform digest drift; this script never changes pins.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { DECODER_CONFIG_SHA, DECODER_PLATFORM_SHA, SCANNER_CONFIG_SHA, SCANNER_PLATFORM_SHA,
  syntheticSnapshotDigest } from './docker-test-launcher.mjs';

const root = resolve(import.meta.dirname, '../..');
const cacheRoot = resolve(root, 'node_modules/.cache/p0304cde');
const baseImage = 'clamav/clamav:1.4.7_base@sha256:21622d96b8a7080af7974d99ca60a9e061eff5ff831ed6986d00953fc19ff67f';
const opensslPrimary = 'B146647E45A7B33947AB226B2A2C87D161692D40';
// Official BuildKit v0.35.1 multi-platform index, pinned by full digest.
const buildkitImage = 'moby/buildkit:v0.35.1@sha256:baf6138eb8c37644800c7c913fba051e840ebb9ba13eaf92d92ef9a1712d0b4c';
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
const inputDir = join(work, 'scanner-inputs');
const updateDir = join(work, 'definitions-update');
const snapshotDir = join(cacheRoot, 'snapshot-ci-' + runId);
const gnupgDir = join(work, 'gnupg');
const descriptorDir = join(cacheRoot, 'engines-ci-' + runId);
const descriptorPath = join(descriptorDir, 'worker-fixture-backport-v1.json');
const scannerTag = 'fixlevelup-p05-clamav-ci:' + runId;
const decoderTag = 'fixlevelup-p05-decoder-ci:' + runId;
const scannerMetadataPath = join(work, 'scanner-build-metadata.json');
const decoderMetadataPath = join(work, 'decoder-build-metadata.json');
const scannerOciTarPath = join(work, 'scanner-image.oci.tar');
const decoderOciTarPath = join(work, 'decoder-image.oci.tar');
const scannerLayoutPath = join(work, 'scanner-oci-layout');
const decoderLayoutPath = join(work, 'decoder-oci-layout');
const updaterName = 'fixlevelup-p05-defs-' + runId;
const buildxBuilderName = 'fixlevelup-p05-oci-' + runId;
let buildxBuilderCreated = false;
let scannerImageId;
let decoderImageId;
mkdirSync(inputDir, { recursive: true });
mkdirSync(updateDir, { recursive: true });
chmodSync(updateDir, 0o777); // FreshClam runs as UID 65534, not as root.
mkdirSync(snapshotDir, { recursive: true });
mkdirSync(gnupgDir, { recursive: true, mode: 0o700 });
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
function exactImage(configSha, platformSha, tag, metadataPath, ociTarPath, layoutPath, runtimeCheck) {
  // The legacy reviewed "indexSha256" value was compared with Docker .Id;
  // it is therefore the exact config digest, not a root OCI-index digest.
  // Verify the OCI layout's structure/child manifest separately and bind its
  // config blob plus the loaded Docker image to that reviewed config digest.
  const metadata = JSON.parse(readFileSync(metadataPath, 'utf8'));
  const isDigest = (value) => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/u.test(value);
  const sha256 = (bytes) => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
  const safe = (value) => isDigest(value) ? value : null;
  const descriptorDigest = metadata['containerimage.descriptor']?.digest;
  const descriptorMediaType = metadata['containerimage.descriptor']?.mediaType;
  const outputDigest = metadata['containerimage.digest'];
  const metadataConfigDigest = metadata['containerimage.config.digest'];
  // On identity drift, report whether the payload's reviewed libcrypto byte hash
  // still matches. This distinguishes runtime-library drift from OCI identity drift
  // without weakening the OCI pin.
  let runtimeEvidence;
  const readRuntimeEvidence = () => {
    if (runtimeCheck === undefined) { return {}; }
    if (runtimeEvidence !== undefined) { return runtimeEvidence; }
    const containerName = 'fixlevelup-p05-runtime-probe-' + process.pid;
    const copiedFile = join(work, 'runtime-file-probe');
    let created = false;
    try {
      docker(['create', '--name', containerName, '--network', 'none', tag], {
        safeFailure: 'Could not create an inert container for reviewed runtime hash diagnostics',
      });
      created = true;
      docker(['cp', containerName + ':' + runtimeCheck.path, copiedFile], {
        safeFailure: 'Could not copy the reviewed runtime file for hash diagnostics',
      });
      const runtimeBytes = readFileSync(copiedFile);
      const actualRuntimeSha256 = createHash('sha256').update(runtimeBytes).digest('hex');
      const marker = Buffer.from('built on: ', 'ascii');
      const markerOffset = runtimeBytes.indexOf(marker);
      let opensslBuiltOn = null;
      let sourceDateEpochMatch = null;
      // Investigative window only: reviewed implementation/OCI pins were committed in dd87cb4
      // at 2026-11-22T01:35:27Z; the owner-acceptance commit 225af45 followed at 01:42:25Z.
      // Check this narrow final-review interval; neither commit timestamp is asserted as SOURCE_DATE_EPOCH.
      const searchStart = Math.floor(Date.parse('2026-11-22T01:35:27Z') / 1000);
      const searchEnd = Math.floor(Date.parse('2026-11-22T01:42:25Z') / 1000);
      if (markerOffset >= 0) {
        const dateStart = markerOffset + marker.byteLength;
        const dateEnd = runtimeBytes.indexOf(0, dateStart);
        if (dateEnd > dateStart) {
          opensslBuiltOn = runtimeBytes.subarray(dateStart, dateEnd).toString('ascii');
          const dateLength = dateEnd - dateStart;
          const probeBytes = Buffer.from(runtimeBytes);
          const weekdays = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
          const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
          for (let epoch = searchStart; epoch <= searchEnd; epoch++) {
            const date = new Date(epoch * 1000);
            const day = String(date.getUTCDate()).padStart(2, ' ');
            const candidate = weekdays[date.getUTCDay()] + ' ' + months[date.getUTCMonth()] + ' ' + day
              + ' ' + String(date.getUTCHours()).padStart(2, '0') + ':' + String(date.getUTCMinutes()).padStart(2, '0')
              + ':' + String(date.getUTCSeconds()).padStart(2, '0') + ' ' + date.getUTCFullYear() + ' UTC';
            if (candidate.length !== dateLength) { continue; }
            probeBytes.write(candidate, dateStart, dateLength, 'ascii');
            if (createHash('sha256').update(probeBytes).digest('hex') === runtimeCheck.sha256) {
              sourceDateEpochMatch = new Date(epoch * 1000).toISOString();
              break;
            }
          }
        }
      }
      runtimeEvidence = {
        runtimeFile: runtimeCheck.path,
        expectedRuntimeSha256: runtimeCheck.sha256,
        actualRuntimeSha256,
        runtimeShaMatches: actualRuntimeSha256 === runtimeCheck.sha256,
        opensslBuiltOn,
        sourceDateEpochSearch: {
          startUtc: new Date(searchStart * 1000).toISOString(),
          endUtc: new Date(searchEnd * 1000).toISOString(),
          exactMatchUtc: sourceDateEpochMatch,
        },
      };
    } catch {
      runtimeEvidence = {
        runtimeFile: runtimeCheck.path,
        expectedRuntimeSha256: runtimeCheck.sha256,
        actualRuntimeSha256: null,
        runtimeShaMatches: false,
        runtimeProbe: 'unavailable',
      };
    } finally {
      if (created) {
        try { docker(['rm', '-f', containerName]); }
        catch { process.stderr.write('P05 runtime hash probe cleanup failed\\n'); }
      }
      rmSync(copiedFile, { force: true });
    }
    return runtimeEvidence;
  };
  const failIdentity = (reason, extra = {}) => {
    throw new Error('Rebuilt engine OCI identity mismatch: ' + JSON.stringify({
      reason, expectedConfig: configSha, expectedPlatform: platformSha,
      metadataConfig: safe(metadataConfigDigest), descriptor: safe(descriptorDigest),
      descriptorMediaType: typeof descriptorMediaType === 'string' ? descriptorMediaType.slice(0, 100) : null,
      output: safe(outputDigest), ...readRuntimeEvidence(), ...extra,
    }));
  };
  command('tar', ['-xf', ociTarPath, '-C', layoutPath], {
    safeFailure: 'Could not extract the Buildx OCI image layout',
  });
  const layout = JSON.parse(readFileSync(join(layoutPath, 'oci-layout'), 'utf8'));
  if (layout.imageLayoutVersion !== '1.0.0') { failIdentity('unsupported OCI image-layout version'); }
  const indexBytes = readFileSync(join(layoutPath, 'index.json'));
  const index = JSON.parse(indexBytes.toString('utf8'));
  if (index.schemaVersion !== 2 || index.mediaType !== 'application/vnd.oci.image.index.v1+json'
      || !Array.isArray(index.manifests)) {
    failIdentity('OCI layout index has an unexpected schema or media type', {
      exportIndexSha256: sha256(indexBytes), indexMediaType: index.mediaType ?? null,
    });
  }
  const exportIndexSha256 = sha256(indexBytes);
  const candidates = index.manifests.filter((item) => item?.platform?.os === 'linux'
    && item?.platform?.architecture === 'amd64'
    && item?.mediaType === 'application/vnd.oci.image.manifest.v1+json');
  if (candidates.length !== 1 || candidates[0]?.digest !== platformSha) {
    failIdentity('OCI index does not contain exactly the reviewed linux/amd64 manifest', {
      exportIndexSha256,
      platformDescriptors: candidates.map((item) => ({ digest: safe(item.digest), mediaType: item.mediaType })),
    });
  }
  const readVerifiedBlob = (digest, expectedSize, label) => {
    if (!isDigest(digest)) { failIdentity(label + ' digest is invalid'); }
    const path = join(layoutPath, 'blobs', 'sha256', digest.slice('sha256:'.length));
    const bytes = readFileSync(path);
    if (expectedSize !== undefined && bytes.byteLength !== expectedSize) {
      failIdentity(label + ' blob size does not match its descriptor');
    }
    if (sha256(bytes) !== digest) { failIdentity(label + ' blob content does not match its digest'); }
    return bytes;
  };
  const manifestBytes = readVerifiedBlob(candidates[0].digest, candidates[0].size, 'platform manifest');
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  if (manifest.schemaVersion !== 2 || manifest.mediaType !== 'application/vnd.oci.image.manifest.v1+json'
      || !manifest.config || !Array.isArray(manifest.layers)) {
    failIdentity('reviewed platform manifest has an unexpected structure');
  }
  const configDigest = manifest.config.digest;
  const configBytes = readVerifiedBlob(configDigest, manifest.config.size, 'image config');
  const imageConfig = JSON.parse(configBytes.toString('utf8'));
  if (imageConfig.os !== 'linux' || imageConfig.architecture !== 'amd64') {
    failIdentity('reviewed image config is not linux/amd64', { config: safe(configDigest) });
  }
  if (configDigest !== configSha) {
    failIdentity('OCI manifest config differs from the reviewed config digest', {
      config: safe(configDigest), exportIndexSha256,
    });
  }
  if (metadataConfigDigest !== undefined && metadataConfigDigest !== configDigest) {
    failIdentity('Buildx config metadata differs from OCI manifest config', {
      config: safe(configDigest), metadataConfig: safe(metadataConfigDigest),
    });
  }
  if (descriptorDigest !== platformSha || outputDigest !== platformSha
      || descriptorMediaType !== 'application/vnd.oci.image.manifest.v1+json') {
    failIdentity('Buildx output descriptor does not match the reviewed platform manifest');
  }
  const actual = docker(['image', 'inspect', '--format', '{{.Id}} {{.Os}}/{{.Architecture}}', tag], {
    safeFailure: 'Docker local image inspection failed for the rebuilt pinned engine image',
    includeStderr: true,
  }).trim().split(/\s+/u);
  if (actual[0] !== configSha || actual[1] !== 'linux/amd64') {
    failIdentity('loaded Docker image config differs from the verified OCI image', {
      config: configDigest, loadedConfig: actual[0] ?? null, loadedPlatform: actual[1] ?? null,
      exportIndexSha256,
    });
  }
  if (runtimeCheck !== undefined) {
    const evidence = readRuntimeEvidence();
    if (!evidence.runtimeShaMatches) {
      const reason = evidence.runtimeProbe === 'unavailable'
        ? 'could not verify the reviewed runtime file SHA-256'
        : 'loaded runtime file differs from its reviewed SHA-256';
      failIdentity(reason, evidence);
    }
  }
  // The export index hash is diagnostic only; the original reviewed pair did
  // not preserve a root OCI-index digest separately from the Docker config ID.
  return configDigest;
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
  const buildxVersion = command('docker', ['buildx', 'version']).trim();
  const buildxMatch = /\bv(\d+)\.(\d+)\.(\d+)\b/u.exec(buildxVersion);
  if (!buildxMatch || (Number(buildxMatch[1]) === 0 && Number(buildxMatch[2]) < 13)) {
    throw new Error('Pinned OCI proof requires Docker Buildx 0.13.0 or newer for multiple exporters');
  }
  // The runner's default docker driver cannot export OCI layouts. Use an
  // isolated, digest-pinned BuildKit container; never mutate the default builder.
  buildxBuilderCreated = true;
  docker(['buildx', 'create', '--name', buildxBuilderName, '--driver', 'docker-container',
    '--driver-opt', 'image=' + buildkitImage], { inherit: true });
  const builderInfo = docker(['buildx', 'inspect', '--builder', buildxBuilderName, '--bootstrap']);
  if (!/Driver:\s+docker-container/u.test(builderInfo) || !/BuildKit version:\s+v0\.35\.1\b/u.test(builderInfo)) {
    throw new Error('Digest-pinned OCI proof builder did not bootstrap as BuildKit v0.35.1');
  }

  // Download and cryptographically verify OpenSSL's release tarball before
  // using its pinned hash/patch inputs in the offline scanner build.
  const release = 'https://github.com/openssl/openssl/releases/download/openssl-3.5.9/';
  download(release + 'openssl-3.5.9.tar.gz', join(inputDir, 'openssl-3.5.9.tar.gz'));
  download(release + 'openssl-3.5.9.tar.gz.asc', join(inputDir, 'openssl-3.5.9.tar.gz.asc'));
  download('https://www.openssl-library.org/source/pubkeys.asc', join(gnupgDir, 'pubkeys.asc'));
  command('gpg', ['--homedir', gnupgDir, '--batch', '--import', join(gnupgDir, 'pubkeys.asc')]);
  const keyInfo = command('gpg', ['--homedir', gnupgDir, '--batch', '--with-colons', '--fingerprint', opensslPrimary]);
  const fingerprints = keyInfo.split('\n')
    .filter(line => line.startsWith('fpr:'))
    .map(line => line.split(':')[9])
    .filter(Boolean);
  if (!fingerprints.includes(opensslPrimary)) { throw new Error('OpenSSL signing key primary fingerprint mismatch'); }
  const signature = command('gpg', ['--homedir', gnupgDir, '--batch', '--status-fd=1', '--verify',
    join(inputDir, 'openssl-3.5.9.tar.gz.asc'), join(inputDir, 'openssl-3.5.9.tar.gz')]);
  const validSignature = signature.split('\n').find(line => line.startsWith('[GNUPG:] VALIDSIG '));
  if (validSignature?.split(/\s+/u).at(-1) !== opensslPrimary) {
    throw new Error('OpenSSL release signature is not rooted in the pinned canonical key');
  }

  for (const sha of patchFiles) {
    download('https://github.com/openssl/openssl/commit/' + sha + '.patch', join(inputDir, sha + '.patch'));
  }
  download('https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/libxml2-2.13.9-r3.apk',
    join(inputDir, 'libxml2-2.13.9-r3.apk'));
  copyFileSync(resolve(root, 'infra/file-processing/openssl-inputs.sha256'), join(inputDir, 'openssl-inputs.sha256'));
  command('sha256sum', ['--check', 'openssl-inputs.sha256'], { cwd: inputDir });

  // Preserve the scoped Astra-reviewed identities. The index and child-manifest
  // pins remain fixed; Buildx metadata binds the child manifest to the loaded
  // local config digest without relying on unsupported --platform inspection.
  const review = JSON.parse(readFileSync(resolve(root, 'infra/file-processing/oci-review-evidence.json'), 'utf8'));
  // Backward-compatible review key "indexSha256" is the historical Docker
  // image ID/config digest, as confirmed by the original launcher's .Id check.
  if (review.scanner?.indexSha256 !== SCANNER_CONFIG_SHA.slice(7)
      || review.scanner?.linuxAmd64ManifestSha256 !== SCANNER_PLATFORM_SHA.slice(7)
      || review.decoder?.indexSha256 !== DECODER_CONFIG_SHA.slice(7)
      || review.decoder?.linuxAmd64ManifestSha256 !== DECODER_PLATFORM_SHA.slice(7)) {
    throw new Error('Pinned OCI index/platform digests do not match the reviewed OCI evidence');
  }
  mkdirSync(scannerLayoutPath, { recursive: true });
  mkdirSync(decoderLayoutPath, { recursive: true });
  command('docker', ['buildx', 'build', '--builder', buildxBuilderName, '--platform', 'linux/amd64',
    '--output', 'type=oci,dest=' + scannerOciTarPath, '--load', '--metadata-file', scannerMetadataPath,
    '-f', resolve(root, 'infra/file-processing/ClamAV-libcrypto.Dockerfile'), '-t', scannerTag, inputDir], { inherit: true });
  command('docker', ['buildx', 'build', '--builder', buildxBuilderName, '--platform', 'linux/amd64',
    '--output', 'type=oci,dest=' + decoderOciTarPath, '--load', '--metadata-file', decoderMetadataPath,
    '-f', resolve(root, 'infra/file-processing/Dockerfile'), '-t', decoderTag, root], { inherit: true });
  scannerImageId = exactImage(SCANNER_CONFIG_SHA, SCANNER_PLATFORM_SHA, scannerTag,
    scannerMetadataPath, scannerOciTarPath, scannerLayoutPath, {
      path: '/usr/lib/libcrypto.so.3',
      sha256: review.scanner.libcrypto.runtimeSha256,
    });
  decoderImageId = exactImage(DECODER_CONFIG_SHA, DECODER_PLATFORM_SHA, decoderTag,
    decoderMetadataPath, decoderOciTarPath, decoderLayoutPath);

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
  if (buildxBuilderCreated) {
    try { command('docker', ['buildx', 'rm', '--force', buildxBuilderName]); }
    catch { process.stderr.write('P05 isolated BuildKit builder cleanup failed\n'); }
  }
  rmSync(gnupgDir, { recursive: true, force: true });
  rmSync(inputDir, { recursive: true, force: true });
  rmSync(updateDir, { recursive: true, force: true });
  rmSync(work, { recursive: true, force: true });
  if (!complete) {
    rmSync(snapshotDir, { recursive: true, force: true });
    rmSync(descriptorDir, { recursive: true, force: true });
  }
}
