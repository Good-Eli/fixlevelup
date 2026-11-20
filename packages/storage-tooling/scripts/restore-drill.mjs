import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync, lstatSync, realpathSync } from 'node:fs';
import { resolve, parse, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand, ListObjectsV2Command, CreateBucketCommand } from '@aws-sdk/client-s3';
import { loadStorageConfig, makeClient } from './local.mjs';
import { sha256, validateManifest } from './backup-manifest.mjs';
import { databaseDrill } from '../../database-tooling/scripts/restore-proof.mjs';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const suffix = randomBytes(6).toString('hex');
const directory = resolve(root, 'backups', `p0110b-${suffix}`);
const container = `fixlevelup-restore-s3-${suffix}`;
const compose = resolve(root, 'infra/backup/compose.restore.yaml');
const source = loadStorageConfig();
const sourceClient = makeClient(source);
let targetClient, readClient;
let stage = 'preflight';
const env = { ...process.env, RESTORE_SUFFIX: suffix, RESTORE_RPC_SECRET: randomBytes(32).toString('hex') };
function docker(args, expectedFailure = false) {
  const result = spawnSync('docker', args, { env, encoding: 'utf8', timeout: 120_000 });
  if (result.error || (!expectedFailure && result.status !== 0)) { throw new Error('Restore Docker operation failed'); }
  return { status: result.status, output: result.stdout };
}
function command(args) { return docker(['exec', container, '/garage', ...args]).output; }
function client(credentials) {
  return new S3Client({ endpoint: 'http://127.0.0.1:13900', region: 'garage', forcePathStyle: true,
    credentials, maxAttempts: 1, requestChecksumCalculation: 'WHEN_REQUIRED', responseChecksumValidation: 'WHEN_REQUIRED',
    requestHandler: { connectionTimeout: 2000, requestTimeout: 5000, throwOnRequestTimeout: true, socketTimeout: 5000 } });
}
async function rejected(client, operation, expected) {
  try { await client.send(operation); }
  catch (error) {
    if (error?.$metadata?.httpStatusCode === expected) { return; }
    // SDK causes can echo keys or signed URLs; preserve only the fixed error.
    // eslint-disable-next-line preserve-caught-error
    throw new Error('Restore access denial mismatch');
  }
  throw new Error('Restore access unexpectedly granted');
}
const check = (value) => { if (!value) { throw new Error('Synthetic restore comparison failed'); } };
function safeAncestors(path) {
  let current = parse(path).root;
  for (const part of path.slice(current.length).split(sep)) {
    current = resolve(current,part);
    if (existsSync(current)) { const stat=lstatSync(current); check(stat.isDirectory()&&!stat.isSymbolicLink()); }
  }
}
function safeFile(path) { const stat=lstatSync(path); check(stat.isFile()&&!stat.isSymbolicLink()); }
const composeArgs = ['compose','--project-name',container,'-f',compose];
const metadataMatches = (actual, expected) => actual && Object.keys(actual).length === 2
  && actual.sha256 === expected.sha256 && actual.fixture === expected.fixture;
try {
  if (!/^[a-f0-9]{12}$/.test(suffix) || existsSync(directory)) { throw new Error('Unsafe existing backup directory'); }
  // Refuse any running or stopped container publishing the isolated restore port.
  check(docker(['ps', '-aq', '--filter', 'publish=13900']).output.trim() === '');
  check(docker(['inspect', container], true).status !== 0);
  for (const resource of [`${container}-meta`, `${container}-data`]) {
    check(docker(['volume', 'inspect', resource], true).status !== 0);
  }
  check(docker(['network', 'inspect', `${container}-net`], true).status !== 0);
  safeAncestors(directory);
  mkdirSync(resolve(root, 'backups'), { recursive: true, mode: 0o700 });
  mkdirSync(directory, { recursive: false, mode: 0o700 });
  safeAncestors(directory); check(realpathSync.native(directory).toLowerCase()===directory.toLowerCase());
  stage = 'export-synthetic-objects';
  const manifest = { version: 1, suffix, source: { endpoint: source.endpoint, bucket: source.bucket, region: source.region }, objects: [] };
  const sourcePrefix = `synthetic/restore/${suffix}/`;
  // Only new unique synthetic objects are written; existing dev objects are not overwritten/deleted.
  for (const size of [0, 4096, 196608]) {
    const name = `${randomBytes(16).toString('hex')}.bin`, key = `${sourcePrefix}${name}`;
    const bytes = randomBytes(size), metadata = { sha256: sha256(bytes), fixture: 'restore-drill' };
    await sourceClient.send(new PutObjectCommand({ Bucket: source.bucket, Key: key, Body: bytes,
      ContentType: 'application/octet-stream', Metadata: metadata }));
    const object = await sourceClient.send(new GetObjectCommand({ Bucket: source.bucket, Key: key }));
    const exported = await object.Body?.transformToByteArray();
    check(exported && sha256(exported) === metadata.sha256 && Buffer.from(exported).equals(bytes));
    check(object.ContentType === 'application/octet-stream' && metadataMatches(object.Metadata, metadata));
    writeFileSync(resolve(directory, name), exported, { flag: 'wx', mode: 0o600 });
    manifest.objects.push({ key, file: name, bytes: exported.length, sha256: sha256(exported),
      contentType: object.ContentType, metadata: object.Metadata });
  }
  const validated = validateManifest(manifest, suffix);
  writeFileSync(resolve(directory, 'manifest.json'), JSON.stringify(validated, null, 2)+'\n', { flag: 'wx', mode: 0o600 });
  const bucketInfo = JSON.parse(docker(['exec','fixlevelup-dev-s3','/garage','json-api','GetBucketInfo',JSON.stringify({globalAlias:source.bucket})]).output);
  check(bucketInfo.websiteAccess === false && bucketInfo.keys.length === 2
    && JSON.stringify(bucketInfo.globalAliases) === JSON.stringify([source.bucket]));
  const grants = { version: 1, bucket: source.bucket, website: bucketInfo.websiteAccess, keys: [] };
  for (const [role, config, write] of [['readwrite',source,true],['readonly',loadStorageConfig(true),false]]) {
    const actual = bucketInfo.keys.find((key) => key.accessKeyId === config.accessKeyId);
    const keyInfo = JSON.parse(docker(['exec','fixlevelup-dev-s3','/garage','json-api','GetKeyInfo',JSON.stringify({id:config.accessKeyId,showSecretKey:false})]).output);
    check(actual && actual.permissions.read && actual.permissions.write === write && actual.permissions.owner === false
      && keyInfo.permissions.createBucket === false && !keyInfo.secretAccessKey);
    grants.keys.push({ role, read:actual.permissions.read, write:actual.permissions.write,
      owner:actual.permissions.owner, createBucket:keyInfo.permissions.createBucket });
  }
  writeFileSync(resolve(directory, 'access-mapping.json'), JSON.stringify(grants, null, 2)+'\n', { flag: 'wx' });
  // Preserve relevant reproducible config beside logical data; secrets are intentionally not copied.
  for (const [input, output] of [['infra/dev-s3/garage.toml','source-garage.toml'],['infra/backup/garage-restore.toml','restore-garage.toml'],['infra/backup/compose.restore.yaml','compose.restore.yaml']]) {
    writeFileSync(resolve(directory, output), readFileSync(resolve(root, input)), { flag: 'wx' });
  }
  stage = 'database-backup-restore';
  const database = await databaseDrill({ suffix, directory, objects: validated.objects });
  console.log(`Database logical backup/restore: PASS; ${database.source} -> ${database.target}`);

  const keys = grants.keys.map((entry) => ({ ...entry, accessKeyId: `GK${randomBytes(12).toString('hex')}`, secretAccessKey: randomBytes(32).toString('hex') }));
  writeFileSync(resolve(directory, '.env'), `RESTORE_SUFFIX=${suffix}\nRESTORE_RPC_SECRET=${env.RESTORE_RPC_SECRET}\n`+
    keys.map((key) => `${key.role.toUpperCase()}_ACCESS_KEY_ID=${key.accessKeyId}\n${key.role.toUpperCase()}_SECRET_ACCESS_KEY=${key.secretAccessKey}`).join('\n')+'\n', { flag: 'wx', mode: 0o600 });
  stage = 'isolated-garage-bootstrap';
  docker([...composeArgs, 'config', '--quiet']);
  const resolved=JSON.parse(docker([...composeArgs,'config','--format','json']).output);
  const service=resolved.services.garage;
  check(resolved.name===container&&service.container_name===container
    &&service.image==='dxflrs/garage:v2.5.0@sha256:677e5b758e4425a325b811c425c026bf35a4bf42f7ddbaa773de3f4fd779a5a5'
    &&service.ports.length===1&&service.ports[0].host_ip==='127.0.0.1'&&String(service.ports[0].published)==='13900'
    &&resolved.volumes['garage-meta'].name===`${container}-meta`&&resolved.volumes['garage-data'].name===`${container}-data`
    &&resolved.networks['restore-net'].name===`${container}-net`);
  docker([...composeArgs, 'up', '-d', '--wait', '--wait-timeout', '90']);
  check(docker(['inspect','--format','{{index .Config.Labels "com.docker.compose.project"}}',container]).output.trim() === container);
  command(['bucket','create',grants.bucket]);
  for (const key of keys) {
    command(['key','import','--yes','-n',`restore-${key.role}`,key.accessKeyId,key.secretAccessKey]);
    command(['key','deny','--create-bucket',key.accessKeyId]);
    command(['bucket','allow','--read',...(key.write?['--write']:[]),'--key',key.accessKeyId,grants.bucket]);
  }
  const targetInfo=JSON.parse(command(['json-api','GetBucketInfo',JSON.stringify({globalAlias:grants.bucket})]));
  check(targetInfo.websiteAccess===false&&targetInfo.keys.length===2&&JSON.stringify(targetInfo.globalAliases)===JSON.stringify([grants.bucket]));
  for(const key of keys){
    const actual=targetInfo.keys.find((entry)=>entry.accessKeyId===key.accessKeyId);
    const info=JSON.parse(command(['json-api','GetKeyInfo',JSON.stringify({id:key.accessKeyId,showSecretKey:false})]));
    check(actual&&actual.permissions.read===key.read&&actual.permissions.write===key.write&&actual.permissions.owner===false
      &&info.permissions.createBucket===false&&!info.secretAccessKey);
  }
  targetClient = client(keys[0]); readClient = client(keys[1]);
  check((await targetClient.send(new ListObjectsV2Command({ Bucket: grants.bucket }))).KeyCount === 0);
  stage = 's3-restore-and-compare';
  // Reload actual on-disk manifest and validate every file BEFORE importing any object.
  safeAncestors(directory); safeFile(resolve(directory,'manifest.json'));
  const disk = validateManifest(JSON.parse(readFileSync(resolve(directory,'manifest.json'),'utf8')), suffix);
  const artifacts = disk.objects.map((entry) => {
    safeFile(resolve(directory,entry.file));
    const bytes = readFileSync(resolve(directory,entry.file));
    check(bytes.length === entry.bytes && sha256(bytes) === entry.sha256);
    return { entry, bytes };
  });
  for (const {entry,bytes} of artifacts) {
    await targetClient.send(new PutObjectCommand({ Bucket: grants.bucket, Key: entry.key, Body: bytes,
      ContentType: entry.contentType, Metadata: entry.metadata }));
  }
  for (const entry of disk.objects) {
    const restored = await targetClient.send(new GetObjectCommand({ Bucket: grants.bucket, Key: entry.key }));
    const bytes = await restored.Body?.transformToByteArray();
    check(bytes && bytes.length === entry.bytes && sha256(bytes) === entry.sha256);
    check(restored.ContentType === entry.contentType && metadataMatches(restored.Metadata, entry.metadata));
    const head = await targetClient.send(new HeadObjectCommand({ Bucket: grants.bucket, Key: entry.key }));
    check(head.ContentLength === entry.bytes);
    const readonly = await readClient.send(new GetObjectCommand({ Bucket: grants.bucket, Key: entry.key }));
    check(sha256(await readonly.Body.transformToByteArray()) === entry.sha256);
  }
  const listed = await targetClient.send(new ListObjectsV2Command({ Bucket: grants.bucket, Prefix: sourcePrefix }));
  check(JSON.stringify(listed.Contents.map((entry)=>entry.Key).sort())===JSON.stringify(disk.objects.map((entry)=>entry.key).sort()));
  const deniedKey = `${sourcePrefix}denied.bin`;
  await rejected(readClient,new PutObjectCommand({Bucket:grants.bucket,Key:deniedKey,Body:Buffer.from('denied')}),403);
  await rejected(targetClient,new GetObjectCommand({Bucket:grants.bucket,Key:deniedKey}),404);
  await rejected(targetClient,new CreateBucketCommand({Bucket:`restore-noowner-${suffix}`}),403);
  const anonymous = await fetch(`http://127.0.0.1:13900/${grants.bucket}/${disk.objects[0].key}`,{signal:AbortSignal.timeout(5000)});
  check(anonymous.status===403); await anonymous.body?.cancel();
  // Source credentials must not silently authorize the separate restore service.
  const oldKeyClient=client(source);
  try { await rejected(oldKeyClient,new GetObjectCommand({Bucket:grants.bucket,Key:disk.objects[0].key}),403); }
  finally { oldKeyClient.destroy(); }
  const evidence={version:1,suffix,directory: `backups/p0110b-${suffix}`,database,storage:{source:source.endpoint,target:'http://127.0.0.1:13900',bucket:grants.bucket,objects:disk.objects.length,manifestSha256:sha256(readFileSync(resolve(directory,'manifest.json'))),checksums:true,metadata:true,grants:true,oldCredentialsRejected:true},limitations:['logical synthetic drill','local unencrypted artifacts','no off-host durability/RPO/RTO claim','no physical Garage metadata restore']};
  writeFileSync(resolve(directory,'evidence.json'),JSON.stringify(evidence,null,2)+'\n',{flag:'wx'});
  console.log(`S3 logical export/restore bytes/SHA256/metadata/grants: PASS; objects=${disk.objects.length}`);
  console.log(`Evidence retained in backups/p0110b-${suffix}; test DBs/container/volumes retained, no cleanup.`);
} catch (error) {
  if (typeof error?.message === 'string' && /^Database restore drill failed at [a-z-]+; details suppressed; isolated databases\/artifacts retained \(fixlevelup_p0110b_source_[a-f0-9]{12}, fixlevelup_p0110b_restore_[a-f0-9]{12}\)$/.test(error.message)) { console.error(error.message); }
  console.error(`Synthetic restore drill failed at ${stage}; isolated suffix=${suffix}; resources/artifacts preserved, raw errors suppressed.`);
  process.exitCode=1;
} finally { sourceClient.destroy(); targetClient?.destroy(); readClient?.destroy(); }
