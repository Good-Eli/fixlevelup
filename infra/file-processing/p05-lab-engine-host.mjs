// Operator-only bridge for the isolated C lifecycle regression. One session,
// exactly one known synthetic PNG and three consecutive engine operations.
// No listening socket, DB credentials, command strings, client-chosen paths,
// images or engine limits. The child result is the real pinned launcher's.
import { createHash } from 'node:crypto';
import diagnostics from 'node:diagnostics_channel';
import { link, lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createFileProcessingTestLauncher } from './docker-test-launcher.mjs';

const deny = () => { throw new Error('Invalid one-use engine fixture'); };
const sha = b => createHash('sha256').update(b).digest('hex');
const ticket = process.env.FIXLEVELUP_LAB_ENGINE_TICKET ?? '';
const owner = resolve(process.env.FIXLEVELUP_LAB_ENGINE_EXCHANGE ?? '');
if (!/^[a-f0-9]{32}$/u.test(ticket) || basename(owner)!=='p05-engine-jobs' || basename(dirname(owner))!=='.cache'
    || basename(dirname(dirname(owner)))!=='node_modules' || await realpath(owner)!==owner) { deny(); }
const dir = join(owner,ticket);
await mkdir(dir,{mode:0o700}); // existing request or old results are never re-used
const descriptorRoot = resolve('node_modules/.cache/p0304cde');
const descriptorPath = resolve(process.env.FIXLEVELUP_LAB_ENGINE_DESCRIPTOR ?? '');
const descriptorSha256 = process.env.FIXLEVELUP_LAB_ENGINE_DESCRIPTOR_SHA256 ?? '';
if (!descriptorPath.startsWith(descriptorRoot + sep) || await realpath(descriptorPath)!==descriptorPath
    || !/^[a-f0-9]{64}$/u.test(descriptorSha256)) { deny(); }
const descriptorBytes = await readFile(descriptorPath);
if (sha(descriptorBytes)!==descriptorSha256) { deny(); }
// Record names from this Node process only, for exact-ID post-test cleanup.
diagnostics.subscribe('tracing:child_process.spawn:start', ({process:child}) => {
  const args=child.spawnargs;
  if (args[0]==='docker' && args[1]==='create' && args[2]==='--name' && /^fixlevelup-p0304cde-(?:defs-version|scan|decode)-[a-f0-9-]{36}$/u.test(args[3])) {
    console.log('ENGINE_CONTAINER '+args[3]);
  }
});
const descriptor=JSON.parse(descriptorBytes);
const {launcher,epoch}=await createFileProcessingTestLauncher(descriptor);
async function publish(name,value){
  const tmp=join(dir,name+'.host-tmp');await writeFile(tmp,JSON.stringify(value),{flag:'wx',mode:0o600});await link(tmp,join(dir,name));
}
await publish('ready.json',{ticket,epoch});
console.log('ENGINE_READY');
const deadline=performance.now()+190_000;
async function readRequest(n){
  const path=join(dir,String(n)+'.req');
  for (;;) {
    if (performance.now()>=deadline) { deny(); }
    try {
      const s=await lstat(path);
      if (!s.isFile() || s.size>100_000 || s.size<1 || await realpath(dir)!==dir || await realpath(path)!==path) { deny(); }
      return await readFile(path);
    } catch(error){if(error.code!=='ENOENT'){throw error;}}
    await delay(50);
  }
}
function bytes(text,max){
  if(typeof text!=='string' || text.length>4*Math.ceil(max/3)){deny();}
  const b=Buffer.from(text,'base64');if(!b.length || b.length>max || b.toString('base64')!==text){deny();}return b;
}
let raw,served;
for(const [n,op] of ['raw-scan','decode','output-scan'].entries()){
  const input=await readRequest(n), request=JSON.parse(input);
  if(Object.keys(request).sort().join(',')!=='op,parts,ticket' || request.ticket!==ticket || request.op!==op
      || !Array.isArray(request.parts) || request.parts.length!==(n===1?3:1)){deny();}
  const signal=AbortSignal.timeout(45_000);let result;
  if(n===0){
    raw=bytes(request.parts[0],64_000);
    if(raw.length<32 || raw.subarray(0,8).toString('hex')!=='89504e470d0a1a0a' || raw.readUInt32BE(16)!==9 || raw.readUInt32BE(20)!==5 || !raw.includes('SYNTHETIC_PRIVACY_MARKER')){deny();}
    result=await launcher.scan(raw,epoch,signal);
  }else if(n===1){
    const prefix=bytes(request.parts[0],4), hdr=bytes(request.parts[1],1024), payload=bytes(request.parts[2],64_000);
    const expected=JSON.stringify({v:1,mime:'image/png',inputBytes:raw.length,maxOutputBytes:64_000,maxWidth:128,maxHeight:128,maxPixels:16_384,maxChannels:4});
    if(prefix.byteLength!==4 || prefix.readUInt32BE()!==hdr.length || hdr.toString()!==expected || !raw.equals(payload)){deny();}
    result=await launcher.decode([prefix,hdr,payload],64_000,signal);served=Buffer.from(result.stdout);
  }else{
    const payload=bytes(request.parts[0],64_000);if(!served?.length || !served.equals(payload)){deny();}result=await launcher.scan(payload,epoch,signal);
  }
  await publish(String(n)+'.res',{ticket,requestSha256:sha(input),...result,stdout:Buffer.from(result.stdout).toString('base64'),stderr:Buffer.from(result.stderr).toString('base64')});
  console.log(`${op} exit=${String(result.exitCode)} reaped=${String(result.reaped)} inputSha256=${sha(input)}`);
  if(result.exitCode!==0 || result.reaped!==true){deny();}
}
console.log(`ENGINE_COMPLETE raw=${sha(raw)} served=${sha(served)}`);
