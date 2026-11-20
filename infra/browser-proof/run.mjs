import { spawnSync } from 'node:child_process';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
const hash=()=>createHash('sha256').update(readFileSync('pnpm-lock.yaml')).digest('hex');
const lock=hash(),steps=[];
const evidence='/workspace/node_modules/.cache/browser-proof';
function run(name,args){
  console.log(`Browser proof: ${name}`);
  const r=spawnSync('corepack',['pnpm',...args],{stdio:'inherit',timeout:600000});
  if(r.error||r.status!==0||r.signal){throw new Error(`Browser proof failed: ${name}`);}
  if(hash()!==lock){throw new Error('Browser proof lock changed');}
  steps.push(name);
}
try{
  if(process.platform!=='linux'||process.arch!=='x64'||process.version!=='v24.22.3'){throw new Error('Unexpected browser proof runtime');}
  const req=createRequire(new URL('../../packages/browser-tooling/package.json',import.meta.url));
  if(req('@playwright/test/package.json').version!=='1.65.1'){throw new Error('Browser package mismatch');}
  run('offline frozen install',['install','--frozen-lockfile','--offline','--ignore-scripts','--strict-peer-dependencies']);
  run('browser lint/typecheck',['exec','eslint','packages/browser-tooling','infra/browser-proof','--max-warnings','0']);
  run('browser typecheck',['--filter','@fixlevelup/browser-tooling','run','typecheck']);
  run('all production builds',['run','build']);
  run('real browser smoke',['--filter','@fixlevelup/browser-tooling','run','test']);
  mkdirSync(evidence,{recursive:true});
  writeFileSync(`${evidence}/result.json`,JSON.stringify({node:process.version,platform:process.platform,playwright:'1.65.1',lockSha256:lock,network:'none',steps,status:'passed',limitations:['technical pages only','no Telegram integration','no remote CI','no full a11y/UX acceptance']},null,2)+'\n');
  console.log('Browser technical smoke: PASS');
}catch(error){console.error(error instanceof Error?error.message:'Browser proof failed');process.exitCode=1;}
