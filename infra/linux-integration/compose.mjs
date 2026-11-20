import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

// --env-file alone does not beat shell precedence. Explicitly set every
// interpolated secret from this NEW stand's ignored env, never ambient dev values.
const source=readFileSync(new URL('.env',import.meta.url),'utf8');
const patterns={POSTGRES_PASSWORD:/^[a-f0-9]{64}$/,GARAGE_RPC_SECRET:/^[a-f0-9]{64}$/,
  S3_ACCESS_KEY_ID:/^GK[a-f0-9]{24}$/,S3_SECRET_ACCESS_KEY:/^[a-f0-9]{64}$/,
  S3_READONLY_ACCESS_KEY_ID:/^GK[a-f0-9]{24}$/,S3_READONLY_SECRET_ACCESS_KEY:/^[a-f0-9]{64}$/};
const env={...process.env};
for(const key of Object.keys(env)){if(key.startsWith('COMPOSE_')||key==='DOCKER_HOST'||key==='DOCKER_CONTEXT'){delete env[key];}}
for(const[name,pattern]of Object.entries(patterns)){
  const value=new RegExp(`^${name}=([^\\r\\n]+)$`,'m').exec(source)?.[1];
  if(!value||!pattern.test(value)){throw new Error('Invalid isolated integration credentials');}
  env[name]=value;
}
const commands={
  validate:['config','--quiet'],
  build:['build','runner'],
  services:['up','-d','--wait','--wait-timeout','90','postgres','garage'],
  run:['up','--no-deps','--abort-on-container-exit','--exit-code-from','runner','runner'],
};
const args=commands[process.argv[2]];
if(!args){throw new Error('Unsupported isolated integration Compose command');}
const result=spawnSync('docker',['--host','npipe:////./pipe/dockerDesktopLinuxEngine','compose','--project-name','fixlevelup-linux-integration','-f','infra/linux-integration/compose.yaml',...args],
  {cwd:new URL('../../',import.meta.url),env,stdio:'inherit',timeout:1_200_000});
if(result.error){console.error('Isolated Compose operation failed; details suppressed.');process.exitCode=1;}
else{process.exitCode=result.status??1;}
