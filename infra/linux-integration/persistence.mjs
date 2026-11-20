import { readFileSync } from 'node:fs';
import { createLocalDocker, integrationImage } from './docker.mjs';
const mode=process.argv[2];
if(!['write','verify'].includes(mode)){throw new Error('Expected write or verify');}
const text=readFileSync(new URL('.env',import.meta.url),'utf8');
const env={};
for(const name of ['S3_ACCESS_KEY_ID','S3_SECRET_ACCESS_KEY']){
  const value=new RegExp(`^${name}=([^\\r\\n]+)$`,'m').exec(text)?.[1];
  if(!value||!(name==='S3_ACCESS_KEY_ID'?/^GK[a-f0-9]{24}$/:/^[a-f0-9]{64}$/).test(value)){throw new Error('Invalid isolated credential');}
  env[name]=value;
}
const source=`
import{createRequire}from'node:module';import{createHash}from'node:crypto';
const{S3Client,PutObjectCommand,GetObjectCommand,HeadObjectCommand}=createRequire('/workspace/packages/storage-tooling/package.json')('@aws-sdk/client-s3');
const c=new S3Client({endpoint:'http://127.0.0.1:3900',region:'garage',forcePathStyle:true,credentials:{accessKeyId:process.env.S3_ACCESS_KEY_ID,secretAccessKey:process.env.S3_SECRET_ACCESS_KEY},maxAttempts:1,requestChecksumCalculation:'WHEN_REQUIRED',responseChecksumValidation:'WHEN_REQUIRED',requestHandler:{connectionTimeout:2000,requestTimeout:5000,throwOnRequestTimeout:true,socketTimeout:5000}});
const bytes=Buffer.from('Synthetic isolated Linux S3 persistence marker P01-01.11B'),hash=createHash('sha256').update(bytes).digest('hex'),bucket='fixlevelup-dev-private',key='synthetic/linux-integration/persistence.bin';
try{
 if('${mode}'==='write'){try{await c.send(new HeadObjectCommand({Bucket:bucket,Key:key}));throw new Error('Existing marker');}catch(e){if(e?.$metadata?.httpStatusCode!==404)throw new Error('Marker preflight');}await c.send(new PutObjectCommand({Bucket:bucket,Key:key,Body:bytes,Metadata:{sha256:hash,fixture:'linux-persistence'}}));}
 const r=await c.send(new GetObjectCommand({Bucket:bucket,Key:key})),actual=await r.Body.transformToByteArray();if(!Buffer.from(actual).equals(bytes)||createHash('sha256').update(actual).digest('hex')!==hash||r.Metadata?.sha256!==hash)throw new Error('Mismatch');console.log('Isolated Linux S3 persistence ${mode}: PASS');
}catch{console.error('Isolated S3 persistence proof failed safely');process.exitCode=1;}finally{c.destroy();}
`;
try{
  const docker=createLocalDocker();
  const postgres=docker.assertContainer('postgres');
  docker.assertContainer('garage');
  docker.run(['run','--rm','--network',`container:${postgres}`,
    '-e','S3_ACCESS_KEY_ID','-e','S3_SECRET_ACCESS_KEY','--entrypoint','node',integrationImage,'--input-type=module','--eval',source],
    {env,stdio:'inherit',timeout:30000});
}catch{console.error('Isolated persistence container failed safely');process.exitCode=1;}
