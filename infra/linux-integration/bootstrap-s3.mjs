import { readFileSync } from 'node:fs';
import { createLocalDocker } from './docker.mjs';
try{
  const docker=createLocalDocker();
  const container=docker.assertContainer('garage');
  const command=(args)=>docker.run(args).stdout;
  const text=readFileSync(new URL('.env',import.meta.url),'utf8');
  const get=(name,pattern)=>{const v=new RegExp(`^${name}=([^\\r\\n]+)$`,'m').exec(text)?.[1];if(!v||!pattern.test(v)){throw new Error('Invalid isolated credential');}return v;};
  const garage=(args)=>command(['exec',container,'/garage',...args]);
  const bucket='fixlevelup-dev-private';
  if(!garage(['bucket','list']).includes(bucket)){garage(['bucket','create',bucket]);}
  for(const [prefix,write]of[['S3_',true],['S3_READONLY_',false]]){
    const id=get(prefix+'ACCESS_KEY_ID',/^GK[a-f0-9]{24}$/),secret=get(prefix+'SECRET_ACCESS_KEY',/^[a-f0-9]{64}$/);
    if(!garage(['key','list']).includes(id)){garage(['key','import','--yes','-n',write?'integration-rw':'integration-ro',id,secret]);}
    garage(['key','deny','--create-bucket',id]);
    garage(['bucket','deny','--read','--write','--owner','--key',id,bucket]);
    garage(['bucket','allow','--read',...(write?['--write']:[]),'--key',id,bucket]);
    const info=JSON.parse(garage(['json-api','GetKeyInfo',JSON.stringify({id,showSecretKey:false})]));
    const grant=info.buckets.find(b=>b.globalAliases.includes(bucket));
    if(info.permissions.createBucket!==false||!grant||grant.permissions.read!==true||grant.permissions.write!==write||grant.permissions.owner!==false){throw new Error('Isolated grants mismatch');}
  }
  console.log('Isolated Linux Garage bucket readwrite/readonly grants configured; keys suppressed.');
}catch{console.error('Isolated Garage bootstrap failed safely; no raw output/credentials printed.');process.exitCode=1;}
