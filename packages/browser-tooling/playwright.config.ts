import { defineConfig } from '@playwright/test';
import { resolve } from 'node:path';

const root=resolve(import.meta.dirname,'../..');
const projects= (['chromium','firefox','webkit'] as const).flatMap((browserName)=>[
  {name:`${browserName}-desktop`,use:{browserName,viewport:{width:1280,height:800}}},
  {name:`${browserName}-mobile`,use:{browserName,viewport:{width:390,height:844}}},
]);
export default defineConfig({
  testDir:'./tests',
  fullyParallel:false,
  workers:1,
  retries:0,
  forbidOnly:true,
  timeout:30_000,
  expect:{timeout:5000},
  outputDir:resolve(root,'test-results/browser-smoke'),
  reporter:[['list'],['json',{outputFile:resolve(root,'test-results/browser-smoke.json')}]],
  use:{headless:true,trace:'off',video:'off',screenshot:'off'},
  projects,
  webServer:[
    {command:'node apps/web/scripts/next.mjs start --hostname 127.0.0.1 --port 4170',cwd:root,url:'http://127.0.0.1:4170',reuseExistingServer:false,timeout:30_000},
    {command:'corepack pnpm --filter @fixlevelup/miniapp exec vite preview --host 127.0.0.1 --port 4171 --strictPort',cwd:root,url:'http://127.0.0.1:4171',reuseExistingServer:false,timeout:30_000},
  ],
});
