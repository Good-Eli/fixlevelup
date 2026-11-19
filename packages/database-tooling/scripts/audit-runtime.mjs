import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectRuntimeGraph, inspectCompiledImports } from './runtime-graph.mjs';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const packages = inspectRuntimeGraph(resolve(root, 'apps/api/package.json'));
inspectCompiledImports(resolve(root, 'apps/api/dist'));
mkdirSync(resolve(root, 'node_modules/.cache/prisma-foundation-audit'), { recursive: true });
writeFileSync(resolve(root, 'node_modules/.cache/prisma-foundation-audit/api-runtime.json'), JSON.stringify(packages, null, 2) + '\n');
console.log(`API production graph checked: ${String(packages.length)} installed dependency/optional/peer packages and compiled imports; no CLI/Studio/React/Visx.`);
