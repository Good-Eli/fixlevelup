import { build } from 'vite';
import { fileURLToPath } from 'node:url';

// An unprefixed synthetic server value must never appear in browser artifacts.
process.env['MINIAPP_SERVER_CANARY'] = 'synthetic-miniapp-server-secret';
await build({ root: fileURLToPath(new URL('../', import.meta.url)) });
