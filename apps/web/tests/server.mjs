import { createServer } from 'node:http';
import next from 'next';
import { fileURLToPath } from 'node:url';

const app = next({ dev: false, dir: fileURLToPath(new URL('../', import.meta.url)), hostname: '127.0.0.1', port: 0 });
await app.prepare();
const handle = app.getRequestHandler();
const server = createServer((request, response) => {
  void handle(request, response).catch(() => {
    response.statusCode = 500;
    response.end('Technical request failed');
  });
});
server.listen(0, '127.0.0.1', () => {
  const address = server.address();
  if (!address || typeof address === 'string') { throw new Error('Expected loopback listener'); }
  process.send?.({ port: address.port });
});
process.on('message', (message) => {
  if (message === 'close') {
    server.close(() => {
      void app.close().then(() => { process.disconnect(); }).catch(() => { process.exit(1); });
    });
    server.closeIdleConnections();
  }
});
