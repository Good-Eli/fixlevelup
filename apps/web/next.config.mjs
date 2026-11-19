import { resolve } from 'node:path';

/** @type {import('next').NextConfig} */
const config = {
  poweredByHeader: false,
  turbopack: { root: resolve(import.meta.dirname, '../..') },
  experimental: { cpus: 2 },
  async headers() {
    return [{
      source: '/:path*',
      headers: [{ key: 'X-Robots-Tag', value: 'noindex, nofollow, noarchive' }],
    }];
  },
};

export default config;
