import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../../generated/prisma/client.js';

export interface FoundationConnection {
  readonly host: string;
  readonly port: number;
  readonly database: string;
  readonly user: string;
  readonly password: string;
}

// This foundation proof deliberately cannot target another host or database.
// General application DB configuration belongs to the subsequent integration.
export function createFoundationClient(config: FoundationConnection) {
  if (config.host !== '127.0.0.1' || config.port !== 55432
    || config.database !== 'fixlevelup_dev' || config.user !== 'fixlevelup_dev'
    || !/^[a-f0-9]{64}$/.test(config.password)) {
    throw new Error('Invalid foundation database configuration');
  }
  const adapter = new PrismaPg({
    host: config.host,
    port: config.port,
    database: config.database,
    user: config.user,
    password: config.password,
    max: 2,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 1000,
    statement_timeout: 5000,
    options: '-c default_transaction_read_only=on',
    application_name: 'fixlevelup-prisma-foundation',
  });
  return new PrismaClient({ adapter, log: [], errorFormat: 'minimal' });
}
