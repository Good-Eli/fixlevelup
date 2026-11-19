import { Controller, Get, Header, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { RuntimeDatabase } from '../infrastructure/database/runtime-database.js';

@Injectable()
export class HealthService {
  live(): { status: 'ok' } {
    return { status: 'ok' };
  }
}

@Controller('health')
export class HealthController {
  constructor(private readonly health: HealthService, private readonly database: RuntimeDatabase) {}

  @Get('live')
  @Header('Cache-Control', 'no-store')
  live(): { status: 'ok' } {
    return this.health.live();
  }

  @Get('ready')
  @Header('Cache-Control', 'no-store')
  async ready(): Promise<{ status: 'ok' }> {
    if (!await this.database.ready()) { throw new ServiceUnavailableException(); }
    return { status: 'ok' };
  }
}
