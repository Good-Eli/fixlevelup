import { Controller, Get, Header, Injectable, ServiceUnavailableException } from '@nestjs/common';

@Injectable()
export class HealthService {
  live(): { status: 'ok' } {
    return { status: 'ok' };
  }
}

@Controller('health')
export class HealthController {
  constructor(private readonly health: HealthService) {}

  @Get('live')
  @Header('Cache-Control', 'no-store')
  live(): { status: 'ok' } {
    return this.health.live();
  }

  @Get('ready')
  @Header('Cache-Control', 'no-store')
  ready(): never {
    // Actual DB/schema readiness belongs to the PostgreSQL foundation step.
    throw new ServiceUnavailableException();
  }
}
