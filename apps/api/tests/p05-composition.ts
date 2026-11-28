import 'reflect-metadata';
import { Module } from '@nestjs/common';
import type { INestApplication, OnModuleDestroy } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { ProcessAuthorization } from '../src/infrastructure/admission/process-admission.js';
import { admittedPool, requireRequestEffectsPool } from '../src/infrastructure/admission/pool-guard.js';
import type { GuardedPool } from '../src/infrastructure/admission/pool-guard.js';
import { RuntimeDatabase } from '../src/infrastructure/database/runtime-database.js';
import type { DatabaseConfig } from '../src/infrastructure/database/runtime-database.js';
import { AuthorizationService } from '../src/authz/authorization.service.js';
import { FormSessionController, FORM_SESSION_HTTP_DEPS } from '../src/form-session/controller.js';
import { FormSessionService } from '../src/form-session/service.js';
import type { FormSessionConfig } from '../src/form-session/service.js';
import { RequestIntake } from '../src/requests/intake/service.js';
import type { RequestIntakeConfig } from '../src/requests/intake/service.js';
import { intakeBody, IntakeProblemFilter, REQUEST_INTAKE_HTTP, RequestIntakeController } from '../src/requests/intake/http.js';
import type { WebAuthHttpConfig } from '../src/auth/web-auth.controller.js';

@Module({})
class IsolatedIntakeModule {}

/** Separate T input graph. No dynamic ENV switches or fixture ports in R. The
 * only way to construct a test pool is an exact completed launch to an attested
 * S3 disposable instance. The caller owns the launcher; T owns its own pools. */
export async function startIsolatedIntake(options: {
  readonly target: DatabaseConfig; readonly authorization: ProcessAuthorization; readonly form: FormSessionConfig;
  readonly staff: WebAuthHttpConfig; readonly tls: { readonly key: Buffer; readonly cert: Buffer };
  readonly configure: (audit: GuardedPool) => RequestIntakeConfig;
}): Promise<{ app: INestApplication; service: RequestIntake; filePool: GuardedPool }> {
  const { target, authorization } = options;
  const { expected } = authorization.admission.binding;
  if ((expected.consumerKind !== 'API' && expected.consumerKind !== 'TEST') || !Object.is(target.host,'127.0.0.1') || target.port !== 55432
    || !/^fixlevelup_(?:configuration_test_[0-9a-f]{24}|p05_[a-z0-9_]{1,48})$/.test(target.database)
    || process.env['FIXLEVELUP_SYNTHETIC_ORCHESTRATOR'] !== '1' || options.tls.cert.length === 0 || options.tls.key.length === 0) {
    throw new Error('Invalid isolated intake composition');
  }
  const kind = expected.consumerKind;
  const pool = (name: string, max: number) => admittedPool({ authorization,kind },target,{ application_name:name,max,
    connectionTimeoutMillis:2000,query_timeout:6500,statement_timeout:6000,idleTimeoutMillis:1000,options:'-c lock_timeout=5000' });
  const business = pool('fixlevelup-intake-isolated',4);
  const audit = pool('fixlevelup-intake-audit-isolated',1);
  const readiness = new RuntimeDatabase(target,true,authorization,kind);
  let app: INestApplication | undefined;
  let closed = false;
  const resources: OnModuleDestroy = { async onModuleDestroy() {
    if (closed) { return; }
    closed = true;
    await Promise.all([business.end(),audit.end(),readiness.onModuleDestroy()]);
  } };
  try {
    requireRequestEffectsPool(business);
    requireRequestEffectsPool(audit);
    const cluster = process.env['FIXLEVELUP_CLUSTER_NAME'] ?? '';
    if (!/^fixlevelup_p05s4_lab_[a-z0-9_]{1,40}$/.test(cluster)) { throw new Error('Missing isolated cluster binding'); }
    const { rows:[identity] } = await business.query<{ valid: boolean }>(`SELECT current_database()=$1
      AND current_user='fixlevelup_runtime' AND session_user=current_user AND current_setting('cluster_name')=$2
      AND current_setting('server_version_num')='180007' AS valid`,[target.database,cluster]);
    if (identity?.valid !== true || !await readiness.requestEffectsReady()) { throw new Error('Isolated S3 is not ready'); }
    const config = options.configure(audit);
    const search = config.search;
    const form = new FormSessionService(business,{ ...options.form,
      ...(search ? { afterProcessingRevoked:(client,sessionId,consentId) => search.removeProcessingConsent(client,sessionId,consentId) } : {}),
    });
    const service = new RequestIntake(business,form,new AuthorizationService(business),config);
    const module = {module:IsolatedIntakeModule,controllers:[FormSessionController,RequestIntakeController],providers:[
      {provide:'P05_TEST_RESOURCES',useValue:resources},
      {provide:FORM_SESSION_HTTP_DEPS,useValue:{service:form,database:readiness,config:{origin:options.form.origin}}},
      {provide:REQUEST_INTAKE_HTTP,useValue:{service,readiness,origin:options.form.origin,staff:options.staff}},
    ]};
    // Nest commonly takes structural options here, not a class instance.
    // eslint-disable-next-line @typescript-eslint/no-unsafe-class-instance-assignment
    app = await NestFactory.create(module,{ bodyParser:false,logger:false,abortOnError:false,httpsOptions:options.tls });
    const server = app.getHttpAdapter().getInstance() as { disable(name: string): void };
    server.disable('x-powered-by');
    server.disable('etag');
    app.use(intakeBody(readiness));
    app.useGlobalFilters(new IntakeProblemFilter());
    await app.listen(0,'127.0.0.1');
    return { app,service,filePool:business };
  } catch (error) {
    try { await app?.close(); } finally { await resources.onModuleDestroy(); }
    throw error;
  }
}
