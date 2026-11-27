import { ServiceUnavailableException } from '@nestjs/common';
import type { HttpException } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import type { StaffRequest } from '../auth/http.js';
import { boundedJson, closeAfterProblem, readBoundedJson } from '../settings/management/body-parser.js';
import { matchP05FormSessionRoute, P05_F_BODY_LIMIT_BYTES, parseStrictP05Json } from './routes.js';

interface FormSessionBodyReadiness {
  requestIntakeReady(): Promise<boolean>;
  formSessionReady(): Promise<boolean>;
}

/** Only composition T installs this parser; R does not import F wire code. */
export function boundedJsonForFormSession(readiness: FormSessionBodyReadiness) {
  return (req: StaffRequest, res: ServerResponse, next: (error?: HttpException) => void): void => {
    const method = req.method ?? '';
    const url = req.url ?? '';
    const route = matchP05FormSessionRoute(method,url);
    const withinNamespace = /^\/api\/v1\/public(?:\/|$)/i.test(url);
    if (!route && !withinNamespace) { boundedJson(req,res,next); return; }
    const read = () => {
      if (!res.destroyed) { readBoundedJson(req,res,next,{ limit:route?.bodyLimit ?? P05_F_BODY_LIMIT_BYTES,
        decode:parseStrictP05Json,forbidBody:method === 'GET' || method === 'HEAD' }); }
    };
    if (!route) { read(); return; }
    void Promise.resolve().then(async () => {
      if (!await readiness.requestIntakeReady() || !await readiness.formSessionReady()) { throw new ServiceUnavailableException(); }
    }).then(read, () => {
      if (!res.destroyed) { closeAfterProblem(req,res); next(new ServiceUnavailableException()); }
    });
  };
}
