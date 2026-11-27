/**
 * P05-02 form-session module surface.
 *
 * Public exports of the F-session slice: the pure protocol contract
 * (wire names, typed refusals, body validators), the cookie/CSRF/advisory
 * helpers, the exact route table, the core `FormSessionService` and the Nest
 * HTTP controller with its DI token.
 *
 * The module deliberately registers nothing: wiring into `AppModule`, the
 * readiness gates and the test harness composition belong to the integration
 * step, where the lead binds `FORM_SESSION_HTTP_DEPS` and the configuration.
 */

export type {
  ConsentAction, ConsentBody, ConsentGivenBody, ConsentRevokedBody, DistrictCheckBody, FormSessionErrorCode,
  LegalKindParam,
} from './contract.js';
export {
  bindIdempotencyKey, consentBody, districtCheckBody, emptyObjectBody, F_COOKIE_PREFIX, F_CSRF_DOMAIN, F_CSRF_HEADER,
  F_GROUP_COOKIE, F_IDEMPOTENCY_HEADER, F_MAX_COOKIE_BYTES, F_MAX_F_COOKIES, F_MAX_LIVE_ANCHORS_PER_GROUP,
  F_SELECTOR_HEADER, FormSessionError, idempotencyKey, legalKindParam, rejectPersonalFields,
} from './contract.js';
export { formatHostCookie, parseCookieHeader, readFormCookies, readGroupCookie } from './cookies.js';
export type { FormCookie } from './cookies.js';
export { issueCsrfProof, verifyCsrfProof } from './csrf.js';
export type { FormCsrfKey, FormCsrfKeyring } from './csrf.js';
export { adviseDistrict } from './advisory.js';
export type { AdvisoryCoverage, AdvisoryReader } from './advisory.js';
export {
  matchP05FormSessionRoute, P05_F_BODY_LIMIT_BYTES, P05_F_JSON_MAX_DEPTH, P05_F_JSON_MAX_NODES,
  P05_F_JSON_RESPONSE_LIMIT_BYTES, P05_F_RESPONSE_LIMIT_BYTES, P05_FORM_SESSION_PREFIX, parseStrictP05Json,
  payloadTooLarge,
} from './routes.js';
export type { P05FormSessionOperation, P05FormSessionRoute } from './routes.js';
export { FormSessionController, FORM_SESSION_HTTP_DEPS } from './controller.js';
export type {
  FormSessionHttpConfig, FormSessionHttpDeps, FormSessionReadiness,
} from './controller.js';
export { FormSessionService } from './service.js';
export type {
  BrowserBootstrapResult, ConsentResult, CoverageResult, CsrfBootstrapResult, FormSessionApi, FormSessionBaseInput,
  FormSessionConfig, FormSessionConsentInput, FormSessionPool, FormSessionSelectorInput, FormSessionAuthError,
  FormThrottleBudget, IssueSessionResult, LegalDocumentPublic, RevokeResult,
} from './service.js';
