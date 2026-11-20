import { createParamDecorator, InternalServerErrorException, SetMetadata } from '@nestjs/common';
import type { ExecutionContext } from '@nestjs/common';
import { CAPABILITY_METADATA, isCapability } from './capability.js';
import type { Capability } from './capability.js';
import type { AuthorizedRequest } from './authorization.guard.js';
import type { StaffWebPrincipal } from './principal.js';

/** Route-level capability requirement; read by StaffWebAuthGuard via Reflector.
 * Class-level requirements are overridden by the handler-level one.
 */
export const RequireCapability = (capability: Capability): MethodDecorator & ClassDecorator => {
  if (!isCapability(capability)) { throw new Error('Unknown capability'); }
  return SetMetadata(CAPABILITY_METADATA, capability);
};

/** Injects the guard-verified staff-web principal; use only on routes behind StaffWebAuthGuard. */
export const CurrentPrincipal = createParamDecorator(
  (_data: unknown, context: ExecutionContext): StaffWebPrincipal => {
    const request = context.switchToHttp().getRequest<AuthorizedRequest>();
    const principal = request.principal;
    if (!principal) { throw new InternalServerErrorException(); }
    return principal;
  },
);
