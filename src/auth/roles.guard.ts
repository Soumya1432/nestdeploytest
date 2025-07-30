import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Role } from '@prisma/client';

@Injectable()
// export class RolesGuard implements CanActivate {
//   canActivate(context: ExecutionContext): boolean {
//     const requiredRoles = this.getRoles(context);
//     const { user } = context.switchToHttp().getRequest();
//     return requiredRoles.includes(user.role);
//   }

//   private getRoles(context: ExecutionContext): string[] {
//     const handler = context.getHandler();
//     return this.reflector.getAllAndOverride<Role[]>('roles', [handler]) || [];
//   }

//   constructor(private reflector: Reflector) {}
// }
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>('roles', [
      context.getHandler(),
      context.getClass(),
    ]);

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!requiredRoles || requiredRoles.length === 0) return true;

    if (!user) return false; // No user found on request

    return requiredRoles.includes(user.role);
  }
}
