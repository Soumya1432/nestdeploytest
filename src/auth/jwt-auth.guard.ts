import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
// getRequest(context: ExecutionContext) {
//     const ctx = context.switchToHttp();
//     const request = ctx.getRequest();

//     // Extract JWT from cookie
//     const token = request.cookies?.access_token;
//     if (token) {
//         request.headers.authorization = `Bearer ${token}`;
//     }

//     return request;
// }
