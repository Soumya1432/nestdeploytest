import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';
import { DatabaseService } from 'src/database/database.service';
import { jwtConstants } from './constants/jwt-contstant';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(private readonly databaseService: DatabaseService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => {
          const token = request?.cookies?.Authentication;
          this.logger.debug(
            `Extracted Authentication token: ${token ? 'Present' : 'Missing'}`,
          );
          return token || null;
        },
      ]),
      ignoreExpiration: false,
      secretOrKey: jwtConstants.accessTokenSecret,
    });
  }

  async validate(payload: any) {
    this.logger.debug('Validating access token with payload:', payload);

    if (!payload?.id) {
      this.logger.error(`Invalid or missing UUID in payload.id: ${payload.id}`);
      throw new UnauthorizedException('Invalid token payload');
    }

    this.logger.debug(`Fetching user for id: ${payload.id}`);
    const user = await this.databaseService.user.findUnique({
      where: { id: payload.id, deletedAt: null },
    });

    if (!user) {
      this.logger.error(`User not found for id: ${payload.id}`);
      throw new UnauthorizedException('Invalid token');
    }

    this.logger.debug(
      `Access token validated successfully for user: ${user.email}`,
    );
    return {
      id: user.id,
      email: user.email,
      role: user.role,
    };
  }
}
