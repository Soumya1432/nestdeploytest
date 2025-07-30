//  fully working with correct setup
import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';
import { DatabaseService } from 'src/database/database.service';
import * as bcrypt from 'bcrypt';
import { validate as isValidUUID } from 'uuid';
import { jwtConstants } from './constants/jwt-contstant';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  private readonly logger = new Logger(JwtRefreshStrategy.name);

  constructor(private readonly databaseService: DatabaseService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => {
          const token = request?.cookies?.Refresh;
          console.log('!st token', token);
          this.logger.debug(
            `Extracted Refresh token: ${token ? 'Present' : 'Missing'}`,
          );
          return token;
        },
      ]),
      secretOrKey: jwtConstants.refreshTokenSecret,
      ignoreExpiration: false,
      passReqToCallback: true,
    });
  }

  async validate(req: Request, payload: any) {
    console.log('refresh token calling');
    this.logger.debug(
      `Validating refresh token payload: ${JSON.stringify(payload)}`,
    );
    const refreshToken = req.cookies?.Refresh;
    if (!refreshToken) {
      this.logger.error('No refresh token found in cookies');
      throw new UnauthorizedException('Refresh token not provided');
    }

    if (!payload?.id || !isValidUUID(payload.id)) {
      this.logger.error(`Invalid or missing UUID in payload.id: ${payload.id}`);
      throw new UnauthorizedException('Invalid token payload');
    }

    this.logger.debug(`Querying refresh token for userId: ${payload.id}`);
    const storedToken = await this.databaseService.refreshToken.findFirst({
      where: {
        userId: payload.id,
        expiresAt: { gt: new Date() },
      },
    });

    if (!storedToken) {
      this.logger.error(
        `No valid refresh token found for userId: ${payload.id}`,
      );
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
    console.log('stoed token', storedToken);

    this.logger.debug(`Comparing refresh token for userId: ${payload.id}`);
    const isValidToken = await bcrypt.compare(refreshToken, storedToken.token);
    this.logger.debug(`Bcrypt compare result: ${isValidToken}`);

    if (!isValidToken) {
      this.logger.error(`Refresh token mismatch for userId: ${payload.id}`);
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    this.logger.debug(`Fetching user for id: ${payload.id}`);
    const user = await this.databaseService.user.findUnique({
      where: { id: payload.id, deletedAt: null },
    });

    if (!user) {
      this.logger.error(`User not found for id: ${payload.id}`);
      throw new UnauthorizedException('User not found');
    }

    this.logger.debug(
      `Refresh token validated successfully for user: ${user.email}`,
    );
    return {
      refreshToken,
      ...payload,
      id: user.id,
      email: user.email,
      role: user.role,
    };
  }
}
