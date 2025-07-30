// corrected code
// import { Module } from '@nestjs/common';
// import { AuthController } from './auth.controller';
// import { AuthService } from './auth.service';
// import { DatabaseModule } from 'src/database/database.module';
// import { MailModule } from 'src/mail/mail.module';
// import { PassportModule } from '@nestjs/passport';
// import { JwtModule } from '@nestjs/jwt';
// import { jwtConstants } from './constants/jwt-contstant';
// import { JwtStrategy } from './jwt-strategy';
// import { ConfigModule, ConfigService } from '@nestjs/config';

// @Module({
//   imports: [
//     DatabaseModule,
//     PassportModule,
//     ConfigModule,
//     MailModule,
//     JwtModule.register({
//       global: true,
//       secret: jwtConstants.secret,
//       signOptions: { expiresIn: '1h' },
//     }),
//   ],
//   controllers: [AuthController],
//   providers: [AuthService, JwtStrategy],
//   exports: [AuthService, JwtModule],
// })
// export class AuthModule {}

// import { Module } from '@nestjs/common';
// import { AuthController } from './auth.controller';
// import { AuthService } from './auth.service';
// import { DatabaseModule } from 'src/database/database.module';
// import { MailModule } from 'src/mail/mail.module';
// import { PassportModule } from '@nestjs/passport';
// import { JwtModule } from '@nestjs/jwt';
// import { JwtStrategy } from './jwt-strategy';
// import { ConfigModule } from '@nestjs/config';
// import { JwtRefreshStrategy } from './jwt-refresh.strategy';
// import { JwtRefreshAuthGuard } from './jwt-refresh-auth.guard';

// @Module({
//   imports: [
//     DatabaseModule,
//     PassportModule,
//     ConfigModule,
//     MailModule,
//     JwtModule.register({
//       global: true,
//       secret: process.env.JWT_ACCESS_TOKEN_SECRET,
//       signOptions: { expiresIn: '1h' },
//     }),
//   ],
//   controllers: [AuthController],
//   providers: [AuthService, JwtStrategy,JwtRefreshStrategy,JwtRefreshAuthGuard],
//   exports: [AuthService, JwtModule],
// })
// export class AuthModule {}

// import { Module } from '@nestjs/common';
// import { AuthController } from './auth.controller';
// import { AuthService } from './auth.service';
// import { DatabaseModule } from 'src/database/database.module';
// import { MailModule } from 'src/mail/mail.module';
// import { PassportModule } from '@nestjs/passport';
// import { JwtModule } from '@nestjs/jwt';
// import { ConfigModule, ConfigService } from '@nestjs/config';
// import { JwtStrategy } from './jwt-strategy';
// import { JwtRefreshStrategy } from './jwt-refresh.strategy';

// @Module({
//   imports: [
//     DatabaseModule,
//     PassportModule.register({ defaultStrategy: 'jwt' }),
//     ConfigModule,
//     MailModule,
//     JwtModule.registerAsync({
//       imports: [ConfigModule],
//       useFactory: async (configService: ConfigService) => ({
//         secret: configService.getOrThrow('JWT_ACCESS_TOKEN_SECRET'),
//         signOptions: {
//           expiresIn: `${configService.getOrThrow('JWT_ACCESS_TOKEN_EXPIRATION_MS')}ms`,
//         },
//       }),
//       inject: [ConfigService],
//     }),
//   ],
//   controllers: [AuthController],
//   providers: [AuthService, JwtStrategy, JwtRefreshStrategy],
//   exports: [AuthService, JwtModule],
// })
// export class AuthModule {}

import { Module, OnModuleInit } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { DatabaseModule } from 'src/database/database.module';
import { MailModule } from 'src/mail/mail.module';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './jwt-strategy';

import { jwtConstants } from './constants/jwt-contstant';
import { JwtRefreshStrategy } from './jwt-refresh.strategy';
import { JwtRefreshAuthGuard } from './jwt-refresh-auth.guard';


@Module({
  imports: [
    DatabaseModule,
    PassportModule,
    MailModule,
    JwtModule.register({
      global: true,
      secret: jwtConstants.accessTokenSecret,
      signOptions: { expiresIn: `${jwtConstants.accessTokenExpirationMs}ms` },
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtStrategy,
    JwtRefreshStrategy,
    JwtRefreshAuthGuard,
  ],
  exports: [AuthService, JwtModule],
})
export class AuthModule {}
// export class AuthModule implements OnModuleInit {
//   private readonly logger = new Logger(AuthModule.name);

//   onModuleInit() {
//     // Validate environment variables
//     if (!jwtConstants.accessTokenSecret || !jwtConstants.refreshTokenSecret) {
//       this.logger.error(
//         'JWT_ACCESS_TOKEN_SECRET or JWT_REFRESH_TOKEN_SECRET not defined in .env',
//       );
//       throw new Error('JWT secrets must be defined in .env');
//     }
//     this.logger.log('AuthModule initialized with JWT constants');
//   }
// }
