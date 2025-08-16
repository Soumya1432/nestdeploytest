import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { DatabaseService } from 'src/database/database.service';
import { MailService } from 'src/mail/mail.service';
import * as bcrypt from 'bcrypt';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { SignUpDto } from './dto/signup-auth.dto';
import { jwtConstants } from './constants/jwt-contstant';


@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  constructor(
    private readonly databaseService: DatabaseService,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService,
  ) {
    // Log secrets for debugging (remove in production)
    // this.logger.debug(
    //   `Using JWT_ACCESS_TOKEN_SECRET: ${jwtConstants.accessTokenSecret}`,
    // );
    // this.logger.debug(
    //   `Using JWT_REFRESH_TOKEN_SECRET: ${jwtConstants.refreshTokenSecret}`,
    // );
  }

  // fully working signup in correct method with mail service included
  async register(signupDto: SignUpDto): Promise<any> {
    try {
      const { email } = signupDto;
      const existingUser = await this.databaseService.user.findUnique({
        where: { email },
      });

      if (existingUser) {
        if (!existingUser.isEmailVerified) {
          // Email exists but not verified; resend OTP
          const otp = Math.floor(100000 + Math.random() * 900000).toString();
          const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
          const hashedOtp = await bcrypt.hash(otp, 10);
          await this.databaseService.user.update({
            where: { email },
            data: {
              otp: hashedOtp,
              otpExpiry: otpExpiresAt,
            },
          });

          await this.mailService.sendOtpEmail(
            email,
            'Your OTP code for verification',
            otp,
          );

          return {
            data: {
              email: existingUser.email,
              id: existingUser.id,
            },
            message:
              'Email already registered but not verified. A new OTP has been sent.',
          };
        }

        throw new BadRequestException(
          `You are already registered, please login to conitnue`,
        );
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
      const hashedOtp = await bcrypt.hash(otp, 10);
      const newUser = await this.databaseService.user.create({
        data: {
          email,
          otp: hashedOtp,
          otpExpiry: otpExpiresAt,
          isEmailVerified: false,
        },
      });

      this.logger.log(`New user created: ${newUser.email}`);

      await this.mailService.sendOtpEmail(
        newUser.email,
        'Your OTP code for verification',
        otp,
      );

      return {
        data: {
          email: newUser.email,
          id: newUser.id,
        },
        message: 'User registered successfully. Please verify OTP.',
      };
    } catch (error) {
      this.logger.error('Error during user creation', error);
      if (error instanceof BadRequestException) {
        throw error; // Let BadRequestException pass through to the filter
      }
      throw new InternalServerErrorException(
        'Failed to register user',
        error.message,
      ); // Wrap other errors in InternalServerErrorException
    }
  }

  //  testing code for custom otp input checking not inlcuded any mail service == test phase
  // async register(signupDto: SignUpDto): Promise<any> {
  //   try {
  //     const { email } = signupDto;

  //     const existingUser = await this.databaseService.user.findUnique({
  //       where: { email },
  //     });

  //     // Skip email validation for testing
  //     const emailOtpInput = '123456'; // Always use this OTP
  //     const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
  //     const hashedOtp = await bcrypt.hash(emailOtpInput, 10);

  //     if (existingUser) {
  //       if (!existingUser.isEmailVerified) {
  //         // Update OTP for existing unverified user
  //         await this.databaseService.user.update({
  //           where: { email },
  //           data: {
  //             otp: hashedOtp,
  //             otpExpiry: otpExpiresAt,
  //           },
  //         });

  //         return {
  //           data: {
  //             email: existingUser.email,
  //             id: existingUser.id,
  //             otp: emailOtpInput, // for test verification (remove in production)
  //           },
  //           message: 'Email already registered but not verified. Test OTP set.',
  //         };
  //       }

  //       throw new BadRequestException(
  //         'You are already registered, please login to continue',
  //       );
  //     }

  //     // Create new user with test OTP
  //     const newUser = await this.databaseService.user.create({
  //       data: {
  //         email,
  //         otp: hashedOtp,
  //         otpExpiry: otpExpiresAt,
  //         isEmailVerified: false,
  //       },
  //     });

  //     this.logger.log(`New user created: ${newUser.email}`);

  //     return {
  //       data: {
  //         email: newUser.email,
  //         id: newUser.id,
  //         otp: emailOtpInput, // for test verification (remove in production)
  //       },
  //       message: 'User registered successfully with test OTP.',
  //     };
  //   } catch (error) {
  //     this.logger.error('Error during user creation', error);
  //     if (error instanceof BadRequestException) throw error;
  //     throw new InternalServerErrorException(
  //       'Failed to register user',
  //       error.message,
  //     );
  //   }
  // }

  async verifyEmail(verifyOtpDto: VerifyOtpDto, res: Response): Promise<any> {
    try {
      const { email, otp } = verifyOtpDto;
      if (!email) {
        throw new BadRequestException('Email is required');
      }
      const user = await this.databaseService.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new BadRequestException('No user found for this email.');
      }
      if (
        !user.otp ||
        !user.otpExpiry ||
        new Date() > new Date(user.otpExpiry)
      ) {
        throw new BadRequestException('OTP has expired');
      }

      const isValid = await bcrypt.compare(otp, user.otp);

      if (!isValid) {
        throw new BadRequestException('Invalid OTP.');
      }

      const tokenPayload = {
        id: user.id,
        email: user.email,
        role: user.role,
      };

      const accessToken = this.jwtService.sign(tokenPayload, {
        secret: jwtConstants.accessTokenSecret,
        expiresIn: `${jwtConstants.accessTokenExpirationMs}ms`,
      });

      const refreshToken = this.jwtService.sign(tokenPayload, {
        secret: jwtConstants.refreshTokenSecret,
        expiresIn: `${jwtConstants.refreshTokenExpirationMs}ms`,
      });

      const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

      await this.databaseService.refreshToken.deleteMany({
        where: {
          userId: user.id,
          // expiresAt: { gt: new Date() },
          expiresAt: { gt: new Date() },
        },
      });

      await this.databaseService.refreshToken.create({
        data: {
          userId: user.id,
          token: hashedRefreshToken,
          expiresAt: new Date(
            Date.now() + jwtConstants.refreshTokenExpirationMs,
          ),
        },
      });

      await this.databaseService.user.update({
        where: { email },
        data: {
          isEmailVerified: true,
          otp: null,
          otpExpiry: null,
          lastLogin: new Date(),
        },
      });

      res.cookie('Authentication', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: jwtConstants.accessTokenExpirationMs,
      });

      res.cookie('Refresh', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: jwtConstants.refreshTokenExpirationMs,
      });

      this.logger.log(`OTP verified for user: ${email}`);

      return user;
    } catch (error) {
      this.logger.error('Failed to verify OTP', {
        error: error.message,
        stack: error.stack,
      });
      if (error instanceof BadRequestException) {
        throw error;
      }
      throw new InternalServerErrorException(
        `Failed to verify OTP: ${error.message}`,
      );
    }
  }

  // fully working login in correct method with mail service included
  async login(signupDto: SignUpDto): Promise<any> {
    try {
      const { email } = signupDto;

      const existingUser = await this.databaseService.user.findUnique({
        where: { email },
      });

      // const isValidEmail =
      //   await this.emailValidationService.isEmailValid(email);
      // if (!isValidEmail) {
      //   throw new BadRequestException('Please check your email first');
      // }

      if (!existingUser) {
        throw new BadRequestException(`User not found. Please sign up first.`);
      }

      if (!existingUser.isEmailVerified) {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedOtp = await bcrypt.hash(otp, 10);
        const otpExpiry = new Date(Date.now() + 2 * 60 * 1000);

        await this.databaseService.user.update({
          where: { email },
          data: {
            otp: hashedOtp,
            otpExpiry,
          },
        });

        await this.mailService.sendOtpEmail(
          email,
          'Your OTP code for verification',
          otp,
        );

        this.logger.log(`OTP resent for unverified user login: ${email}`);
        return {
          message: 'Email not verified. A new OTP has been sent.',
          // redirectTo: '/auth/verify-email',
          data: existingUser,
          // user: {
          //   id: existingUser.id,
          //   email: existingUser.email,
          // },
        };
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const hashedOtp = await bcrypt.hash(otp, 10);
      const otpExpiry = new Date(Date.now() + 2 * 60 * 1000);

      await this.databaseService.user.update({
        where: { email },
        data: {
          otp: hashedOtp,
          otpExpiry,
          lastLogin: new Date(),
        },
      });

      await this.mailService.sendOtpEmail(email, 'Your OTP code', otp);

      this.logger.log(`OTP sent for login: ${email}`);

      return {
        message: 'OTP sent. Please verify to login.',
      };
    } catch (error) {
      this.logger.error('Error during login', error);
      if (error instanceof BadRequestException) {
        throw error;
      }
      throw new InternalServerErrorException('Failed to process login');
    }
  }

  // //  testing code for custom otp input checking not inlcuded any mail service == test phase
  // async login(signupDto: SignUpDto): Promise<any> {
  //   try {
  //     const { email } = signupDto;

  //     const existingUser = await this.databaseService.user.findUnique({
  //       where: { email },
  //     });

  //     // For testing only
  //     const emailOtpInput = '123456';
  //     const otpExpiry = new Date(Date.now() + 2 * 60 * 1000);
  //     const hashedOtp = await bcrypt.hash(emailOtpInput, 10);

  //     if (!existingUser) {
  //       throw new BadRequestException(`User not found. Please sign up first.`);
  //     }

  //     if (!existingUser.isEmailVerified) {
  //       // Unverified user - update OTP only, skip sending email
  //       await this.databaseService.user.update({
  //         where: { email },
  //         data: {
  //           otp: hashedOtp,
  //           otpExpiry,
  //         },
  //       });

  //       this.logger.log(`OTP set for unverified user login: ${email}`);

  //       return {
  //         message: 'Email not verified. Test OTP set.',
  //         data: {
  //           email: existingUser.email,
  //           id: existingUser.id,
  //           otp: emailOtpInput, // For testing, remove in production
  //         },
  //       };
  //     }

  //     // Verified user - update OTP and last login
  //     await this.databaseService.user.update({
  //       where: { email },
  //       data: {
  //         otp: hashedOtp,
  //         otpExpiry,
  //         lastLogin: new Date(),
  //       },
  //     });

  //     this.logger.log(`OTP set for verified user login: ${email}`);

  //     return {
  //       message: 'Test OTP set. Please verify to login.',
  //       data: {
  //         email: existingUser.email,
  //         id: existingUser.id,
  //         otp: emailOtpInput, // For testing, remove in production
  //       },
  //     };
  //   } catch (error) {
  //     this.logger.error('Error during login', error);
  //     if (error instanceof BadRequestException) throw error;
  //     throw new InternalServerErrorException('Failed to process login');
  //   }
  // }

  async resendOtp(email: string): Promise<any> {
    try {
      const user = await this.databaseService.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new BadRequestException('User not found.');
      }

      if (user.isEmailVerified) {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedOtp = await bcrypt.hash(otp, 10);
        const otpExpiry = new Date(Date.now() + 2 * 60 * 1000);

        await this.databaseService.user.update({
          where: { email },
          data: {
            otp: hashedOtp,
            otpExpiry,
          },
        });

        await this.mailService.sendOtpEmail(email, 'Login OTP code', otp);

        this.logger.log(`Login OTP resent for user: ${email}`);
        return { message: 'Login OTP resent successfully.' };
      }

      if (user.otpExpiry && new Date(user.otpExpiry) > new Date()) {
        return {
          message: 'OTP already sent. Please wait before requesting again.',
        };
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const hashedOtp = await bcrypt.hash(otp, 10);
      const otpExpiry = new Date(Date.now() + 2 * 60 * 1000);

      await this.databaseService.user.update({
        where: { email },
        data: {
          otp: hashedOtp,
          otpExpiry,
        },
      });

      await this.mailService.sendOtpEmail(email, 'Resend OTP code', otp);

      // this.logger.log(`OTP resent for user: ${email}`);
      return { message: 'OTP resent successfully.' };
    } catch (error) {
      this.logger.error('Error resending OTP', error);
      if (error instanceof BadRequestException) {
        throw error;
      }
      throw new InternalServerErrorException('Failed to resend OTP');
    }
  }

  async refreshToken(refreshToken: string, res: Response): Promise<any> {
    const logger = new Logger('AuthService.refreshToken');
    logger.debug(`Attempting to refresh token`);
    try {
      logger.debug(
        `Verifying refresh token with secret: ${jwtConstants.refreshTokenSecret}`,
      );
      const payload = this.jwtService.verify(refreshToken, {
        secret: jwtConstants.refreshTokenSecret,
      });
      console.log('Refresh token payload', payload);
      logger.debug(`Payload: ${JSON.stringify(payload)}`);

      const user = await this.databaseService.user.findFirst({
        where: { id: payload.id },
      });

      if (!user) {
        logger.error(`User not found for id: ${payload.id}`);
        throw new UnauthorizedException('Invalid token');
      }

      logger.debug(`Querying refresh token for userId: ${user.id}`);
      const storedToken = await this.databaseService.refreshToken.findFirst({
        where: {
          userId: user.id,
          expiresAt: { gt: new Date() },
        },
      });

      if (!storedToken) {
        logger.error(`No valid refresh token found for userId: ${user.id}`);
        throw new UnauthorizedException('Refresh token not found');
      }

      logger.debug(`Comparing refresh token`);
      const isValidToken = await bcrypt.compare(
        refreshToken,
        storedToken.token,
      );
      logger.debug(`Bcrypt compare result: ${isValidToken}`);
      if (!isValidToken) {
        logger.error(`Refresh token mismatch for userId: ${user.id}`);
        throw new UnauthorizedException('Refresh token mismatch');
      }

      const tokenPayload = {
        id: user.id,
        email: user.email,
        role: user.role,
      };

      const newAccessToken = this.jwtService.sign(tokenPayload, {
        secret: jwtConstants.accessTokenSecret,
        expiresIn: `${jwtConstants.accessTokenExpirationMs}ms`,
      });

      const newRefreshToken = this.jwtService.sign(tokenPayload, {
        secret: jwtConstants.refreshTokenSecret,
        expiresIn: `${jwtConstants.refreshTokenExpirationMs}ms`,
      });

      const hashedRefreshToken = await bcrypt.hash(newRefreshToken, 10);
      logger.debug(
        `Generated new refresh token, hashed: ${hashedRefreshToken}`,
      );

      await this.databaseService.refreshToken.deleteMany({
        where: { userId: user.id },
      });
      logger.debug(`Deleted old refresh tokens for userId: ${user.id}`);

      await this.databaseService.refreshToken.create({
        data: {
          userId: user.id,
          token: hashedRefreshToken,
          expiresAt: new Date(
            Date.now() + jwtConstants.refreshTokenExpirationMs,
          ),
        },
      });

      res.cookie('Authentication', newAccessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: jwtConstants.accessTokenExpirationMs,
      });

      res.cookie('Refresh', newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: jwtConstants.refreshTokenExpirationMs,
      });

      logger.log(`Tokens refreshed for user: ${user.email}`);
      return {
        message: 'Tokens refreshed successfully',
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          refreshToken,
        },
      };
    } catch (error) {
      logger.error(`Failed to refresh token: ${error.message}`, error.stack);
      throw new UnauthorizedException(
        `Failed to refresh token: ${error.message}`,
      );
    }
  }

  async logout(id: string, res: Response) {
    const logger = new Logger('AuthService.logout');
    logger.debug(`Attempting logout for userId: ${id}`);

    try {
      const user = await this.databaseService.user.findUnique({
        where: { id, deletedAt: null },
      });

      if (!user) {
        logger.error(`User not found for id: ${id}`);
        throw new UnauthorizedException('User not found');
      }

      await this.databaseService.refreshToken.deleteMany({
        where: { userId: id },
      });

      res.clearCookie('Authentication', {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
      });
      res.clearCookie('Refresh', {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
      });

      logger.log(`Logout successful for user: ${user.email}`);
      return {
        message: 'Logout successful',
        data: {
          id: user.id,
          email: user.email,
          role: user.role,
        },
      };
    } catch (error) {
      logger.error(
        `Failed to logout userId: ${id}: ${error.message}`,
        error.stack,
      );
      throw new UnauthorizedException(`Failed to logout: ${error.message}`);
    }
  }


  
}
