import {
  Body,
  Controller,
  Post,
  Res,
  UseGuards,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { Response, Request } from 'express';
import { SignUpDto } from './dto/signup-auth.dto';
import { JwtRefreshAuthGuard } from './jwt-refresh-auth.guard';
import { JwtAuthGuard } from './jwt-auth.guard';
import { messages } from 'src/config/helpers.config';

const entityNameSingular = 'user';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signup(@Body() signUpDto: SignUpDto): Promise<{
    success: boolean;
    data: { email: string; id: string } | null;
    message: string;
    errors: null | string;
    meta: { timestamp: string; method: string };
  }> {
    return await this.authService.register(signUpDto);
  }

  @Post('verify-email')
  async verifyEmail(
    @Body() verifyOtpDto: VerifyOtpDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<any> {
    const verifyUser = await this.authService.verifyEmail(verifyOtpDto, res);
    return {
      data: verifyUser,
      message: 'User verfied successfully',
    };
  }

  @Post('login')
  async login(@Body() signUpDto: SignUpDto): Promise<any> {
    return await this.authService.login(signUpDto);
  }

  // @Post('verify-login')
  // async verifyLogin(
  //   @Body() verifyOtpDto: VerifyOtpDto,
  //   @Res({ passthrough: true }) res: Response,
  // ): Promise<any> {
  //   return await this.authService.verifyLogin(verifyOtpDto, res);
  // }

  @Post('resend-otp')
  async resendOtp(@Body('email') email: string) {
    return await this.authService.resendOtp(email);
  }

  @Post('refresh')
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    console.log('Cookies received:', req?.cookies);
    const refreshToken = req.cookies?.Refresh;
    console.log('Refresh token', refreshToken);
    if (!refreshToken) {
      console.error('No Refresh cookie found');
      throw new UnauthorizedException('Refresh token not found');
    }
    return await this.authService.refreshToken(refreshToken, res);
  }

  @UseGuards(JwtRefreshAuthGuard)
  @Post('logout')
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    console.log('Logout calling');
    console.log('Cookies received:', req?.cookies);
    const user = req.user as { id: string };
    return await this.authService.logout(user.id, res);
  }
}
