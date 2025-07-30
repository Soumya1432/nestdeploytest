import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class VerifyOtpDto {
  @IsEmail()
  @IsString()
  email: string;

  @IsNotEmpty()
  @Length(6, 6)
  otp: string;

  otpExpiry: null;
}
