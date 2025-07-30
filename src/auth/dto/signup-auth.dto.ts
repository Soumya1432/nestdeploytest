import { IsEmail, IsString } from 'class-validator';

export class SignUpDto {
  @IsEmail()
  @IsString()
  email: string;
}
