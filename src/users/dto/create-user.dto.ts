import { Role } from '@prisma/client';
import {
  IsEmail,
  IsEnum,
  IsMobilePhone,
  IsOptional,
  IsString,
} from 'class-validator';

export class CreateUserDto {
  @IsString()
  firstName: string;

  @IsString()
  lastName?: string;

  @IsEmail()
  email: string;

  @IsMobilePhone()
  mobileNo?: number;

  // @IsEnum(['USER', 'ADMIN', 'ACCOUNT_MANAGER'])
  // role: string;
  // Role is optional and only allowed for admins
  @IsOptional()
  @IsEnum(Role)
  role?: Role;
}
