import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { DatabaseService } from 'src/database/database.service';
import { CreateUserDto } from './dto/create-user.dto';
import { Prisma, Role, User } from '@prisma/client';


@Injectable()
export class UsersService {
  constructor(private readonly databaseService: DatabaseService) {}

  async fundUserOwnProfile(userId: string): Promise<any> {
    const user = await this.databaseService.user.findFirst({
      where: { id: userId },
    });
    return user;
  }

  async create(createUserDto: CreateUserDto, creatorRole: Role): Promise<User> {
    // Optionally, restrict role assignment based on creator's role
    if (createUserDto.role && creatorRole !== Role.ADMIN) {
      throw new ForbiddenException('Only admins can assign roles');
    }

    // const existingUser = await this.databaseService.user.findUnique({
    //   where: { email: createUserDto.email },
    // });
    // if (existingUser) {
    //   throw new BadRequestException('User with this email already exists');
    // }

    try {
      return await this.databaseService.user.create({
        data: {
          firstName: createUserDto.firstName,
          lastName: createUserDto.lastName,
          email: createUserDto.email,
          mobileNo: createUserDto.mobileNo?.toString(), // Convert number to string if provided
          role: createUserDto.role
            ? (Role as any)[createUserDto.role]
            : Role.USER, // Ensure role is of type Role
        },
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new BadRequestException(
          'User with this email or mobile number already exists',
        );
      }
      throw new BadRequestException('Failed to create user');
    }
  }

}
