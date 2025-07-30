import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { Prisma, Role, User } from '@prisma/client';
import { DatabaseService } from 'src/database/database.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { CreateUserDto } from './dto/create-user.dto';

@Injectable()
export class UsersService {
  constructor(private readonly databaseService: DatabaseService) {}

  // working
  async findAll(query: {
    searchField?: keyof Prisma.UserWhereInput;
    search?: string;
    sortBy?: keyof Prisma.UserOrderByWithAggregationInput;
    sortOrder?: 'asc' | 'desc';
    page?: number;
    limit?: number;
  }): Promise<any> {
    const {
      searchField,
      search,
      sortBy = 'createdAt',
      sortOrder = 'desc',
      page = 1,
      limit = 10,
    } = query;

    const pageNum = Number(page) || 1;
    const limitNum = Number(limit) || 10;

    let searchCondition: Prisma.UserWhereInput[] | undefined = undefined;

    if (search) {
      if (!searchField) {
        // Define default fields to search when searchField is not provided
        searchCondition = [
          { firstName: { contains: search, mode: 'insensitive' } },
          { lastName: { contains: search, mode: 'insensitive' } },
          { email: { contains: search, mode: 'insensitive' } },
        ];
      } else {
        searchCondition = [
          {
            [searchField]: {
              contains: search,
              mode: 'insensitive',
            },
          } as any,
        ];
      }
    }

    const where: Prisma.UserWhereInput = {
      deletedAt: null,
      ...(searchCondition ? { OR: searchCondition } : {}),
    };

    const users = await this.databaseService.user.findMany({
      where,
      orderBy: { [sortBy]: sortOrder },
      skip: (pageNum - 1) * limitNum,
      take: limitNum,
    });

    const total = await this.databaseService.user.count({ where });

    return {
      data: {
        data: users,
        meta: {
          total,
          page: pageNum,
          limit: limitNum,
          totalPages: Math.ceil(total / limitNum),
        },
      },
    };
  }

  // working
  async findUserOwnProfile(userId: string): Promise<any> {
    const user = await this.databaseService.user.findFirst({
      where: { id: userId },
    });

    return user;
  }

  // working
  async create(createUserDto: CreateUserDto, creatorRole: Role): Promise<User> {
    // Optionally, restrict role assignment based on creator's role
    if (createUserDto.role && creatorRole !== Role.ADMIN) {
      throw new ForbiddenException('Only admins can assign roles');
    }

    const existingUser = await this.databaseService.user.findUnique({
      where: { email: createUserDto.email },
    });
    if (existingUser) {
      throw new BadRequestException('User with this email already exists');
    }

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

  async update(
    id: string,
    updateUserDto: UpdateUserDto,
    authUser: { id: string; role: Role },
  ): Promise<User> {
    // Check if the target user exists
    const existingUser = await this.databaseService.user.findUnique({
      where: { id },
    });
    if (!existingUser) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }

    // Prepare update data
    const updateData: Partial<User> = {
      firstName: updateUserDto.firstName,
      lastName: updateUserDto.lastName,
      email: updateUserDto.email,
      mobileNo: updateUserDto.mobileNo?.toString(), // Convert number to string
    };

    // Restrict role updates to admins
    if (updateUserDto.role) {
      if (authUser.role !== Role.ADMIN) {
        throw new ForbiddenException('Only admins can update user roles');
      }
      updateData.role = updateUserDto.role;
    }

    // For non-admins, ensure they can only update their own profile
    if (authUser.role !== Role.ADMIN && authUser.id !== id) {
      throw new ForbiddenException('You can only update your own profile');
    }

    // Remove undefined fields to avoid Prisma errors
    Object.keys(updateData).forEach((key) => {
      if (updateData[key] === undefined) {
        delete updateData[key];
      }
    });

    try {
      return await this.databaseService.user.update({
        where: { id },
        data: updateData,
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new BadRequestException(
            'Email or mobile number already in use',
          );
        }
      }
      throw new BadRequestException('Failed to update user');
    }
  }

  async delete(
    id: string,
    currentUser: { id: string; email: string; role: string },
  ): Promise<void> {
    // Check if user is admin or trying to delete their own profile
    if (currentUser.role !== 'ADMIN' && currentUser.id !== id) {
      throw new ForbiddenException('You can only delete your own profile');
    }

    try {
      // Start a transaction to ensure atomicity
      await this.databaseService.$transaction(async (prisma) => {
        // Find the user
        const user = await prisma.user.findFirst({
          where: { id, deletedAt: null },
        });

        if (!user) {
          throw new NotFoundException('User not found');
        }

        // Soft delete the user
        await prisma.user.update({
          where: { id },
          data: { deletedAt: new Date() },
        });
      });
    } catch (error) {
      throw error instanceof NotFoundException
        ? error
        : new InternalServerErrorException('Failed to delete user');
    }
  }
}
