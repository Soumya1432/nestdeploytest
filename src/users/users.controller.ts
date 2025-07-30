import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Request,
  Query,
  Req,
  UseGuards,
  Res,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { Prisma, Role } from '@prisma/client';
import { JwtRefreshAuthGuard } from 'src/auth/jwt-refresh-auth.guard';
import { RolesGuard } from 'src/auth/roles.guard';
import { Roles } from 'src/auth/roles.decorator';
import { messages } from 'src/config/helpers.config';
import { CreateUserDto } from './dto/create-user.dto';
const entityNameSingular = 'User';
const entityNamePlural = 'Users';
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) { }

  @UseGuards(JwtRefreshAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @Get()
  async findAllUsers(
    @Query()
    query: {
      searchField?: keyof Prisma.UserWhereInput;
      search?: string;
      sortBy?: keyof Prisma.UserOrderByWithAggregationInput;
      sortOrder?: 'asc' | 'desc';
      page?: number;
      limit?: number;
    },
  ) {
    const usersRecord = await this.usersService.findAll(query);
    return {
      message: `${entityNamePlural} ${messages.success.find}`,
      data: usersRecord?.data,
    };
  }

  @UseGuards(JwtRefreshAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @Get('/admin/me')
  async getProfileAdmin(@Request() req: any): Promise<any> {
    const userId = req.user?.id;
    const records = await this.usersService.findUserOwnProfile(userId);

    return {
      message: `${entityNamePlural}profile ${messages.success.find}`,
      data: records,
    };
  }

  @UseGuards(JwtRefreshAuthGuard)
  @Get('me')
  async getProfile(@Request() req: any): Promise<any> {
    const userId = req.user?.id;
    const records = await this.usersService.findUserOwnProfile(userId);

    return {
      message: `${entityNamePlural}profile ${messages.success.find}`,
      data: records,
    };
  }

  // @Get(':id')
  // async getUser(@Param('id') id: string) {
  //   return this.usersService.findSingleUser(id);
  // }

  @UseGuards(JwtRefreshAuthGuard, RolesGuard)
  @Roles(Role.ADMIN, Role.ACCOUNT_MANAGER)
  @Post('create')
  async create(@Body() createUserDto: CreateUserDto, @Req() req: any) {
    const user = req.user as { id: string; email: string; role: Role };
    return this.usersService.create(createUserDto, user.role);
  }

  // update is working
  @UseGuards(JwtRefreshAuthGuard)
  @Patch('me')
  async updateOwnProfile(
    @Req() req: any,
    @Body() updateUserDto: UpdateUserDto,
  ) {
    const user = req.user as { id: string; role: Role };
    if (!user?.id) {
      throw new BadRequestException('Invalid user token');
    }

    // Prevent role changes by normal users
    if (updateUserDto.role && user.role !== Role.ADMIN) {
      delete updateUserDto.role;
    }

    const userUpdateRecord = await this.usersService.update(
      user.id,
      updateUserDto,
      user,
    );
    console.log('user update their details', userUpdateRecord);
    return {
      message: `${entityNameSingular} ${messages.success.update}`,
      data: userUpdateRecord,
    };
  }

  @UseGuards(JwtRefreshAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @Patch(':id')
  async updateUserByAdmin(
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDto,
    @Req() req: { user: { id: string; role: Role } },
  ) {
    const user = req.user;
    if (!user?.id) {
      throw new BadRequestException('Invalid user token');
    }
    const userUpdate = await this.usersService.update(id, updateUserDto, user);
    console.log('USer data updated', userUpdate);
    return {
      message: `${entityNameSingular} ${messages.success.update}`,
      data: userUpdate,
    };
  }

  // @UseGuards(JwtRefreshAuthGuard)
  // @Delete('me')
  // async deleteOwnProfile(@Req() req: any) {
  //   const currentUser = req.user as { id: string; email: string; role: string };
  //   await this.usersService.delete(currentUser.id, currentUser);
  //   return {
  //     message: 'Your profile has been deleted successfully',
  //     user: {
  //       id: currentUser.id,
  //       email: currentUser.email,
  //       role: currentUser.role,
  //     },
  //   };
  // }

  @UseGuards(JwtRefreshAuthGuard)
  @Delete('me')
  async deleteOwnProfile(@Res({ passthrough: true }) res, @Req() req: any) {
    const currentUser = req.user as { id: string; email: string; role: string };

    await this.usersService.delete(currentUser.id, currentUser);

    // Clear cookies after user is deleted
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    return {
      message: 'Your profile has been deleted successfully',
      user: {
        id: currentUser.id,
        email: currentUser.email,
        role: currentUser.role,
      },
    };
  }

  @UseGuards(JwtRefreshAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @Delete(':id')
  async deleteUserByAdmin(@Param('id') id: string, @Req() req: any) {
    const currentUser = req.user as { id: string; email: string; role: string };
    await this.usersService.delete(id, currentUser);
    return {
      message: 'User deleted successfully by admin',
      deletedUserId: id,
    };
  }
}
