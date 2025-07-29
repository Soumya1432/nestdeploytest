import { Module } from '@nestjs/common';
import { LoginattemptsService } from './loginattempts.service';
import { LoginattemptsController } from './loginattempts.controller';

@Module({
  providers: [LoginattemptsService],
  controllers: [LoginattemptsController],
})
export class LoginattemptsModule {}
