import { Module } from '@nestjs/common';
import { LoginattemptsService } from './loginattempts.service';
import { LoginattemptsController } from './loginattempts.controller';
import { DatabaseModule } from 'src/database/database.module';

@Module({
  imports :[DatabaseModule],
  providers: [LoginattemptsService],
  controllers: [LoginattemptsController],
})
export class LoginattemptsModule {}
