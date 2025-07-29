import { Test, TestingModule } from '@nestjs/testing';
import { LoginattemptsController } from './loginattempts.controller';

describe('LoginattemptsController', () => {
  let controller: LoginattemptsController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [LoginattemptsController],
    }).compile();

    controller = module.get<LoginattemptsController>(LoginattemptsController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
