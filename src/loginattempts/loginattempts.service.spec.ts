import { Test, TestingModule } from '@nestjs/testing';
import { LoginattemptsService } from './loginattempts.service';

describe('LoginattemptsService', () => {
  let service: LoginattemptsService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [LoginattemptsService],
    }).compile();

    service = module.get<LoginattemptsService>(LoginattemptsService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
