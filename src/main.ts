import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  
  app.use(cookieParser());
  // app.use(bodyParser.urlencoded({ extended: true })); // Parse form-data
  // app.use(bodyParser.json());
  app.enableCors({
    origin: [
      'http://localhost:3000',
      'http://localhost:3001',
      'http://192.168.29.4:3000',
      'https://payu.in',
       'https://4489d77476a8.ngrok-free.app'
    ],
    credentials: true,
    allowedHeaders: ['Authorization', 'Content-Type'],
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  });



  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
