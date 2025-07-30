import { Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { MailController } from './mail.controller';
import { DatabaseModule } from 'src/database/database.module';
import { MailerModule } from '@nestjs-modules/mailer';
import { join } from 'path';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';

@Module({
  imports: [
    DatabaseModule,
    MailerModule.forRoot({
      transport: {
        host: process.env.MAIL_HOST,
        port: process.env.MAIL_PORT,
        secure: false, // true for 465, false for other ports
        auth: {
          user: process.env.MAIL_USER, // generated ethereal user
          pass: process.env.MAIL_PASS, // generated ethereal password
        },
        // tls: {
        //   rejectUnauthorized: false,
        // },
      },
      defaults: {
        // from: '"Greenature" <soumyabiswas@crontel.com>',
        from: '"Green Nature" <support@greennature.in>',
      },
      template: {
        // dir:join(__dirname,'./','templates'),
        dir: join(process.cwd(), 'src', 'mail', 'templates'),
        adapter: new HandlebarsAdapter(),
        options: {
          strict: true,
        },
      },
    }),
  ],
  providers: [MailService],
  controllers: [MailController],
  exports: [MailService]
})
export class MailModule {}
