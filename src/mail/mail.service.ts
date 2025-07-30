import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';

@Injectable()
export class MailService {
    constructor(
        private readonly mailerService:MailerService,
    ){}
     async sendOtpEmail(email: string, subject: string, message: string) {
    await this.mailerService.sendMail({
      to: email,
      subject: subject,
      template: 'otp', // Assuming 'otp' is the correct template
      context: {
        name: email.split('@')[0],
        otp: message, // Use the 'message' field as the OTP
        expiry: '10 minutes', // Show expiry time
      },
    });
  }
}
