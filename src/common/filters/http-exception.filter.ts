// src/common/filters/all-exceptions.filter.ts
import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  BadRequestException,
} from '@nestjs/common';
import { Request, Response } from 'express';

function deriveMethodsErrors(method, statusCode) {
  console.log('--- START DERIVED METHOD ---');
  console.log(method, statusCode);
  let message = '',
    errors: string[] = [];
  switch (method + '-' + statusCode) {
    case 'GET-200':
      message = 'No record found';
      errors.push('The requested resource could not be found');
      break;
    case 'GET-404':
      message = 'Not found';
      errors.push('The requested resource could not be found');
      break;
    case 'POST-400':
      message = 'Bad Request';
      errors.push('The request was invalid or cannot be otherwise served');
      break;

    case 'GET-401':
      message = 'Unauthorized';
      errors.push('You must be authenticated to access this resource');
      break;
    case 'POST-401':
      console.log('Inside post 401');
      message = 'Forbidden';
      errors.push('You do not have permission to access this resource');
      break;
    case 'GET-403':
      console.log('Inside post 403');
      message = 'Forbidden';
      errors.push('You do not have permission to access this resource');
      break;
    case 'POST-403':
      console.log('Inside post 403');
      message = 'Forbidden';
      errors.push('You do not have permission to access this resource');
      break;
    case 'PATCH-403':
      console.log('Inside post 403');
      message = 'Forbidden';
      errors.push('You do not have permission to access this resource');
      break;
    case 'DELETE-403':
      console.log('Inside post 403');
      message = 'Forbidden';
      errors.push('You do not have permission to access this resource');
      break;
    case 'POST-404':
      message = 'Not found';
      errors.push('The requested resource could not be found');
      break;
    case 'PATCH-400':
      console.log('PATCH-400');
      message = 'Bad request';
      errors.push('Invalid syntax or data');
      break;
    case 'PATCH-404':
      message = 'Not found';
      errors.push('The requested resource could not be found');
      break;
    case 'PUT-404':
      message = 'Not found';
      errors.push('The requested resource could not be found');
      break;
    case 'DELETE-403':
      message = 'Forbidden';
      errors.push('You do not have permission to delete this resource');
      break;
    case 'DELETE-404':
      message = 'Resource not found';
      errors.push('The resource you are trying to delete does not exist.');
      break;

    default:
      console.log(method + '-' + statusCode, typeof method + '-' + statusCode);
      break;
  }
  console.log('--- END DERIVED METHOD ---');
  return { message, errors };
}
const statusLog: any = [];
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    let message = '',
      errors: string[] = [],
      status,
      deriveMethodsErrorsObject;

    console.log('--- START EXCEPTION FILTER ---');
    if (exception instanceof BadRequestException) {
      status = exception.getStatus();
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      message = exception.getResponse()['error'];
      errors = exception.getResponse()['message'];
    } 
    else if (exception instanceof HttpException) {
      console.log('--- START INSIDE HTTPEXCEPTION ---');

      console.log('---- EXCEPTION OBJECT', exception);
      console.log('---- EXCEPTION NAME', exception?.name);
      console.log('---- EXCEPTION MESSAGE', exception?.message);
      console.log('----- STATUS', exception.getStatus());
      console.log('------ BEFORE STATUSLOG');

      statusLog.push(exception.getStatus());
      console.log(statusLog);

      console.log('------ AFTER STATUSLOG ');

      deriveMethodsErrorsObject = deriveMethodsErrors(
        request.method,
        exception.getStatus(),
      );

      status = exception.getStatus();
      message = deriveMethodsErrorsObject?.message;
      errors = deriveMethodsErrorsObject?.errors;

      console.log('---- END INSIDE HTTPEXCEPTION ---');
    } else if (exception instanceof Error) {
      // message = exception.message;
      // errors = [exception.stack];
      console.log('---- START INSIDE ERROR---');
      console.log('----- 2');
      console.log('------ ERROR OBJECT', exception);
      console.log('------ ERROR NAME', exception?.name);
      console.log('------- BEFORE STATUSLOG BEFORE');

      console.log(statusLog);

      console.log('------- AFTER STATUSLOG AFTER');

      if (exception?.name === 'PrismaClientKnownRequestError') {
        status = 200;
      }

      if (
        exception?.name === 'TypeError' &&
        statusLog.length > 0 &&
        (statusLog[0] === 403 || statusLog[0] === 401)
      ) {
        status = statusLog[0];
        statusLog.splice(0, statusLog.length);
      } else {
        status = 404;
      }

      deriveMethodsErrorsObject = deriveMethodsErrors(request.method, status);
      message = deriveMethodsErrorsObject?.message;
      errors = deriveMethodsErrorsObject?.errors;
      console.log('--- END INSIDE ERROR---');
    } else {
      console.log('--- 3 ---');
    }
    console.log('--- END EXCEPTION FILTER ---');

    response.status(status).json({
      success: false,
      data: null,
      message,
      errors,
      meta: {
        timestamp: new Date().toISOString(),
        path: request.url,
        method: request.method,
        statusCode: status,
      },
    });
  }
}
