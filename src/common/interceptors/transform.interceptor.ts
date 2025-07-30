import { ExecutionContext, Injectable, NestInterceptor,CallHandler
 } from "@nestjs/common";
import { map, Observable } from "rxjs";

// this code is basically a API response wrapper using typescript and nestjs backend, it defines structure ApiResponse<T> and an interceptor 

// TransformInterceptor<T> to shape API response consistently

// interface defines structure or blueprint for the response object

// <T> : This is generic type placeholder, It means the type of data is totally dynamic, and can be any type (array, object, string) depending on usage

// Think of <T> as a placeholder for any type, of actual data, returned in the API response
// ApiResponse<User>  // here T= User

export interface ApiResponse<T> {
    success: Boolean;   // whether the api call was successfull (meaning true or false)
    message: string;    // Human readable message ( "Success","failed")
    data: T | null;     // Main response body can be any type T, or null if no data
    errors: string[] | null;    // List od error message
    meta: {                 // metadata about request
        timeStamp: string;  // time when response was send
        method: string;   // HTTP method passing (GET,PUT,PATCH,POST,DELETE)
    }
}

@Injectable()
export class TransformInterceptor<T>
  implements NestInterceptor<T, ApiResponse<T>> {
  intercept(
    context: ExecutionContext,
    next: CallHandler
  ): Observable<ApiResponse<T>> {
    const ctx = context.switchToHttp();
    const request = ctx.getRequest();
    const successStatus = true;
    return next.handle().pipe(
      map((response: any) => {
        let method = request.method;
        let data, message, meta;

        switch (method) {
          case "GET":
            data = response?.data?.data ?? response?.data;
            message = response?.message;
            meta = response?.data?.meta;
            break;

          case "POST":
          case "PATCH":
          case "PUT":
          case "DELETE":
            data = response?.data;
            message = response?.message;
            break;

          default:
            break;
        }

        return {
          success: successStatus,
          data: data,
          message: message ?? "OK",
          errors: null,
          meta: meta ?? {
            timeStamp: new Date().toISOString(),
            method: request.method,
          },
        };
      })
    );
  }
  }