package com.cyberintel.exception;
import org.slf4j.*;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.dao.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.multipart.*;
@RestControllerAdvice
public class GlobalExceptionHandler {
 private static final Logger log=LoggerFactory.getLogger(GlobalExceptionHandler.class);
 private ResponseEntity<ApiError> error(HttpStatus status,String message){return ResponseEntity.status(status).body(ApiError.of(status.value(),message));}
 @ExceptionHandler(ApiException.class) ResponseEntity<ApiError> api(ApiException e){return error(e.getStatus(),e.getMessage());}
 @ExceptionHandler({MethodArgumentNotValidException.class,HttpMessageNotReadableException.class,org.springframework.web.multipart.support.MissingServletRequestPartException.class,org.springframework.web.method.annotation.MethodArgumentTypeMismatchException.class})
 ResponseEntity<ApiError> validation(Exception e){return error(HttpStatus.BAD_REQUEST,"Invalid request. Check the submitted fields.");}
 @ExceptionHandler(AuthenticationException.class) ResponseEntity<ApiError> auth(Exception e){return error(HttpStatus.UNAUTHORIZED,"Invalid email or password.");}
 @ExceptionHandler(AccessDeniedException.class) ResponseEntity<ApiError> forbidden(Exception e){return error(HttpStatus.FORBIDDEN,"Access denied.");}
 @ExceptionHandler(DataIntegrityViolationException.class) ResponseEntity<ApiError> conflict(Exception e){return error(HttpStatus.CONFLICT,"The request conflicts with an existing record.");}
 @ExceptionHandler(DataAccessException.class) ResponseEntity<ApiError> database(Exception e){log.error("Database operation failed",e);return error(HttpStatus.SERVICE_UNAVAILABLE,"Database temporarily unavailable.");}
 @ExceptionHandler(MaxUploadSizeExceededException.class) ResponseEntity<ApiError> size(Exception e){return error(HttpStatus.PAYLOAD_TOO_LARGE,"File exceeds the upload size limit.");}
 @ExceptionHandler(MultipartException.class) ResponseEntity<ApiError> upload(Exception e){return error(HttpStatus.BAD_REQUEST,"Invalid file upload.");}
 @ExceptionHandler(Exception.class) ResponseEntity<ApiError> unexpected(Exception e){log.error("Unexpected request failure",e);return error(HttpStatus.INTERNAL_SERVER_ERROR,"An unexpected server error occurred.");}
}
