package com.cyberintel.exception;
import java.time.Instant;
public record ApiError(boolean success,String message,Instant timestamp,int status) {
 public static ApiError of(int status,String message){return new ApiError(false,message,Instant.now(),status);}
}
