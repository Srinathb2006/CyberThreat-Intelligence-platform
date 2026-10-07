package com.cyberintel.security;
import com.cyberintel.exception.ApiError;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.stereotype.Component;
@Component
public class SecurityErrorWriter {
 private final ObjectMapper mapper;
 public SecurityErrorWriter(ObjectMapper mapper){this.mapper=mapper;}
 public void write(HttpServletResponse response,int status,String message)throws IOException{
  response.setStatus(status);response.setContentType("application/json");mapper.writeValue(response.getOutputStream(),ApiError.of(status,message));
 }
}
