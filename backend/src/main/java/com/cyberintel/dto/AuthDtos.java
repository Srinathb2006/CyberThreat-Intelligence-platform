package com.cyberintel.dto;
import com.cyberintel.entity.*;
import jakarta.validation.constraints.*;
public final class AuthDtos {
 private AuthDtos(){}
 public record RegisterRequest(@NotBlank @Size(max=100) String name,
  @NotBlank @Email @Size(max=254) String email,
  @NotBlank @Size(min=10,max=72) String password) {}
 public record LoginRequest(@NotBlank @Email @Size(max=254) String email,
  @NotBlank @Size(max=72) String password) {}
 public record UserResponse(Long id,String name,String email,Role role){
  public static UserResponse from(User user){return new UserResponse(user.getId(),user.getName(),user.getEmail(),user.getRole());}
 }
 public record AuthResponse(String token,UserResponse user){}
}
