package com.cyberintel.service;
import com.cyberintel.dto.AuthDtos.*;
import com.cyberintel.entity.User;
import com.cyberintel.repository.UserRepository;
import com.cyberintel.security.JwtService;
import com.cyberintel.exception.ApiException;
import com.cyberintel.util.InputNormalizer;
import java.nio.charset.StandardCharsets;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
@Service
public class AuthService {
 private final UserRepository users;private final PasswordEncoder encoder;private final JwtService jwt;private final String dummyHash;
 public AuthService(UserRepository users,PasswordEncoder encoder,JwtService jwt){this.users=users;this.encoder=encoder;this.jwt=jwt;this.dummyHash=encoder.encode("timing-only-unusable-password");}
 @Transactional public AuthResponse register(RegisterRequest request){
  if(request.password().getBytes(StandardCharsets.UTF_8).length>72)throw new ApiException(HttpStatus.BAD_REQUEST,"Password must not exceed 72 UTF-8 bytes.");
  String email=InputNormalizer.email(request.email());
  if(users.existsByEmail(email))throw new ApiException(HttpStatus.CONFLICT,"An account with this email already exists.");
  var user=users.saveAndFlush(new User(request.name().strip(),email,encoder.encode(request.password())));
  return response(user);
 }
 @Transactional(readOnly=true) public AuthResponse login(LoginRequest request){
  if(request.password().getBytes(StandardCharsets.UTF_8).length>72)throw new BadCredentialsException("Invalid credentials");
  var user=users.findByEmail(InputNormalizer.email(request.email())).orElse(null);
  boolean matches=encoder.matches(request.password(),user==null?dummyHash:user.getPassword());
  if(user==null || !matches)throw new BadCredentialsException("Invalid credentials");
  return response(user);
 }
 @Transactional(readOnly=true) public UserResponse current(String email){return UserResponse.from(users.findByEmail(email).orElseThrow(()->new BadCredentialsException("Invalid credentials")));}
 private AuthResponse response(User user){return new AuthResponse(jwt.generate(user),UserResponse.from(user));}
}
