package com.cyberintel.controller;
import com.cyberintel.dto.AuthDtos.*;
import com.cyberintel.service.AuthService;
import jakarta.validation.Valid;
import java.security.Principal;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
@RestController @RequestMapping("/api/auth")
public class AuthController {
 private final AuthService auth;
 public AuthController(AuthService auth){this.auth=auth;}
 @PostMapping("/register") @ResponseStatus(HttpStatus.CREATED) public AuthResponse register(@Valid @RequestBody RegisterRequest request){return auth.register(request);}
 @PostMapping("/login") public AuthResponse login(@Valid @RequestBody LoginRequest request){return auth.login(request);}
 @GetMapping("/me") public UserResponse me(Principal principal){return auth.current(principal.getName());}
}
