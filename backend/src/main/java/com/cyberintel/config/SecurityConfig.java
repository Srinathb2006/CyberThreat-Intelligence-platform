package com.cyberintel.config;
import com.cyberintel.security.*;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.*;
@Configuration @EnableMethodSecurity
public class SecurityConfig {
 @Bean FilterRegistrationBean<JwtAuthenticationFilter> jwtFilterRegistration(JwtAuthenticationFilter filter){
  var registration=new FilterRegistrationBean<>(filter);registration.setEnabled(false);return registration;
 }
 @Bean PasswordEncoder passwordEncoder(){return new BCryptPasswordEncoder(12);}
 @Bean SecurityFilterChain security(HttpSecurity http,JwtAuthenticationFilter jwt,SecurityErrorWriter errors)throws Exception{
  return http.csrf(csrf->csrf.disable()).cors(cors->{})
   .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
   .authorizeHttpRequests(auth->auth.requestMatchers(HttpMethod.POST,"/api/auth/register","/api/auth/login").permitAll()
    .requestMatchers("/api/admin/**").hasRole("ADMIN").anyRequest().authenticated())
   .exceptionHandling(handler->handler.authenticationEntryPoint((req,res,e)->errors.write(res,401,"Authentication required."))
    .accessDeniedHandler((req,res,e)->errors.write(res,403,"Access denied.")))
   .addFilterBefore(jwt,UsernamePasswordAuthenticationFilter.class).build();
 }
 @Bean CorsConfigurationSource corsConfigurationSource(@Value("${app.cors-origins}") String origins){
  var config=new CorsConfiguration();
  var allowed=Arrays.stream(origins.split(",")).map(String::trim).filter(s->!s.isEmpty()).toList();
  if(allowed.isEmpty() || allowed.contains("*"))throw new IllegalArgumentException("Configure explicit CORS origins.");
  config.setAllowedOrigins(allowed);config.setAllowedMethods(List.of("GET","POST","PUT","PATCH","DELETE","OPTIONS"));
  config.setAllowedHeaders(List.of("Authorization","Content-Type"));config.setAllowCredentials(false);config.setMaxAge(3600L);
  var source=new UrlBasedCorsConfigurationSource();source.registerCorsConfiguration("/api/**",config);return source;
 }
}
