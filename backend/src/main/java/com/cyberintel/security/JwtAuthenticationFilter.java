package com.cyberintel.security;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.dao.DataAccessException;
import org.springframework.web.filter.OncePerRequestFilter;
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
 private final JwtService jwt;private final DatabaseUserDetailsService users;private final SecurityErrorWriter errors;
 public JwtAuthenticationFilter(JwtService jwt,DatabaseUserDetailsService users,SecurityErrorWriter errors){this.jwt=jwt;this.users=users;this.errors=errors;}
 @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain)throws ServletException,IOException{
  String header=request.getHeader("Authorization");
  if(header!=null && header.startsWith("Bearer ")){
   try {
    var user=users.loadUserByUsername(jwt.subject(header.substring(7)));
    SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user,null,user.getAuthorities()));
   } catch(JwtException|IllegalArgumentException|UsernameNotFoundException e){
    SecurityContextHolder.clearContext();errors.write(response,401,"Invalid or expired authentication token.");return;
   } catch(DataAccessException e){
    SecurityContextHolder.clearContext();errors.write(response,503,"Database temporarily unavailable.");return;
   }
  }
  chain.doFilter(request,response);
 }
}
