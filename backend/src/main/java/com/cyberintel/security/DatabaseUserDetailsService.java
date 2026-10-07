package com.cyberintel.security;
import com.cyberintel.repository.UserRepository;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;
@Service
public class DatabaseUserDetailsService implements UserDetailsService {
 private final UserRepository users;
 public DatabaseUserDetailsService(UserRepository users){this.users=users;}
 public UserDetails loadUserByUsername(String email){
  var user=users.findByEmail(email).orElseThrow(()->new UsernameNotFoundException("User not found"));
  return org.springframework.security.core.userdetails.User.withUsername(user.getEmail()).password(user.getPassword()).roles(user.getRole().name()).build();
 }
}
