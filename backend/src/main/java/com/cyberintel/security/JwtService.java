package com.cyberintel.security;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import com.cyberintel.entity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
@Service
public class JwtService {
 private final SecretKey key; private final long expiration;
 public JwtService(@Value("${app.jwt.secret}") String secret,@Value("${app.jwt.expiration-seconds}") long expiration){
  if(secret.getBytes(StandardCharsets.UTF_8).length<32) throw new IllegalArgumentException("JWT_SECRET must contain at least 32 bytes of random secret material.");
  if(expiration<60 || expiration>86400) throw new IllegalArgumentException("JWT expiration must be 60–86400 seconds.");
  this.key=Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)); this.expiration=expiration;
 }
 public String generate(User user){Instant now=Instant.now();return Jwts.builder().issuer("cyberintel").subject(user.getEmail())
  .issuedAt(Date.from(now)).expiration(Date.from(now.plusSeconds(expiration))).signWith(key).compact();}
 public String subject(String token){return Jwts.parser().verifyWith(key).requireIssuer("cyberintel").build().parseSignedClaims(token).getPayload().getSubject();}
}
