package com.cyberintel;
import com.cyberintel.security.JwtService;
import com.cyberintel.entity.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
class JwtServiceTest {
 private static final String SECRET="test-only-secret-material-at-least-32-bytes-long";
 @Test void rejectsExpiredAndIncorrectlySignedTokens(){
  var service=new JwtService(SECRET,3600);
  var key=Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
  var expired=Jwts.builder().issuer("cyberintel").subject("test@example.com").expiration(new Date(1)).signWith(key).compact();
  assertThatThrownBy(()->service.subject(expired)).isInstanceOf(ExpiredJwtException.class);
  var other=new JwtService("another-test-only-secret-material-at-least-32-bytes",3600);
  var token=other.generate(new User("Test","test@example.com","hashed"));
  assertThatThrownBy(()->service.subject(token)).isInstanceOf(JwtException.class);
 }
 @Test void rejectsWeakSecret(){assertThatThrownBy(()->new JwtService("weak",3600)).isInstanceOf(IllegalArgumentException.class);}
}
