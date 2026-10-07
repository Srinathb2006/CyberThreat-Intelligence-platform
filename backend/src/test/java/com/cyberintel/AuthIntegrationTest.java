package com.cyberintel;
import com.cyberintel.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.http.MediaType;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.assertj.core.api.Assertions.*;
@SpringBootTest @AutoConfigureMockMvc @ActiveProfiles("test")
class AuthIntegrationTest {
 @Autowired MockMvc mvc; @Autowired ObjectMapper json; @Autowired UserRepository users;
 @Test void registrationLoginAndAuthorization()throws Exception{
  var response=mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
   .content("{\"name\":\"Analyst\",\"email\":\"Analyst@example.com\",\"password\":\"StrongPass123!\"}"))
   .andExpect(status().isCreated()).andExpect(jsonPath("$.user.role").value("USER"))
   .andExpect(jsonPath("$.user.password").doesNotExist()).andReturn().getResponse().getContentAsString();
  String token=json.readTree(response).get("token").asText();
  assertThat(users.findByEmail("analyst@example.com").orElseThrow().getPassword()).startsWith("$2").isNotEqualTo("StrongPass123!");
  mvc.perform(get("/api/auth/me").header("Authorization","Bearer "+token)).andExpect(status().isOk()).andExpect(jsonPath("$.email").value("analyst@example.com"));
  mvc.perform(get("/api/admin/tools").header("Authorization","Bearer "+token)).andExpect(status().isForbidden()).andExpect(jsonPath("$.status").value(403));
  mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content("{\"email\":\"analyst@example.com\",\"password\":\"StrongPass123!\"}"))
   .andExpect(status().isOk()).andExpect(jsonPath("$.token").isString());
  mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content("{\"email\":\"analyst@example.com\",\"password\":\"wrong\"}"))
   .andExpect(status().isUnauthorized());
  mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"Duplicate\",\"email\":\"analyst@example.com\",\"password\":\"StrongPass123!\"}"))
   .andExpect(status().isConflict());
 }
 @Test void invalidRequestsAndTokensAreRejected()throws Exception{
  mvc.perform(get("/api/platform/status")).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.success").value(false));
  mvc.perform(get("/api/platform/status").header("Authorization","Bearer forged")).andExpect(status().isUnauthorized());
  mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"\",\"email\":\"bad\",\"password\":\"short\"}")).andExpect(status().isBadRequest());
  mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"Admin\",\"email\":\"admin@example.com\",\"password\":\"StrongPass123!\",\"role\":\"ADMIN\"}")).andExpect(status().isBadRequest());
 }
 @Test void corsOnlyAllowsConfiguredFrontend()throws Exception{
  mvc.perform(options("/api/auth/login").header("Origin","http://localhost:5173").header("Access-Control-Request-Method","POST"))
   .andExpect(status().isOk()).andExpect(header().string("Access-Control-Allow-Origin","http://localhost:5173"));
  mvc.perform(options("/api/auth/login").header("Origin","https://untrusted.example").header("Access-Control-Request-Method","POST"))
   .andExpect(status().isForbidden());
 }
}
