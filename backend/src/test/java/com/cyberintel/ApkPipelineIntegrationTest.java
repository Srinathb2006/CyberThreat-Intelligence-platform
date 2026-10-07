package com.cyberintel;
import com.fasterxml.jackson.databind.*;
import com.cyberintel.repository.ApkAnalysisRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.http.MediaType;
import java.security.MessageDigest;
import java.util.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.assertj.core.api.Assertions.*;
@SpringBootTest @AutoConfigureMockMvc @ActiveProfiles("test")
class ApkPipelineIntegrationTest {
 @Autowired MockMvc mvc;@Autowired ObjectMapper json;@Autowired ApkAnalysisRepository repository;
 String token()throws Exception{
  String body=json.writeValueAsString(Map.of("name","APK Tester","email",UUID.randomUUID()+"@example.com","password","FixturePassword123!"));
  return json.readTree(mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isCreated()).andReturn().getResponse().getContentAsString()).get("token").asText();
 }
 long upload(String token)throws Exception{
  byte[] apk=ApkTestFixtures.apk(null);
  var response=mvc.perform(multipart("/api/apk/upload").file(new MockMultipartFile("file","safe.apk","application/vnd.android.package-archive",apk)).header("Authorization","Bearer "+token))
   .andExpect(status().isCreated()).andExpect(jsonPath("$.status").value("UPLOADED"))
   .andExpect(jsonPath("$.sha256").value(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(apk))))
   .andReturn().getResponse().getContentAsString();
  return json.readTree(response).get("scanId").asLong();
 }
 @Test void uploadHashMockResultsPersistenceAndOwnership()throws Exception{
  String token=token();long id=upload(token);
  mvc.perform(post("/api/apk-analysis/"+id+"/start").header("Authorization","Bearer "+token)).andExpect(status().isAccepted());
  JsonNode result=null;
  for(int i=0;i<60;i++){
   result=json.readTree(mvc.perform(get("/api/apk-analysis/"+id).header("Authorization","Bearer "+token)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
   if(result.get("status").asText().equals("COMPLETED"))break;
   Thread.sleep(100);
  }
  assertThat(result.get("status").asText()).isEqualTo("COMPLETED");assertThat(result.get("analysisMode").asText()).isEqualTo("MOCK");
  assertThat(result.get("permissions").size()).isGreaterThan(0);assertThat(repository.findByScanId(id)).isPresent();
  assertThat(result.toString()).doesNotContain("storageKey","target/test-analysis","riskScore");
  mvc.perform(get("/api/apk-analysis/"+id).header("Authorization","Bearer "+token())).andExpect(status().isNotFound());
  mvc.perform(post("/api/apk-analysis/"+id+"/start").header("Authorization","Bearer "+token())).andExpect(status().isNotFound());
  mvc.perform(post("/api/apk-analysis/"+id+"/cancel").header("Authorization","Bearer "+token())).andExpect(status().isNotFound());
  mvc.perform(get("/api/apk-analysis").header("Authorization","Bearer "+token)).andExpect(jsonPath("$[0].scanId").value(id));
  mvc.perform(post("/api/apk-analysis/"+id+"/start").header("Authorization","Bearer "+token)).andExpect(status().isConflict());
 }
 @Test void cancellationIsTerminal()throws Exception{
  String token=token();long id=upload(token);
  mvc.perform(post("/api/apk-analysis/"+id+"/cancel").header("Authorization","Bearer "+token)).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("CANCELLED"));
  mvc.perform(post("/api/apk-analysis/"+id+"/start").header("Authorization","Bearer "+token)).andExpect(status().isConflict());
 }
 @Test void rejectsInvalidFilesAndUnauthenticatedUpload()throws Exception{
  String token=token();byte[] valid=ApkTestFixtures.apk(null);
  mvc.perform(multipart("/api/apk/upload").file(new MockMultipartFile("file","safe.apk","application/octet-stream",valid))).andExpect(status().isUnauthorized());
  for(String name:List.of("safe.apk.zip","safe.exe","safe.jar","safe.zip","safe.rar","../safe.apk","a\\safe.apk")){
   mvc.perform(multipart("/api/apk/upload").file(new MockMultipartFile("file",name,"application/octet-stream",valid)).header("Authorization","Bearer "+token)).andExpect(status().isBadRequest());
  }
  mvc.perform(multipart("/api/apk/upload").file(new MockMultipartFile("file","bad.apk","application/octet-stream",new byte[]{0x50,0x4b,3,4,0,0,0,0})).header("Authorization","Bearer "+token)).andExpect(status().isBadRequest());
  mvc.perform(multipart("/api/apk/upload").file(new MockMultipartFile("file","bad.apk","application/octet-stream",ApkTestFixtures.apk("../escape"))).header("Authorization","Bearer "+token)).andExpect(status().isBadRequest());
  mvc.perform(multipart("/api/apk/upload").file(new MockMultipartFile("file","bad.apk","text/plain",valid)).header("Authorization","Bearer "+token)).andExpect(status().isBadRequest());
 }
}
