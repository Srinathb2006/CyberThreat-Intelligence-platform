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
 @Autowired com.cyberintel.repository.MalwareFindingRepository malwareFindings;
 @Autowired com.cyberintel.repository.AlertRepository alerts;
 @Test void riskCalculationPersistsRecommendationsAndGeneratesAlerts() throws Exception {
  String token = token();
  long id = upload(token);
  var finding = new com.cyberintel.entity.MalwareFinding();
  finding.apkAnalysis = repository.findByScanId(id).orElseThrow();
  finding.category = "dynamic_loading";
  finding.title = "Dynamic code loading";
  finding.description = "Loads external code";
  finding.evidence = "DexClassLoader";
  finding.severity = "HIGH";
  finding.confidence = "HIGH";
  finding.source = "STATIC";
  finding.ruleId = "dynamic_loading_test";
  malwareFindings.save(finding);

  var calculated = json.readTree(mvc.perform(post("/api/risk-correlation/" + id + "/calculate")
    .header("Authorization", "Bearer " + token)).andExpect(status().isOk())
    .andReturn().getResponse().getContentAsString());
  assertThat(alerts.findByScanIdOrderByCreatedAtDesc(id)).hasSize(1);
  assertThat(calculated.get("recommendations").get(0).get("category").asText()).isEqualTo("DYNAMIC_CODE_LOADING");
  malwareFindings.deleteById(finding.id);
  var reloaded = json.readTree(mvc.perform(get("/api/risk-correlation/" + id)
    .header("Authorization", "Bearer " + token)).andExpect(status().isOk())
    .andReturn().getResponse().getContentAsString());
  assertThat(reloaded.get("recommendations")).isEqualTo(calculated.get("recommendations"));
  var recommendations = json.readTree(mvc.perform(get("/api/risk-correlation/" + id + "/recommendations")
    .header("Authorization", "Bearer " + token)).andExpect(status().isOk())
    .andReturn().getResponse().getContentAsString());
  assertThat(recommendations).isEqualTo(calculated.get("recommendations"));
  mvc.perform(get("/api/reports/" + id + "/json")
    .header("Authorization", "Bearer " + token)).andExpect(status().isOk())
    .andExpect(jsonPath("$.riskAssessment.indicators[0].sourceType").value("malware_finding"));

  finding.id = null;
  malwareFindings.save(finding);
  mvc.perform(post("/api/risk-correlation/" + id + "/calculate")
    .header("Authorization", "Bearer " + token)).andExpect(status().isOk());
  assertThat(alerts.findByScanIdOrderByCreatedAtDesc(id)).hasSize(1);
 }
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
  assertThat(result.get("toolStatus").get("androguard").asText()).isEqualTo("MOCK");
  assertThat(result.get("permissions").size()).isGreaterThan(0);assertThat(repository.findByScanId(id)).isPresent();
  mvc.perform(post("/api/static-analysis/" + id).header("Authorization", "Bearer " + token))
    .andExpect(status().isOk());
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
 @Test void yaraDemoIsPersistedAndScopedToOwner()throws Exception{
  String owner=token();long id=upload(owner);
  mvc.perform(post("/api/apk-analysis/"+id+"/yara").header("Authorization","Bearer "+owner)).andExpect(status().isConflict());
  mvc.perform(post("/api/apk-analysis/"+id+"/start").header("Authorization","Bearer "+owner)).andExpect(status().isAccepted());
  for(int i=0;i<60;i++){
   var response=json.readTree(mvc.perform(get("/api/apk-analysis/"+id).header("Authorization","Bearer "+owner)).andReturn().getResponse().getContentAsString());
   if(response.get("status").asText().equals("COMPLETED"))break;
   Thread.sleep(100);
  }
  var result=json.readTree(mvc.perform(post("/api/apk-analysis/"+id+"/yara").header("Authorization","Bearer "+owner))
   .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
  assertThat(result.get("mode").asText()).isEqualTo("DEMO");
  assertThat(result.get("message").asText()).contains("synthetic");
  assertThat(result.get("matches").get(0).get("ruleName").asText()).isEqualTo("DEMO_SAMPLE_RULE");
  assertThat(result.get("matches").get(0).get("evidence").asText()).startsWith("DEMO:");
  var saved=json.readTree(mvc.perform(get("/api/apk-analysis/"+id+"/yara").header("Authorization","Bearer "+owner))
   .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
  assertThat(saved).isEqualTo(result);
  String other=token();
  mvc.perform(get("/api/apk-analysis/"+id+"/yara").header("Authorization","Bearer "+other)).andExpect(status().isNotFound());
  mvc.perform(post("/api/apk-analysis/"+id+"/yara").header("Authorization","Bearer "+other)).andExpect(status().isNotFound());
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
