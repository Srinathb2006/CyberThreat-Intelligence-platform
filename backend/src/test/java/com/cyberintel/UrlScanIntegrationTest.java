package com.cyberintel;

import com.cyberintel.repository.ScanRepository;
import com.cyberintel.repository.UrlScanRepository;
import com.fasterxml.jackson.databind.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.http.MediaType;
import java.util.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest @AutoConfigureMockMvc @ActiveProfiles("test")
class UrlScanIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired ScanRepository scans;
    @Autowired UrlScanRepository results;

    private String token() throws Exception {
        String body = json.writeValueAsString(Map.of("name", "URL Tester", "email", UUID.randomUUID() + "@example.com", "password", "FixturePassword123!"));
        return json.readTree(mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString()).get("token").asText();
    }
    @Test void savesReloadsAndIsolatesResultsWithoutContactingTarget() throws Exception {
        String owner = token(), other = token();
        // .invalid cannot resolve, but local analysis must succeed.
        String url = "http://never-resolve.invalid:8080/%2576erify?account=urgent";
        JsonNode created = json.readTree(mvc.perform(post("/api/url-scans").header("Authorization", "Bearer " + owner)
                .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(Map.of("url", url))))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.status").value("COMPLETED"))
                .andReturn().getResponse().getContentAsString());
        long id = created.get("scanId").asLong();
        assertThat(scans.findById(id).orElseThrow().getScanType().name()).isEqualTo("URL");
        assertThat(scans.findById(id).orElseThrow().getRiskScore()).isEqualTo(created.at("/analysis/score").asInt());
        JsonNode reloaded = json.readTree(mvc.perform(get("/api/url-scans/" + id).header("Authorization", "Bearer " + owner))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertThat(reloaded.get("analysis")).isEqualTo(created.get("analysis"));
        assertThat(reloaded.get("url")).isEqualTo(created.get("url"));
        assertThat(reloaded.get("scanId")).isEqualTo(created.get("scanId"));
        assertThat(reloaded.get("status")).isEqualTo(created.get("status"));
        // Database timestamps have microsecond precision rather than JVM nanoseconds.
        assertThat(java.time.Duration.between(java.time.Instant.parse(created.get("createdAt").asText()),
                java.time.Instant.parse(reloaded.get("createdAt").asText())).abs()).isLessThan(java.time.Duration.ofMillis(1));
        mvc.perform(get("/api/url-scans").header("Authorization", "Bearer " + owner))
                .andExpect(status().isOk()).andExpect(jsonPath("$[0].scanId").value(id));
        mvc.perform(get("/api/url-scans").header("Authorization", "Bearer " + other))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(0));
        mvc.perform(get("/api/url-scans/" + id).header("Authorization", "Bearer " + other)).andExpect(status().isNotFound());
        mvc.perform(get("/api/url-scans/9223372036854775807").header("Authorization", "Bearer " + owner)).andExpect(status().isNotFound());
    }
    @Test void validationAndAuthenticationDoNotCreateRecords() throws Exception {
        String owner = token();
        long before = results.count(), scansBefore = scans.count();
        for (String body : List.of("{}", "{\"url\":null}", "{\"url\":\"\"}", "{\"url\":\"file:///etc/passwd\"}", "{\"url\":\"https://127.1\"}",
                json.writeValueAsString(Map.of("url", "https://example.com/" + "a".repeat(2048))))) {
            mvc.perform(post("/api/url-scans").header("Authorization", "Bearer " + owner)
                    .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isBadRequest());
        }
        mvc.perform(post("/api/url-scans").contentType(MediaType.APPLICATION_JSON).content("{\"url\":\"https://example.com\"}"))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/url-scans")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/url-scans/1")).andExpect(status().isUnauthorized());
        assertThat(results.count()).isEqualTo(before);
        assertThat(scans.count()).isEqualTo(scansBefore);
    }
}
