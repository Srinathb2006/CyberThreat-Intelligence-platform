package com.cyberintel;

import com.cyberintel.repository.ScanRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.http.MediaType;
import java.util.Map;
import java.util.UUID;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest @AutoConfigureMockMvc @ActiveProfiles("test")
class PhishingDetectionIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired ScanRepository scans;

    private String token() throws Exception {
        String body = json.writeValueAsString(Map.of("name", "Phishing Tester", "email", UUID.randomUUID() + "@example.com", "password", "FixturePassword123!"));
        return json.readTree(mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString()).get("token").asText();
    }
    @Test void returnsExplainableStatelessAssessment() throws Exception {
        String owner = token();
        long before = scans.count();
        var response = mvc.perform(post("/api/phishing/analyze").header("Authorization", "Bearer " + owner)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"https://never-resolve.invalid/login?next=http://other.zip/verify\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.host").value("never-resolve.invalid"))
                .andExpect(jsonPath("$.https").value(true)).andExpect(jsonPath("$.reasons").isArray())
                .andExpect(jsonPath("$.redirectIndicators[0].host").value("other.zip"))
                .andReturn().getResponse().getContentAsString();
        var result = json.readTree(response);
        assertThat(result.get("score").asInt()).isBetween(0, 100);
        assertThat(result.get("riskLevel").asText()).isIn("LOW", "MEDIUM", "HIGH", "CRITICAL");
        for (var reason : result.get("reasons")) {
            assertThat(reason.get("description").asText()).isNotBlank();
            assertThat(reason.get("evidence").asText()).isNotBlank();
            assertThat(reason.get("contribution").asInt()).isPositive();
        }
        assertThat(scans.count()).isEqualTo(before);
    }
    @Test void requiresAuthenticationAndRejectsInvalidInput() throws Exception {
        mvc.perform(post("/api/phishing/analyze").contentType(MediaType.APPLICATION_JSON)
                .content("{\"url\":\"https://example.com\"}")).andExpect(status().isUnauthorized());
        String owner = token();
        for (String body : new String[]{"{}", "{\"url\":null}", "{\"url\":\"\"}", "{\"url\":\"file:///etc/passwd\"}",
                "{\"url\":\"https://example.com/%250a\"}", json.writeValueAsString(Map.of("url", "https://example.com/" + "a".repeat(2048)))}) {
            mvc.perform(post("/api/phishing/analyze").header("Authorization", "Bearer " + owner)
                    .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isBadRequest());
        }
    }
}
