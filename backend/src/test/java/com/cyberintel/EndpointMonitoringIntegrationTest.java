package com.cyberintel;

import com.cyberintel.repository.EndpointRepository;
import com.cyberintel.repository.EndpointSecurityEventRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import java.util.Map;
import java.util.UUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest @AutoConfigureMockMvc @ActiveProfiles("test")
class EndpointMonitoringIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired EndpointRepository endpoints;
    @Autowired EndpointSecurityEventRepository events;
    private String token() throws Exception {
        String body = json.writeValueAsString(Map.of("name", "Endpoint Tester", "email", "endpoint-" + UUID.randomUUID() + "@example.com", "password", "FixturePassword123!"));
        return json.readTree(mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString()).get("token").asText();
    }
    private JsonNode register(String token, String hostname) throws Exception {
        String body = json.writeValueAsString(Map.of("hostname", hostname, "deviceName", "Finance Laptop", "operatingSystem", "Windows 11", "platform", "WINDOWS", "status", "ONLINE"));
        return json.readTree(mvc.perform(post("/api/endpoints").header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString());
    }
    @Test void registersDemoEndpointWithRiskAndEvents() throws Exception {
        String owner = token(); JsonNode endpoint = register(owner, "FINANCE-LAPTOP"); long id = endpoint.get("id").asLong();
        assertThat(endpoint.get("hostname").asText()).isEqualTo("finance-laptop");
        assertThat(endpoint.get("demoData").asBoolean()).isTrue();
        assertThat(endpoint.at("/riskSummary/score").asInt()).isEqualTo(45);
        assertThat(endpoint.at("/riskSummary/riskLevel").asText()).isEqualTo("MEDIUM");
        assertThat(events.findByEndpointIdOrderByObservedAtDesc(id)).hasSize(3);
        mvc.perform(get("/api/endpoints").header("Authorization", "Bearer " + owner))
                .andExpect(status().isOk()).andExpect(jsonPath("$[0].id").value(id)).andExpect(jsonPath("$[0].riskSummary.suspiciousEvents").value(2));
        mvc.perform(get("/api/endpoints/" + id).header("Authorization", "Bearer " + owner))
                .andExpect(status().isOk()).andExpect(jsonPath("$.events.length()").value(3)).andExpect(jsonPath("$.events[0].demoData").value(true));
        mvc.perform(get("/api/endpoints/" + id + "/events").header("Authorization", "Bearer " + owner).param("suspiciousOnly", "true"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(2)).andExpect(jsonPath("$[0].suspicious").value(true));
        mvc.perform(get("/api/endpoints/" + id).header("Authorization", "Bearer " + owner).param("suspiciousOnly", "true"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.events.length()").value(2)).andExpect(jsonPath("$.endpoint.riskSummary.totalEvents").value(3));
    }
    @Test void validatesRegistrationAndScopesEndpointsToOwner() throws Exception {
        String owner = token(), other = token(); JsonNode endpoint = register(owner, "private-node"); long id = endpoint.get("id").asLong();
        mvc.perform(get("/api/endpoints").header("Authorization", "Bearer " + other)).andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(0));
        mvc.perform(get("/api/endpoints/" + id).header("Authorization", "Bearer " + other)).andExpect(status().isNotFound());
        mvc.perform(get("/api/endpoints/" + id + "/events").header("Authorization", "Bearer " + other)).andExpect(status().isNotFound());
        mvc.perform(post("/api/endpoints").header("Authorization", "Bearer " + owner).contentType(MediaType.APPLICATION_JSON)
                .content("{\"hostname\":\"private-node\",\"deviceName\":\"Duplicate\",\"operatingSystem\":\"Linux\",\"platform\":\"LINUX\"}"))
                .andExpect(status().isConflict());
        for (String body : new String[]{"{}", "{\"hostname\":\"bad host\",\"deviceName\":\"x\",\"operatingSystem\":\"Linux\",\"platform\":\"LINUX\"}",
                "{\"hostname\":\"okay\",\"deviceName\":\"x\",\"operatingSystem\":\"Linux\",\"platform\":\"LINUX\",\"status\":\"RUNNING\"}"}) {
            mvc.perform(post("/api/endpoints").header("Authorization", "Bearer " + owner).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isBadRequest());
        }
        mvc.perform(get("/api/endpoints")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/endpoints").contentType(MediaType.APPLICATION_JSON).content("{}")) .andExpect(status().isUnauthorized());
        assertThat(endpoints.findById(id)).isPresent();
    }
}
