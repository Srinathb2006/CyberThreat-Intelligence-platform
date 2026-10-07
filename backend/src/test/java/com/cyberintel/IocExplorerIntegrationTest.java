package com.cyberintel;

import com.cyberintel.entity.*;
import com.cyberintel.repository.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest @AutoConfigureMockMvc @ActiveProfiles("test")
class IocExplorerIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired UserRepository users;
    @Autowired ScanRepository scans;
    @Autowired ApkAnalysisRepository analyses;
    @Autowired IocRepository iocs;
    @Autowired ThreatIntelligenceRepository intelligence;
    @Autowired ThreatMatchRepository matches;

    record Account(String email, String token) {}
    private Account account() throws Exception {
        String email = "ioc-" + UUID.randomUUID() + "@example.com";
        String body = json.writeValueAsString(Map.of("name", "IOC Tester", "email", email, "password", "FixturePassword123!"));
        String token = json.readTree(mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString()).get("token").asText();
        return new Account(email, token);
    }
    private ApkAnalysis analysis(Account account, String target) {
        User user = users.findByEmail(account.email()).orElseThrow();
        Scan scan = scans.save(new Scan(Scan.ScanType.APK, target, user));
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.scan = scan;
        analysis.md5 = "d41d8cd98f00b204e9800998ecf8427e";
        analysis.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        analysis.storageKey = "test/ioc-explorer.apk";
        analysis.sourceSummary = "{}";
        return analyses.save(analysis);
    }
    private IOC ioc(ApkAnalysis analysis, String value, String type, String severity, String confidence) {
        IOC ioc = new IOC();
        ioc.apkAnalysis = analysis;
        ioc.value = value;
        ioc.type = type;
        ioc.source = "STATIC_ANALYSIS";
        ioc.severity = severity;
        ioc.confidence = confidence;
        ioc.description = "Stored IOC description";
        ioc.firstSeen = Instant.parse("2026-01-01T00:00:00Z");
        ioc.lastSeen = Instant.parse("2026-01-02T00:00:00Z");
        return iocs.save(ioc);
    }
    private ThreatMatch matched(IOC ioc) {
        ThreatIntelligence ti = new ThreatIntelligence();
        ti.indicator = ioc.value;
        ti.indicatorType = ioc.type;
        ti.threatName = "Fixture malware";
        ti.threatFamily = "Fixture family";
        ti.category = "MALWARE";
        ti.severity = "HIGH";
        ti.confidence = "HIGH";
        ti.description = "Known malicious fixture";
        ti.source = "LOCAL_TEST_FEED";
        ti.active = true;
        ti.createdAt = Instant.now(); ti.updatedAt = Instant.now();
        intelligence.save(ti);
        ThreatMatch match = new ThreatMatch();
        match.ioc = ioc; match.threatIntelligence = ti; match.status = "MATCHED"; match.matchType = "EXACT";
        match.severity = "HIGH"; match.confidence = "HIGH"; match.description = "Fixture match";
        return matches.save(match);
    }

    @Test void readsCurrentUsersStoredIocsWithFiltersAndMatchDetails() throws Exception {
        Account owner = account();
        ApkAnalysis firstAnalysis = analysis(owner, "owner-first.apk");
        ApkAnalysis secondAnalysis = analysis(owner, "owner-second.apk");
        IOC matching = ioc(firstAnalysis, "explorer-fixture.example", "DOMAIN", "HIGH", "HIGH");
        matched(matching);
        ioc(firstAnalysis, "198.51.100.88", "IP", "MEDIUM", "LOW");
        ioc(secondAnalysis, "https://unique-explorer.example/path", "URL", "LOW", "MEDIUM");

        mvc.perform(get("/api/ioc-explorer").header("Authorization", "Bearer " + owner.token())
                .param("search", "fixture").param("type", "DOMAIN").param("severity", "HIGH").param("confidence", "HIGH")
                .param("scanId", firstAnalysis.scan.getId().toString()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(matching.id))
                .andExpect(jsonPath("$[0].scanId").value(firstAnalysis.scan.getId()))
                .andExpect(jsonPath("$[0].scanTarget").value("owner-first.apk"))
                .andExpect(jsonPath("$[0].threatMatches.length()").value(1))
                .andExpect(jsonPath("$[0].threatMatches[0].status").value("MATCHED"))
                .andExpect(jsonPath("$[0].threatMatches[0].threatName").value("Fixture malware"));

        mvc.perform(get("/api/ioc-explorer/" + matching.id).header("Authorization", "Bearer " + owner.token()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.value").value("explorer-fixture.example"))
                .andExpect(jsonPath("$.threatMatches[0].threatSource").value("LOCAL_TEST_FEED"));
        mvc.perform(get("/api/ioc-explorer").header("Authorization", "Bearer " + owner.token()).param("scanId", secondAnalysis.scan.getId().toString()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].type").value("URL"));
    }

    @Test void isolatesOtherUsersAndRequiresAuthentication() throws Exception {
        Account owner = account(), other = account();
        IOC privateIoc = ioc(analysis(owner, "private.apk"), "private-explorer.example", "DOMAIN", "CRITICAL", "HIGH");
        mvc.perform(get("/api/ioc-explorer").header("Authorization", "Bearer " + other.token()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(0));
        mvc.perform(get("/api/ioc-explorer/" + privateIoc.id).header("Authorization", "Bearer " + other.token()))
                .andExpect(status().isNotFound());
        mvc.perform(get("/api/ioc-explorer")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/ioc-explorer/" + privateIoc.id)).andExpect(status().isUnauthorized());
        assertThat(iocs.findById(privateIoc.id)).isPresent();
    }
}
