package com.cyberintel.repository;

import com.cyberintel.entity.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@EntityScan(basePackages = "com.cyberintel.entity")
@EnableJpaRepositories(basePackages = "com.cyberintel.repository")
@ActiveProfiles("test")
class ThreatMatchRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private ThreatMatchRepository repository;

    private ApkAnalysis createAnalysis(String email) {
        User user = new User("Test User", email, "password");
        entityManager.persistAndFlush(user);

        Scan scan = new Scan(Scan.ScanType.APK, "test.apk", user);
        entityManager.persistAndFlush(scan);

        ApkAnalysis analysis = new ApkAnalysis();
        analysis.scan = scan;
        analysis.md5 = "d41d8cd98f00b204e9800998ecf8427e";
        analysis.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        analysis.storageKey = "storage/test.apk";
        analysis.sourceSummary = "{}";
        entityManager.persistAndFlush(analysis);
        return analysis;
    }

    private IOC createIoc(ApkAnalysis analysis, String value, String type) {
        IOC ioc = new IOC();
        ioc.apkAnalysis = analysis;
        ioc.value = value;
        ioc.type = type;
        ioc.source = "STATIC_ANALYSIS";
        ioc.severity = "MEDIUM";
        ioc.confidence = "MEDIUM";
        ioc.description = "Test IOC";
        ioc.firstSeen = Instant.now();
        ioc.lastSeen = Instant.now();
        return ioc;
    }

    private ThreatIntelligence createThreatIntelligence(String indicator, String type, String threatName) {
        ThreatIntelligence ti = new ThreatIntelligence();
        ti.indicator = indicator;
        ti.indicatorType = type;
        ti.threatName = threatName;
        ti.threatFamily = "Family";
        ti.category = "MALWARE";
        ti.severity = "HIGH";
        ti.confidence = "HIGH";
        ti.description = "Description";
        ti.source = "TEST";
        ti.tags = "tags";
        ti.firstSeen = Instant.now();
        ti.lastSeen = Instant.now();
        ti.active = true;
        ti.createdAt = Instant.now();
        ti.updatedAt = Instant.now();
        return ti;
    }

    private ThreatMatch createMatch(IOC ioc, ThreatIntelligence ti, String matchType, String status) {
        ThreatMatch match = new ThreatMatch();
        match.ioc = ioc;
        match.threatIntelligence = ti;
        match.matchType = matchType;
        match.status = status;
        match.confidence = "HIGH";
        match.severity = "HIGH";
        match.description = "Test match";
        match.matchedAt = Instant.now();
        return match;
    }

    @Test
    void findByIocId_returnsMatchesForIoc() {
        ApkAnalysis analysis = createAnalysis("test1@example.com");
        IOC ioc = createIoc(analysis, "http://evil.com", "URL");
        ThreatIntelligence ti1 = createThreatIntelligence("http://evil.com", "URL", "Threat 1");
        ThreatIntelligence ti2 = createThreatIntelligence("http://evil.com", "URL", "Threat 2");
        entityManager.persistAndFlush(ioc);
        entityManager.persistAndFlush(ti1);
        entityManager.persistAndFlush(ti2);

        ThreatMatch match1 = createMatch(ioc, ti1, "EXACT", "MATCHED");
        ThreatMatch match2 = createMatch(ioc, ti2, "EXACT", "MATCHED");
        entityManager.persistAndFlush(match1);
        entityManager.persistAndFlush(match2);

        List<ThreatMatch> results = repository.findByIocId(ioc.id);

        assertThat(results).hasSize(2);
    }

    @Test
    void findByThreatIntelligenceId_returnsMatchesForThreatIntelligence() {
        ApkAnalysis analysis = createAnalysis("test2@example.com");
        IOC ioc1 = createIoc(analysis, "http://evil1.com", "URL");
        IOC ioc2 = createIoc(analysis, "http://evil2.com", "URL");
        ThreatIntelligence ti = createThreatIntelligence("http://evil.com", "URL", "Threat");
        entityManager.persistAndFlush(ioc1);
        entityManager.persistAndFlush(ioc2);
        entityManager.persistAndFlush(ti);

        ThreatMatch match1 = createMatch(ioc1, ti, "EXACT", "MATCHED");
        ThreatMatch match2 = createMatch(ioc2, ti, "EXACT", "MATCHED");
        entityManager.persistAndFlush(match1);
        entityManager.persistAndFlush(match2);

        List<ThreatMatch> results = repository.findByThreatIntelligenceId(ti.id);

        assertThat(results).hasSize(2);
    }

    @Test
    void findByStatus_returnsMatchesWithStatus() {
        ApkAnalysis analysis = createAnalysis("test3@example.com");
        IOC ioc = createIoc(analysis, "http://evil.com", "URL");
        ThreatIntelligence ti = createThreatIntelligence("http://evil.com", "URL", "Threat");
        entityManager.persistAndFlush(ioc);
        entityManager.persistAndFlush(ti);

        ThreatMatch matched = createMatch(ioc, ti, "EXACT", "MATCHED");
        ThreatMatch noMatch = createMatch(ioc, ti, "EXACT", "NO_MATCH");
        entityManager.persistAndFlush(matched);
        entityManager.persistAndFlush(noMatch);

        List<ThreatMatch> results = repository.findByStatus("MATCHED");

        assertThat(results).hasSize(1);
        assertThat(results.get(0).status).isEqualTo("MATCHED");
    }

    @Test
    void findMatchedByIocId_returnsOnlyMatchedStatus() {
        ApkAnalysis analysis = createAnalysis("test4@example.com");
        IOC ioc = createIoc(analysis, "http://evil.com", "URL");
        ThreatIntelligence ti = createThreatIntelligence("http://evil.com", "URL", "Threat");
        entityManager.persistAndFlush(ioc);
        entityManager.persistAndFlush(ti);

        ThreatMatch matched = createMatch(ioc, ti, "EXACT", "MATCHED");
        ThreatMatch noMatch = createMatch(ioc, ti, "EXACT", "NO_MATCH");
        entityManager.persistAndFlush(matched);
        entityManager.persistAndFlush(noMatch);

        List<ThreatMatch> results = repository.findMatchedByIocId(ioc.id);

        assertThat(results).hasSize(1);
        assertThat(results.get(0).status).isEqualTo("MATCHED");
    }

    @Test
    void findMatchedByThreatIntelligenceId_returnsOnlyMatchedStatus() {
        ApkAnalysis analysis = createAnalysis("test5@example.com");
        IOC ioc1 = createIoc(analysis, "http://evil1.com", "URL");
        IOC ioc2 = createIoc(analysis, "http://evil2.com", "URL");
        ThreatIntelligence ti = createThreatIntelligence("http://evil.com", "URL", "Threat");
        entityManager.persistAndFlush(ioc1);
        entityManager.persistAndFlush(ioc2);
        entityManager.persistAndFlush(ti);

        ThreatMatch matched = createMatch(ioc1, ti, "EXACT", "MATCHED");
        ThreatMatch noMatch = createMatch(ioc2, ti, "EXACT", "NO_MATCH");
        entityManager.persistAndFlush(matched);
        entityManager.persistAndFlush(noMatch);

        List<ThreatMatch> results = repository.findMatchedByThreatIntelligenceId(ti.id);

        assertThat(results).hasSize(1);
        assertThat(results.get(0).status).isEqualTo("MATCHED");
    }
}