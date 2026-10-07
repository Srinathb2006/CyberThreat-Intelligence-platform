package com.cyberintel.repository;

import com.cyberintel.entity.ThreatIntelligence;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@ActiveProfiles("test")
class ThreatIntelligenceRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private ThreatIntelligenceRepository repository;

    @Test
    void findByIndicator_returnsMatchingRecords() {
        ThreatIntelligence ti1 = createThreatIntelligence("http://evil.com", "URL", "Threat 1");
        ThreatIntelligence ti2 = createThreatIntelligence("http://evil.com", "DOMAIN", "Threat 2");
        entityManager.persistAndFlush(ti1);
        entityManager.persistAndFlush(ti2);

        List<ThreatIntelligence> results = repository.findByIndicator("http://evil.com");

        assertThat(results).hasSize(2);
    }

    @Test
    void findByIndicatorType_returnsMatchingRecords() {
        ThreatIntelligence ti1 = createThreatIntelligence("http://evil.com", "URL", "Threat 1");
        ThreatIntelligence ti2 = createThreatIntelligence("192.0.2.1", "IP", "Threat 2");
        entityManager.persistAndFlush(ti1);
        entityManager.persistAndFlush(ti2);

        List<ThreatIntelligence> results = repository.findByIndicatorType("URL");

        assertThat(results).hasSize(1);
        assertThat(results.get(0).indicatorType).isEqualTo("URL");
    }

    @Test
    void findByActiveTrue_returnsOnlyActiveRecords() {
        ThreatIntelligence active = createThreatIntelligence("http://active.com", "URL", "Active");
        active.active = true;
        ThreatIntelligence inactive = createThreatIntelligence("http://inactive.com", "URL", "Inactive");
        inactive.active = false;
        entityManager.persistAndFlush(active);
        entityManager.persistAndFlush(inactive);

        List<ThreatIntelligence> results = repository.findByActiveTrue();

        assertThat(results).hasSize(1);
        assertThat(results.get(0).indicator).isEqualTo("http://active.com");
    }

    @Test
    void findByCategory_returnsMatchingRecords() {
        ThreatIntelligence ti1 = createThreatIntelligence("http://malware.com", "URL", "Malware");
        ti1.category = "MALWARE";
        ThreatIntelligence ti2 = createThreatIntelligence("http://phish.com", "URL", "Phishing");
        ti2.category = "PHISHING";
        entityManager.persistAndFlush(ti1);
        entityManager.persistAndFlush(ti2);

        List<ThreatIntelligence> results = repository.findByCategory("MALWARE");

        assertThat(results).hasSize(1);
        assertThat(results.get(0).category).isEqualTo("MALWARE");
    }

    @Test
    void findBySeverity_returnsMatchingRecords() {
        ThreatIntelligence ti1 = createThreatIntelligence("http://critical.com", "URL", "Critical");
        ti1.severity = "CRITICAL";
        ThreatIntelligence ti2 = createThreatIntelligence("http://high.com", "URL", "High");
        ti2.severity = "HIGH";
        entityManager.persistAndFlush(ti1);
        entityManager.persistAndFlush(ti2);

        List<ThreatIntelligence> results = repository.findBySeverity("CRITICAL");

        assertThat(results).hasSize(1);
        assertThat(results.get(0).severity).isEqualTo("CRITICAL");
    }

    @Test
    void findBySource_returnsMatchingRecords() {
        ThreatIntelligence ti1 = createThreatIntelligence("http://source1.com", "URL", "Source 1");
        ti1.source = "SOURCE_A";
        ThreatIntelligence ti2 = createThreatIntelligence("http://source2.com", "URL", "Source 2");
        ti2.source = "SOURCE_B";
        entityManager.persistAndFlush(ti1);
        entityManager.persistAndFlush(ti2);

        List<ThreatIntelligence> results = repository.findBySource("SOURCE_A");

        assertThat(results).hasSize(1);
        assertThat(results.get(0).source).isEqualTo("SOURCE_A");
    }

    @Test
    void findByIndicatorAndType_returnsExactMatch() {
        ThreatIntelligence ti1 = createThreatIntelligence("http://evil.com", "URL", "Threat 1");
        ThreatIntelligence ti2 = createThreatIntelligence("http://evil.com", "DOMAIN", "Threat 2");
        entityManager.persistAndFlush(ti1);
        entityManager.persistAndFlush(ti2);

        List<ThreatIntelligence> results = repository.findByIndicatorAndType("http://evil.com", "URL");

        assertThat(results).hasSize(1);
        assertThat(results.get(0).indicatorType).isEqualTo("URL");
    }

    @Test
    void findByIndicatorExact_returnsMatchingRecords() {
        ThreatIntelligence ti1 = createThreatIntelligence("http://evil.com", "URL", "Threat 1");
        ti1.active = true;
        ThreatIntelligence ti2 = createThreatIntelligence("http://evil.com", "DOMAIN", "Threat 2");
        ti2.active = false;
        entityManager.persistAndFlush(ti1);
        entityManager.persistAndFlush(ti2);

        List<ThreatIntelligence> results = repository.findByIndicatorExact("http://evil.com");

        assertThat(results).hasSize(1);
        assertThat(results.get(0).active).isTrue();
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
}