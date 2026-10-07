package com.cyberintel.repository;

import com.cyberintel.entity.ThreatIntelligenceSource;
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
class ThreatIntelligenceSourceRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private ThreatIntelligenceSourceRepository repository;

    @Test
    void findByEnabledTrue_returnsOnlyEnabledSources() {
        ThreatIntelligenceSource enabled = createSource("Enabled Source", "LOCAL", true);
        ThreatIntelligenceSource disabled = createSource("Disabled Source", "LOCAL", false);
        entityManager.persistAndFlush(enabled);
        entityManager.persistAndFlush(disabled);

        List<ThreatIntelligenceSource> results = repository.findByEnabledTrue();

        assertThat(results).hasSize(1);
        assertThat(results.get(0).name).isEqualTo("Enabled Source");
        assertThat(results.get(0).enabled).isTrue();
    }

    @Test
    void findBySourceType_returnsMatchingSources() {
        ThreatIntelligenceSource local = createSource("Local Source", "LOCAL", true);
        ThreatIntelligenceSource imported = createSource("Imported Source", "IMPORTED", true);
        entityManager.persistAndFlush(local);
        entityManager.persistAndFlush(imported);

        List<ThreatIntelligenceSource> results = repository.findBySourceType("LOCAL");

        assertThat(results).hasSize(1);
        assertThat(results.get(0).sourceType).isEqualTo("LOCAL");
    }

    private ThreatIntelligenceSource createSource(String name, String sourceType, boolean enabled) {
        ThreatIntelligenceSource source = new ThreatIntelligenceSource();
        source.name = name;
        source.description = "Description";
        source.sourceType = sourceType;
        source.url = "http://source.com";
        source.enabled = enabled;
        source.createdAt = Instant.now();
        return source;
    }
}