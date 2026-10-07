package com.cyberintel.repository;

import com.cyberintel.entity.ThreatIntelligenceSource;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface ThreatIntelligenceSourceRepository extends JpaRepository<ThreatIntelligenceSource, Long> {
 List<ThreatIntelligenceSource> findByEnabledTrue();
 List<ThreatIntelligenceSource> findBySourceType(String sourceType);
}