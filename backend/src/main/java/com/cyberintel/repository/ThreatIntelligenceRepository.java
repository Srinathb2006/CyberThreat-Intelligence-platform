package com.cyberintel.repository;

import com.cyberintel.entity.ThreatIntelligence;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;

public interface ThreatIntelligenceRepository extends JpaRepository<ThreatIntelligence, Long> {
 List<ThreatIntelligence> findByIndicator(String indicator);
 List<ThreatIntelligence> findByIndicatorType(String indicatorType);
 List<ThreatIntelligence> findByActiveTrue();
 List<ThreatIntelligence> findByCategory(String category);
 List<ThreatIntelligence> findBySeverity(String severity);
 List<ThreatIntelligence> findBySource(String source);

 @Query("select t from ThreatIntelligence t where t.indicator = :indicator and t.indicatorType = :type and t.active = true")
 List<ThreatIntelligence> findByIndicatorAndType(@Param("indicator") String indicator, @Param("type") String type);

 @Query("select t from ThreatIntelligence t where t.indicator = :indicator and t.active = true")
 List<ThreatIntelligence> findByIndicatorExact(@Param("indicator") String indicator);
}