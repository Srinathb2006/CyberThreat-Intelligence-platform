package com.cyberintel.repository;

import com.cyberintel.entity.ThreatMatch;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;

public interface ThreatMatchRepository extends JpaRepository<ThreatMatch, Long> {
    List<ThreatMatch> findByIocId(Long iocId);
    List<ThreatMatch> findByThreatIntelligenceId(Long threatIntelligenceId);
    List<ThreatMatch> findByStatus(String status);

    @Query("select tm from ThreatMatch tm where tm.ioc.id = :iocId and tm.status = 'MATCHED'")
    List<ThreatMatch> findMatchedByIocId(@Param("iocId") Long iocId);

    @Query("select tm from ThreatMatch tm where tm.threatIntelligence.id = :tiId and tm.status = 'MATCHED'")
    List<ThreatMatch> findMatchedByThreatIntelligenceId(@Param("tiId") Long tiId);

    @Modifying
    @Query("delete from ThreatMatch tm where tm.ioc.id = :iocId")
    void deleteByIocId(@Param("iocId") Long iocId);
}