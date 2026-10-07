package com.cyberintel.repository;
import com.cyberintel.entity.ApkAnalysis;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import jakarta.persistence.LockModeType;
import java.util.*;
public interface ApkAnalysisRepository extends JpaRepository<ApkAnalysis,Long>{
 Optional<ApkAnalysis> findByScanId(Long scanId);
 List<ApkAnalysis> findTop50ByScanUserEmailOrderByCreatedAtDesc(String email);
 @Lock(LockModeType.PESSIMISTIC_WRITE) @Query("select a from ApkAnalysis a where a.scan.id=:scanId")
 Optional<ApkAnalysis> lockByScanId(@Param("scanId") Long scanId);
 @Query("select a from ApkAnalysis a where a.scan.status in (com.cyberintel.entity.Scan.Status.QUEUED,com.cyberintel.entity.Scan.Status.RUNNING)")
 List<ApkAnalysis> findInterrupted();
 List<ApkAnalysis> findByCreatedAtBeforeAndArtifactsRetainedTrue(java.time.Instant cutoff);
}
