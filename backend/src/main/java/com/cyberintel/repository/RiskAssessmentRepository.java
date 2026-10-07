package com.cyberintel.repository;

import com.cyberintel.entity.RiskAssessment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.util.Optional;

public interface RiskAssessmentRepository extends JpaRepository<RiskAssessment, Long> {
    List<RiskAssessment> findByScanIdOrderByCreatedAtDesc(Long scanId);

    Optional<RiskAssessment> findByScanIdAndIsLatestTrue(Long scanId);

    Optional<RiskAssessment> findTopByScanIdOrderByCreatedAtDesc(Long scanId);

    @Query("SELECT ra FROM RiskAssessment ra WHERE ra.apkAnalysisId = :analysisId ORDER BY ra.createdAt DESC")
    List<RiskAssessment> findByApkAnalysisIdOrderByCreatedAtDesc(@Param("analysisId") Long analysisId);

    @Query("SELECT ra FROM RiskAssessment ra WHERE ra.riskLevel = :level")
    List<RiskAssessment> findByRiskLevel(@Param("level") String level);

    @Query("SELECT COUNT(ra) FROM RiskAssessment ra WHERE ra.riskLevel = :level AND ra.isLatest = true")
    Long countByRiskLevelAndLatest(@Param("level") String level);
}