package com.cyberintel.repository;

import com.cyberintel.entity.RiskIndicator;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;

public interface RiskIndicatorRepository extends JpaRepository<RiskIndicator, Long> {
    List<RiskIndicator> findByRiskAssessmentId(Long riskAssessmentId);

    @Query("SELECT ri FROM RiskIndicator ri WHERE ri.riskAssessment.id = :assessmentId ORDER BY ri.contribution DESC")
    List<RiskIndicator> findByRiskAssessmentIdOrderByContributionDesc(@Param("assessmentId") Long assessmentId);

    @Query("SELECT ri FROM RiskIndicator ri WHERE ri.category = :category AND ri.riskAssessment.id = :assessmentId")
    List<RiskIndicator> findByCategoryAndAssessmentId(@Param("category") String category, @Param("assessmentId") Long assessmentId);

    @Query("SELECT ri FROM RiskIndicator ri WHERE ri.sourceType = :sourceType AND ri.riskAssessment.id = :assessmentId")
    List<RiskIndicator> findBySourceTypeAndAssessmentId(@Param("sourceType") String sourceType, @Param("assessmentId") Long assessmentId);
}