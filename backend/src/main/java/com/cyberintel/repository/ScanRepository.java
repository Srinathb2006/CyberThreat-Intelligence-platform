package com.cyberintel.repository;

import com.cyberintel.entity.Scan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ScanRepository extends JpaRepository<Scan, Long> {

    List<Scan> findAllByOrderByCreatedAtDesc();

    List<Scan> findTop10ByOrderByCreatedAtDesc();

    @Query("SELECT s FROM Scan s WHERE " +
            "(:status IS NULL OR s.status = :status) AND " +
            "(:riskLevel IS NULL OR s.riskLevel = :riskLevel) AND " +
            "(:search IS NULL OR LOWER(s.target) LIKE LOWER(CONCAT('%', :search, '%'))) " +
            "ORDER BY s.createdAt DESC")
    List<Scan> findFiltered(
            @Param("status") Scan.Status status,
            @Param("riskLevel") Scan.RiskLevel riskLevel,
            @Param("search") String search
    );

    long countByRiskLevel(Scan.RiskLevel riskLevel);

    long countByStatus(Scan.Status status);

    @Query("SELECT COUNT(s) FROM Scan s WHERE s.riskLevel IN (com.cyberintel.entity.Scan.RiskLevel.HIGH, com.cyberintel.entity.Scan.RiskLevel.CRITICAL)")
    long countHighAndCriticalRisks();

    @Query("SELECT AVG(s.riskScore) FROM Scan s WHERE s.riskScore IS NOT NULL")
    Double getAverageRiskScore();
}
