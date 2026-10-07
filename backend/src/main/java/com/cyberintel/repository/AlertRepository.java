package com.cyberintel.repository;

import com.cyberintel.entity.Alert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface AlertRepository extends JpaRepository<Alert, Long> {

    List<Alert> findByScanIdOrderByCreatedAtDesc(Long scanId);

    List<Alert> findByStatusOrderByCreatedAtDesc(Alert.Status status);

    List<Alert> findBySeverityOrderByCreatedAtDesc(Alert.Severity severity);

    List<Alert> findAllByOrderByCreatedAtDesc();

    long countByStatus(Alert.Status status);

    long countBySeverity(Alert.Severity severity);

    boolean existsByScanIdAndTitle(Long scanId, String title);

    @Query("SELECT a FROM Alert a WHERE " +
            "(:status IS NULL OR a.status = :status) AND " +
            "(:severity IS NULL OR a.severity = :severity) AND " +
            "(:search IS NULL OR LOWER(a.title) LIKE LOWER(CONCAT('%', :search, '%')) OR LOWER(a.description) LIKE LOWER(CONCAT('%', :search, '%')) OR LOWER(a.source) LIKE LOWER(CONCAT('%', :search, '%'))) " +
            "ORDER BY a.createdAt DESC")
    List<Alert> findFiltered(
            @Param("status") Alert.Status status,
            @Param("severity") Alert.Severity severity,
            @Param("search") String search
    );

    List<Alert> findTop10ByOrderByCreatedAtDesc();
}
