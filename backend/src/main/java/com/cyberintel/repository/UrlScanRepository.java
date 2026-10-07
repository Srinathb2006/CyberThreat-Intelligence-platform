package com.cyberintel.repository;

import com.cyberintel.entity.UrlScan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.EntityGraph;
import java.util.List;
import java.util.Optional;

public interface UrlScanRepository extends JpaRepository<UrlScan, Long> {
    @EntityGraph(attributePaths = "scan")
    Optional<UrlScan> findByScanIdAndScanUserEmail(Long scanId, String email);
    @EntityGraph(attributePaths = "scan")
    List<UrlScan> findTop50ByScanUserEmailOrderByScanCreatedAtDescScanIdDesc(String email);
}
