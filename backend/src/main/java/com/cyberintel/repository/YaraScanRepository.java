package com.cyberintel.repository;

import com.cyberintel.entity.YaraScan;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface YaraScanRepository extends JpaRepository<YaraScan,Long> {
 Optional<YaraScan> findByAnalysisId(Long analysisId);
}
