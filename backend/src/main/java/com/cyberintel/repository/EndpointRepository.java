package com.cyberintel.repository;

import com.cyberintel.entity.Endpoint;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface EndpointRepository extends JpaRepository<Endpoint, Long> {
    List<Endpoint> findByUserEmailOrderByLastSeenAtDesc(String email);
    Optional<Endpoint> findByIdAndUserEmail(Long id, String email);
    boolean existsByUserEmailAndHostname(String email, String hostname);
}
