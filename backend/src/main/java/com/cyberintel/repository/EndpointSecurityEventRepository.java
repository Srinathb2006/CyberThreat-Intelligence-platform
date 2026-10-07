package com.cyberintel.repository;

import com.cyberintel.entity.EndpointSecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface EndpointSecurityEventRepository extends JpaRepository<EndpointSecurityEvent, Long> {
    List<EndpointSecurityEvent> findByEndpointIdOrderByObservedAtDesc(Long endpointId);
    List<EndpointSecurityEvent> findByEndpointIdAndSuspiciousTrueOrderByObservedAtDesc(Long endpointId);
}
