package com.cyberintel.service;

import com.cyberintel.dto.EndpointDtos;
import com.cyberintel.entity.Endpoint;
import com.cyberintel.entity.EndpointSecurityEvent;
import com.cyberintel.entity.User;
import com.cyberintel.exception.ApiException;
import com.cyberintel.repository.EndpointRepository;
import com.cyberintel.repository.EndpointSecurityEventRepository;
import com.cyberintel.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Locale;

/** Inventory records plus deterministic demo events; it collects no endpoint telemetry. */
@Service
@Transactional
public class EndpointMonitoringService {
    private final EndpointRepository endpoints;
    private final EndpointSecurityEventRepository events;
    private final UserRepository users;
    public EndpointMonitoringService(EndpointRepository endpoints, EndpointSecurityEventRepository events, UserRepository users) {
        this.endpoints = endpoints; this.events = events; this.users = users;
    }

    public EndpointDtos.Endpoint register(EndpointDtos.RegisterRequest request, String email) {
        User user = users.findByEmail(email).orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Authentication required."));
        String hostname = request.hostname().trim().toLowerCase(Locale.ROOT);
        if (endpoints.existsByUserEmailAndHostname(email, hostname)) {
            throw new ApiException(HttpStatus.CONFLICT, "An endpoint with this hostname is already registered.");
        }
        Endpoint.Status status = status(request.status());
        Endpoint endpoint = endpoints.save(new Endpoint(user, hostname, request.deviceName().trim(), request.operatingSystem().trim(), request.platform().trim(), status));
        seedDemoEvents(endpoint);
        return toEndpoint(endpoint, events.findByEndpointIdOrderByObservedAtDesc(endpoint.getId()));
    }

    @Transactional(readOnly = true)
    public List<EndpointDtos.Endpoint> list(String email) {
        return endpoints.findByUserEmailOrderByLastSeenAtDesc(email).stream()
                .map(endpoint -> toEndpoint(endpoint, events.findByEndpointIdOrderByObservedAtDesc(endpoint.getId()))).toList();
    }

    @Transactional(readOnly = true)
    public EndpointDtos.EndpointDetail detail(Long id, String email, boolean suspiciousOnly) {
        Endpoint endpoint = owned(id, email);
        List<EndpointSecurityEvent> found = suspiciousOnly
                ? events.findByEndpointIdAndSuspiciousTrueOrderByObservedAtDesc(id)
                : events.findByEndpointIdOrderByObservedAtDesc(id);
        List<EndpointSecurityEvent> all = suspiciousOnly ? events.findByEndpointIdOrderByObservedAtDesc(id) : found;
        return new EndpointDtos.EndpointDetail(toEndpoint(endpoint, all), found.stream().map(this::toEvent).toList());
    }

    @Transactional(readOnly = true)
    public List<EndpointDtos.Event> eventList(Long id, String email, boolean suspiciousOnly) {
        owned(id, email);
        List<EndpointSecurityEvent> found = suspiciousOnly
                ? events.findByEndpointIdAndSuspiciousTrueOrderByObservedAtDesc(id)
                : events.findByEndpointIdOrderByObservedAtDesc(id);
        return found.stream().map(this::toEvent).toList();
    }

    private Endpoint owned(Long id, String email) {
        return endpoints.findByIdAndUserEmail(id, email).orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Endpoint not found."));
    }
    private Endpoint.Status status(String value) {
        if (value == null || value.isBlank()) return Endpoint.Status.UNKNOWN;
        try { return Endpoint.Status.valueOf(value.trim().toUpperCase(Locale.ROOT)); }
        catch (IllegalArgumentException e) { throw new ApiException(HttpStatus.BAD_REQUEST, "Status must be ONLINE, OFFLINE, or UNKNOWN."); }
    }
    private void seedDemoEvents(Endpoint endpoint) {
        Instant now = Instant.now();
        List<EndpointSecurityEvent> demo = List.of(
                new EndpointSecurityEvent(endpoint, "SYSTEM_START", EndpointSecurityEvent.Severity.LOW,
                        "Demo endpoint registered", "Deterministic demonstration event created at registration. No device telemetry was collected.", "Endpoint Monitoring Demo", false, now.minusSeconds(300)),
                new EndpointSecurityEvent(endpoint, "AUTHENTICATION", EndpointSecurityEvent.Severity.MEDIUM,
                        "Repeated sign-in attempts", "Demo signal representing repeated failed sign-in attempts. It is not sourced from the registered device.", "Endpoint Monitoring Demo", true, now.minusSeconds(180)),
                new EndpointSecurityEvent(endpoint, "PROCESS_ACTIVITY", EndpointSecurityEvent.Severity.HIGH,
                        "Unusual process ancestry", "Demo signal representing an unusual parent-child process relationship. No process was observed or executed.", "Endpoint Monitoring Demo", true, now.minusSeconds(60)));
        events.saveAll(demo);
    }
    private EndpointDtos.Endpoint toEndpoint(Endpoint endpoint, List<EndpointSecurityEvent> events) {
        return new EndpointDtos.Endpoint(endpoint.getId(), endpoint.getHostname(), endpoint.getDeviceName(), endpoint.getOperatingSystem(),
                endpoint.getPlatform(), endpoint.getStatus().name(), endpoint.getLastSeenAt(), endpoint.isDemoData(), endpoint.getCreatedAt(), risk(events));
    }
    private EndpointDtos.Event toEvent(EndpointSecurityEvent event) {
        return new EndpointDtos.Event(event.getId(), event.getEndpoint().getId(), event.getEventType(), event.getSeverity().name(), event.getTitle(),
                event.getDescription(), event.getSource(), event.getObservedAt(), event.isSuspicious(), event.isDemoData());
    }
    private EndpointDtos.RiskSummary risk(List<EndpointSecurityEvent> eventList) {
        int suspicious = (int) eventList.stream().filter(EndpointSecurityEvent::isSuspicious).count();
        int high = (int) eventList.stream().filter(e -> e.getSeverity() == EndpointSecurityEvent.Severity.HIGH || e.getSeverity() == EndpointSecurityEvent.Severity.CRITICAL).count();
        int score = Math.min(100, eventList.stream().filter(EndpointSecurityEvent::isSuspicious).mapToInt(e -> switch (e.getSeverity()) {
            case LOW -> 5; case MEDIUM -> 15; case HIGH -> 30; case CRITICAL -> 50;
        }).sum());
        String level = score > 75 ? "CRITICAL" : score > 50 ? "HIGH" : score > 25 ? "MEDIUM" : "LOW";
        return new EndpointDtos.RiskSummary(score, level, eventList.size(), suspicious, high);
    }
}
