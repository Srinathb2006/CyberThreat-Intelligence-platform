package com.cyberintel.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;

public final class EndpointDtos {
    private EndpointDtos() {}
    public record RegisterRequest(
            @NotBlank @Size(max = 255) @Pattern(regexp = "[A-Za-z0-9][A-Za-z0-9._-]*", message = "Invalid hostname") String hostname,
            @NotBlank @Size(max = 255) String deviceName,
            @NotBlank @Size(max = 255) String operatingSystem,
            @NotBlank @Size(max = 50) String platform,
            @Size(max = 20) String status) {}
    public record RiskSummary(int score, String riskLevel, int totalEvents, int suspiciousEvents, int highOrCriticalEvents) {}
    public record Event(Long id, Long endpointId, String eventType, String severity, String title, String description,
                        String source, Instant observedAt, boolean suspicious, boolean demoData) {}
    public record Endpoint(Long id, String hostname, String deviceName, String operatingSystem, String platform,
                           String status, Instant lastSeenAt, boolean demoData, Instant createdAt, RiskSummary riskSummary) {}
    public record EndpointDetail(Endpoint endpoint, List<Event> events) {}
}
