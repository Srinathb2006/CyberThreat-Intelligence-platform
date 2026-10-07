package com.cyberintel.dto;

import java.time.Instant;
import java.util.List;

public final class IocExplorerDtos {
    private IocExplorerDtos() {}

    public record ThreatMatch(Long id, String status, String matchType, String severity, String confidence,
                              String description, Instant matchedAt, Long threatIntelligenceId,
                              String threatName, String threatFamily, String threatCategory,
                              String threatIndicator, String threatSource) {}

    public record Ioc(Long id, Long scanId, String scanTarget, String value, String type, String source,
                      String severity, String confidence, String description, Instant firstSeen,
                      Instant lastSeen, Instant createdAt, List<ThreatMatch> threatMatches) {}
}
