package com.cyberintel.dto;

import java.time.Instant;
import java.util.List;

public final class AlertDtos {
    private AlertDtos() {}

    public record AlertDto(
            Long id,
            Long scanId,
            String scanTarget,
            String title,
            String description,
            String severity,
            String status,
            String source,
            String category,
            String notes,
            String resolvedBy,
            Instant resolvedAt,
            Instant createdAt,
            Instant updatedAt
    ) {}

    public record UpdateAlertStatusRequest(
            String status,
            String notes
    ) {}

    public record ResolveAlertRequest(
            String notes,
            String resolvedBy
    ) {}

    public record AlertStatsDto(
            long total,
            long newCount,
            long investigatingCount,
            long resolvedCount,
            long criticalCount,
            long highCount,
            long mediumCount,
            long lowCount
    ) {}
}
