package com.cyberintel.dto;

import java.time.Instant;
import java.util.List;

public final class ScanHistoryDtos {
    private ScanHistoryDtos() {}

    public record ScanHistoryItemDto(
            Long id,
            String scanType,
            String target,
            String fileName,
            Long fileSize,
            String packageName,
            String applicationName,
            String sha256,
            String status,
            Integer riskScore,
            String riskLevel,
            long findingsCount,
            long iocCount,
            long threatMatchCount,
            long alertCount,
            Instant createdAt,
            Instant completedAt
    ) {}

    public record DashboardStatsDto(
            long totalScans,
            long highCriticalRisks,
            long newAlerts,
            long threatMatches,
            long totalIocs,
            double avgRiskScore,
            List<ScanHistoryItemDto> recentScans,
            List<AlertDtos.AlertDto> recentAlerts
    ) {}
}
