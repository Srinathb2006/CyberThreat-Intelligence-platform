package com.cyberintel.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;

public final class UrlScanDtos {
    private UrlScanDtos() {}
    public record Request(@NotBlank @Size(max = 2048) String url) {}
    public record Finding(String code, String severity, String description, String evidence, int contribution) {}
    public record Analysis(String host, String domain, String ipAddress, boolean https, int port,
                           String path, boolean queryPresent, boolean fragmentPresent,
                           int score, String riskLevel, List<Finding> findings) {}
    public record Result(Long scanId, String url, String status, Instant createdAt, Analysis analysis) {}
}
