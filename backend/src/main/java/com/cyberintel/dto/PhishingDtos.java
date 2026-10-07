package com.cyberintel.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.List;

public final class PhishingDtos {
    private PhishingDtos() {}
    public record Request(@NotBlank @Size(max = 2048) String url) {}
    public record Reason(String code, String severity, String description, String evidence, int contribution) {}
    public record RedirectIndicator(String parameter, String destination, String host, boolean crossHost,
                                    Boolean https, String status) {}
    public record Result(String url, String host, boolean https, boolean ipBased, int score,
                         String riskLevel, List<Reason> reasons, List<RedirectIndicator> redirectIndicators) {}
}
