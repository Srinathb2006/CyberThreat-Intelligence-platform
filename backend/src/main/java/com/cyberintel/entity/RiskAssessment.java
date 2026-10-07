package com.cyberintel.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "risk_assessment")
public class RiskAssessment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "scan_id", nullable = false)
    private Long scanId;

    @Column(name = "apk_analysis_id", nullable = false)
    private Long apkAnalysisId;

    @Column(name = "score", nullable = false)
    private Double score;

    @Column(name = "risk_level", nullable = false, length = 20)
    private String riskLevel;

    @Column(name = "confidence", nullable = false, length = 20)
    private String confidence;

    @Column(name = "summary", length = 4000)
    private String summary;

    @Column(name = "is_latest", nullable = false)
    private Boolean isLatest = true;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @OneToMany(mappedBy = "riskAssessment", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<RiskIndicator> indicators = new ArrayList<>();

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getScanId() { return scanId; }
    public void setScanId(Long scanId) { this.scanId = scanId; }

    public Long getApkAnalysisId() { return apkAnalysisId; }
    public void setApkAnalysisId(Long apkAnalysisId) { this.apkAnalysisId = apkAnalysisId; }

    public Double getScore() { return score; }
    public void setScore(Double score) { this.score = score; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }

    public String getConfidence() { return confidence; }
    public void setConfidence(String confidence) { this.confidence = confidence; }

    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }

    public Boolean getIsLatest() { return isLatest; }
    public void setIsLatest(Boolean isLatest) { this.isLatest = isLatest; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }

    public List<RiskIndicator> getIndicators() { return indicators; }
    public void setIndicators(List<RiskIndicator> indicators) {
        this.indicators = indicators;
        if (indicators != null) {
            indicators.forEach(i -> i.setRiskAssessment(this));
        }
    }

    public void addIndicator(RiskIndicator indicator) {
        indicators.add(indicator);
        indicator.setRiskAssessment(this);
    }
}