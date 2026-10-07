package com.cyberintel.service;

import com.cyberintel.dto.AlertDtos.*;
import com.cyberintel.entity.Alert;
import com.cyberintel.entity.ApkAnalysis;
import com.cyberintel.entity.RiskAssessment;
import com.cyberintel.entity.RiskIndicator;
import com.cyberintel.entity.Scan;
import com.cyberintel.repository.AlertRepository;
import com.cyberintel.repository.ApkAnalysisRepository;
import com.cyberintel.repository.RiskAssessmentRepository;
import com.cyberintel.repository.RiskIndicatorRepository;
import com.cyberintel.repository.ScanRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

@Service
@Transactional
public class AlertService {

    private final AlertRepository alertRepository;
    private final ScanRepository scanRepository;
    private final RiskAssessmentRepository riskAssessmentRepository;
    private final RiskIndicatorRepository riskIndicatorRepository;
    private final ApkAnalysisRepository apkAnalysisRepository;

    public AlertService(
            AlertRepository alertRepository,
            ScanRepository scanRepository,
            RiskAssessmentRepository riskAssessmentRepository,
            RiskIndicatorRepository riskIndicatorRepository,
            ApkAnalysisRepository apkAnalysisRepository) {
        this.alertRepository = alertRepository;
        this.scanRepository = scanRepository;
        this.riskAssessmentRepository = riskAssessmentRepository;
        this.riskIndicatorRepository = riskIndicatorRepository;
        this.apkAnalysisRepository = apkAnalysisRepository;
    }

    public List<Alert> generateAlertsFromAssessment(Long scanId) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new IllegalArgumentException("Scan not found with id: " + scanId));

        RiskAssessment assessment = riskAssessmentRepository.findByScanIdAndIsLatestTrue(scanId)
                .orElse(null);

        if (assessment == null) {
            return List.of();
        }

        ApkAnalysis analysis = apkAnalysisRepository.findByScanId(scanId).orElse(null);
        String appName = (analysis != null && analysis.applicationName != null) ? analysis.applicationName : scan.getTarget();

        List<RiskIndicator> indicators = riskIndicatorRepository.findByRiskAssessmentId(assessment.getId());
        List<Alert> createdAlerts = new ArrayList<>();

        // 1. Alert for Overall Critical or High Risk Level
        if ("CRITICAL".equalsIgnoreCase(assessment.getRiskLevel()) || "HIGH".equalsIgnoreCase(assessment.getRiskLevel())) {
            String title = assessment.getRiskLevel() + " Risk Assessment: " + appName;
            if (!alertRepository.existsByScanIdAndTitle(scanId, title)) {
                Alert.Severity severity = "CRITICAL".equalsIgnoreCase(assessment.getRiskLevel())
                        ? Alert.Severity.CRITICAL : Alert.Severity.HIGH;
                Alert alert = new Alert(
                        title,
                        assessment.getSummary() != null ? assessment.getSummary() : "High risk detected with score " + assessment.getScore(),
                        severity,
                        "Risk Correlation Engine",
                        "RISK_ASSESSMENT",
                        scan
                );
                createdAlerts.add(alertRepository.save(alert));
            }
        }

        // 2. Alert for Threat Intelligence Matches
        boolean hasThreatIntel = indicators.stream().anyMatch(i -> "THREAT_INTELLIGENCE".equalsIgnoreCase(i.getCategory()));
        if (hasThreatIntel) {
            String title = "Threat Intelligence Correlation: " + appName;
            if (!alertRepository.existsByScanIdAndTitle(scanId, title)) {
                Alert alert = new Alert(
                        title,
                        "APK indicators matched known threat intelligence feeds and signatures.",
                        Alert.Severity.CRITICAL,
                        "Threat Intelligence Engine",
                        "THREAT_INTELLIGENCE",
                        scan
                );
                createdAlerts.add(alertRepository.save(alert));
            }
        }

        // 3. Alerts for Specific High-Risk Indicator Categories
        for (RiskIndicator indicator : indicators) {
            if ("CRITICAL".equalsIgnoreCase(indicator.getSeverity()) || "HIGH".equalsIgnoreCase(indicator.getSeverity())) {
                String cat = indicator.getCategory();
                String title = formatIndicatorAlertTitle(cat, appName);
                if (title != null && !alertRepository.existsByScanIdAndTitle(scanId, title)) {
                    Alert.Severity severity = "CRITICAL".equalsIgnoreCase(indicator.getSeverity())
                            ? Alert.Severity.CRITICAL : Alert.Severity.HIGH;
                    Alert alert = new Alert(
                            title,
                            indicator.getDescription() != null ? indicator.getDescription() : "High severity indicator detected in " + cat,
                            severity,
                            indicator.getSourceType() != null ? indicator.getSourceType() : "Static Analysis",
                            cat,
                            scan
                    );
                    createdAlerts.add(alertRepository.save(alert));
                }
            }
        }

        return createdAlerts;
    }

    private String formatIndicatorAlertTitle(String category, String appName) {
        if (category == null) return null;
        return switch (category.toUpperCase()) {
            case "MALWARE_FINDING" -> "Malware Signature Detected: " + appName;
            case "DYNAMIC_CODE_LOADING" -> "Dynamic Code Loading Detected: " + appName;
            case "SMS_ABUSE" -> "Potential SMS Abuse / Toll Fraud: " + appName;
            case "DATA_EXFILTRATION" -> "Data Exfiltration Signal: " + appName;
            case "RANSOMWARE" -> "Ransomware Behavior Detected: " + appName;
            case "PRIVILEGE_ESCALATION" -> "Privilege Escalation Signal: " + appName;
            default -> null;
        };
    }

    @Transactional(readOnly = true)
    public List<AlertDto> getAlerts(String statusStr, String severityStr, String search) {
        Alert.Status status = parseStatus(statusStr);
        Alert.Severity severity = parseSeverity(severityStr);

        List<Alert> alerts = alertRepository.findFiltered(status, severity, search == null ? "" : search);
        return alerts.stream().map(this::toDto).toList();
    }

    @Transactional(readOnly = true)
    public AlertDto getAlertById(Long id) {
        Alert alert = alertRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Alert not found with id: " + id));
        return toDto(alert);
    }

    public AlertDto updateAlertStatus(Long id, UpdateAlertStatusRequest request) {
        Alert alert = alertRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Alert not found with id: " + id));

        Alert.Status newStatus = parseStatus(request.status());
        if (newStatus != null) {
            alert.setStatus(newStatus);
            if (newStatus == Alert.Status.RESOLVED) {
                alert.setResolvedAt(Instant.now());
            }
        }
        if (request.notes() != null) {
            alert.setNotes(request.notes());
        }
        alert.setUpdatedAt(Instant.now());
        return toDto(alertRepository.save(alert));
    }

    public AlertDto resolveAlert(Long id, ResolveAlertRequest request) {
        Alert alert = alertRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Alert not found with id: " + id));

        alert.setStatus(Alert.Status.RESOLVED);
        alert.setResolvedAt(Instant.now());
        if (request != null) {
            if (request.notes() != null) alert.setNotes(request.notes());
            if (request.resolvedBy() != null) alert.setResolvedBy(request.resolvedBy());
        }
        alert.setUpdatedAt(Instant.now());
        return toDto(alertRepository.save(alert));
    }

    @Transactional(readOnly = true)
    public AlertStatsDto getAlertStats() {
        long total = alertRepository.count();
        long newCount = alertRepository.countByStatus(Alert.Status.NEW) + alertRepository.countByStatus(Alert.Status.OPEN);
        long investigatingCount = alertRepository.countByStatus(Alert.Status.INVESTIGATING) + alertRepository.countByStatus(Alert.Status.ACKNOWLEDGED);
        long resolvedCount = alertRepository.countByStatus(Alert.Status.RESOLVED);

        long criticalCount = alertRepository.countBySeverity(Alert.Severity.CRITICAL);
        long highCount = alertRepository.countBySeverity(Alert.Severity.HIGH);
        long mediumCount = alertRepository.countBySeverity(Alert.Severity.MEDIUM);
        long lowCount = alertRepository.countBySeverity(Alert.Severity.LOW);

        return new AlertStatsDto(
                total, newCount, investigatingCount, resolvedCount,
                criticalCount, highCount, mediumCount, lowCount
        );
    }

    private Alert.Status parseStatus(String s) {
        if (s == null || s.isBlank() || "ALL".equalsIgnoreCase(s)) return null;
        try {
            return Alert.Status.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private Alert.Severity parseSeverity(String s) {
        if (s == null || s.isBlank() || "ALL".equalsIgnoreCase(s)) return null;
        try {
            return Alert.Severity.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public AlertDto toDto(Alert alert) {
        Long scanId = alert.getScan() != null ? alert.getScan().getId() : null;
        String scanTarget = alert.getScan() != null ? alert.getScan().getTarget() : null;
        return new AlertDto(
                alert.getId(),
                scanId,
                scanTarget,
                alert.getTitle(),
                alert.getDescription(),
                alert.getSeverity() != null ? alert.getSeverity().name() : null,
                alert.getStatus() != null ? alert.getStatus().name() : null,
                alert.getSource(),
                alert.getCategory(),
                alert.getNotes(),
                alert.getResolvedBy(),
                alert.getResolvedAt(),
                alert.getCreatedAt(),
                alert.getUpdatedAt()
        );
    }
}
