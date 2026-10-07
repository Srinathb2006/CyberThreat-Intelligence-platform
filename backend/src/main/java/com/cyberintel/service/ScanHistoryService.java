package com.cyberintel.service;

import com.cyberintel.dto.AlertDtos;
import com.cyberintel.dto.ScanHistoryDtos.*;
import com.cyberintel.entity.*;
import com.cyberintel.repository.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

@Service
@Transactional(readOnly = true)
public class ScanHistoryService {

    private final ScanRepository scanRepository;
    private final ApkAnalysisRepository apkAnalysisRepository;
    private final MalwareFindingRepository malwareFindingRepository;
    private final IocRepository iocRepository;
    private final ThreatMatchRepository threatMatchRepository;
    private final AlertRepository alertRepository;
    private final AlertService alertService;

    public ScanHistoryService(
            ScanRepository scanRepository,
            ApkAnalysisRepository apkAnalysisRepository,
            MalwareFindingRepository malwareFindingRepository,
            IocRepository iocRepository,
            ThreatMatchRepository threatMatchRepository,
            AlertRepository alertRepository,
            AlertService alertService) {
        this.scanRepository = scanRepository;
        this.apkAnalysisRepository = apkAnalysisRepository;
        this.malwareFindingRepository = malwareFindingRepository;
        this.iocRepository = iocRepository;
        this.threatMatchRepository = threatMatchRepository;
        this.alertRepository = alertRepository;
        this.alertService = alertService;
    }

    public List<ScanHistoryItemDto> getScanHistory(String search, String packageName, String statusStr, String riskLevelStr) {
        Scan.Status status = parseStatus(statusStr);
        Scan.RiskLevel riskLevel = parseRiskLevel(riskLevelStr);

        List<Scan> scans = scanRepository.findFiltered(status, riskLevel, search);
        List<ScanHistoryItemDto> items = new ArrayList<>();

        for (Scan scan : scans) {
            Optional<ApkAnalysis> analysisOpt = apkAnalysisRepository.findByScanId(scan.getId());

            // Filter by packageName if provided
            if (packageName != null && !packageName.isBlank()) {
                if (analysisOpt.isEmpty() || analysisOpt.get().packageName == null
                        || !analysisOpt.get().packageName.toLowerCase().contains(packageName.toLowerCase())) {
                    continue;
                }
            }

            items.add(toScanHistoryItem(scan, analysisOpt.orElse(null)));
        }

        return items;
    }

    public ScanHistoryItemDto getScanHistoryById(Long scanId) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new NoSuchElementException("Scan not found with id: " + scanId));
        ApkAnalysis analysis = apkAnalysisRepository.findByScanId(scanId).orElse(null);
        return toScanHistoryItem(scan, analysis);
    }

    public DashboardStatsDto getDashboardStats() {
        long totalScans = scanRepository.count();
        long highCriticalRisks = scanRepository.countHighAndCriticalRisks();
        long newAlerts = alertRepository.countByStatus(Alert.Status.NEW) + alertRepository.countByStatus(Alert.Status.OPEN);
        long threatMatches = threatMatchRepository.count();
        long totalIocs = iocRepository.count();

        Double avgScore = scanRepository.getAverageRiskScore();
        double avgRiskScore = avgScore != null ? Math.round(avgScore * 10.0) / 10.0 : 0.0;

        List<Scan> recentScans = scanRepository.findTop10ByOrderByCreatedAtDesc();
        List<ScanHistoryItemDto> recentScanDtos = recentScans.stream()
                .map(s -> toScanHistoryItem(s, apkAnalysisRepository.findByScanId(s.getId()).orElse(null)))
                .toList();

        List<Alert> recentAlerts = alertRepository.findTop10ByOrderByCreatedAtDesc();
        List<AlertDtos.AlertDto> recentAlertDtos = recentAlerts.stream()
                .map(alertService::toDto)
                .toList();

        return new DashboardStatsDto(
                totalScans,
                highCriticalRisks,
                newAlerts,
                threatMatches,
                totalIocs,
                avgRiskScore,
                recentScanDtos,
                recentAlertDtos
        );
    }

    public ScanHistoryItemDto toScanHistoryItem(Scan scan, ApkAnalysis analysis) {
        long findingsCount = 0;
        long iocCount = 0;
        long threatMatchCount = 0;
        long alertCount = alertRepository.findByScanIdOrderByCreatedAtDesc(scan.getId()).size();

        String fileName = scan.getTarget();
        Long fileSize = null;
        String packageName = null;
        String applicationName = null;
        String sha256 = null;

        if (analysis != null) {
            findingsCount = malwareFindingRepository.countByApkAnalysisId(analysis.id);
            iocCount = iocRepository.countByApkAnalysisId(analysis.id);

            List<IOC> iocs = iocRepository.findByApkAnalysisId(analysis.id);
            for (IOC ioc : iocs) {
                threatMatchCount += threatMatchRepository.findByIocId(ioc.id).size();
            }

            packageName = analysis.packageName;
            applicationName = analysis.applicationName;
            sha256 = analysis.sha256;
            fileSize = analysis.fileSize;
            if (analysis.storageKey != null) {
                fileName = analysis.storageKey;
            }
        }

        return new ScanHistoryItemDto(
                scan.getId(),
                scan.getScanType() != null ? scan.getScanType().name() : "APK",
                scan.getTarget(),
                fileName,
                fileSize,
                packageName,
                applicationName,
                sha256,
                scan.getStatus() != null ? scan.getStatus().name() : "PENDING",
                scan.getRiskScore(),
                scan.getRiskLevel() != null ? scan.getRiskLevel().name() : "UNKNOWN",
                findingsCount,
                iocCount,
                threatMatchCount,
                alertCount,
                scan.getCreatedAt(),
                scan.getCompletedAt()
        );
    }

    private Scan.Status parseStatus(String s) {
        if (s == null || s.isBlank() || "ALL".equalsIgnoreCase(s)) return null;
        try {
            return Scan.Status.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private Scan.RiskLevel parseRiskLevel(String s) {
        if (s == null || s.isBlank() || "ALL".equalsIgnoreCase(s)) return null;
        try {
            return Scan.RiskLevel.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
