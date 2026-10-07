package com.cyberintel.service;

import com.cyberintel.dto.AlertDtos;
import com.cyberintel.dto.ScanHistoryDtos.*;
import com.cyberintel.entity.*;
import com.cyberintel.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ScanHistoryServiceTest {

    @Mock
    private ScanRepository scanRepository;
    @Mock
    private ApkAnalysisRepository apkAnalysisRepository;
    @Mock
    private MalwareFindingRepository malwareFindingRepository;
    @Mock
    private IocRepository iocRepository;
    @Mock
    private ThreatMatchRepository threatMatchRepository;
    @Mock
    private AlertRepository alertRepository;
    @Mock
    private AlertService alertService;

    private ScanHistoryService scanHistoryService;

    private Scan sampleScan;
    private User sampleUser;
    private ApkAnalysis sampleAnalysis;

    @BeforeEach
    void setUp() throws Exception {
        scanHistoryService = new ScanHistoryService(
                scanRepository,
                apkAnalysisRepository,
                malwareFindingRepository,
                iocRepository,
                threatMatchRepository,
                alertRepository,
                alertService
        );

        sampleUser = new User("SecOps User", "secops@cyberintel.com", "pass123");
        setEntityId(sampleUser, 1L);

        sampleScan = new Scan(Scan.ScanType.APK, "finance-update.apk", sampleUser);
        setEntityId(sampleScan, 100L);
        sampleScan.setRiskScore(90);
        sampleScan.setRiskLevel(Scan.RiskLevel.CRITICAL);
        sampleScan.setStatus(Scan.Status.COMPLETED);

        sampleAnalysis = new ApkAnalysis();
        sampleAnalysis.id = 10L;
        sampleAnalysis.scan = sampleScan;
        sampleAnalysis.applicationName = "Finance Update";
        sampleAnalysis.packageName = "com.sample.finance";
        sampleAnalysis.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        sampleAnalysis.fileSize = 1048576L;
    }

    private void setEntityId(Object entity, Long id) throws Exception {
        Field idField = entity.getClass().getDeclaredField("id");
        idField.setAccessible(true);
        idField.set(entity, id);
    }

    @Test
    @DisplayName("getScanHistory: returns mapped scan history with findings, IOCs and alert counts")
    void getScanHistory_returnsAggregatedItems() {
        when(scanRepository.findFiltered(null, null, null)).thenReturn(List.of(sampleScan));
        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(malwareFindingRepository.countByApkAnalysisId(10L)).thenReturn(5L);
        when(iocRepository.countByApkAnalysisId(10L)).thenReturn(8L);
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(alertRepository.findByScanIdOrderByCreatedAtDesc(100L)).thenReturn(Collections.emptyList());

        List<ScanHistoryItemDto> history = scanHistoryService.getScanHistory(null, null, null, null);

        assertThat(history).hasSize(1);
        ScanHistoryItemDto item = history.get(0);
        assertThat(item.id()).isEqualTo(100L);
        assertThat(item.packageName()).isEqualTo("com.sample.finance");
        assertThat(item.applicationName()).isEqualTo("Finance Update");
        assertThat(item.riskScore()).isEqualTo(90);
        assertThat(item.riskLevel()).isEqualTo("CRITICAL");
        assertThat(item.findingsCount()).isEqualTo(5L);
        assertThat(item.iocCount()).isEqualTo(8L);
    }

    @Test
    @DisplayName("getScanHistory: filters out items that do not match packageName filter")
    void getScanHistory_filtersByPackageName() {
        when(scanRepository.findFiltered(null, null, null)).thenReturn(List.of(sampleScan));
        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));

        List<ScanHistoryItemDto> result = scanHistoryService.getScanHistory(null, "other.package", null, null);
        assertThat(result).isEmpty();

        List<ScanHistoryItemDto> matchingResult = scanHistoryService.getScanHistory(null, "sample.finance", null, null);
        assertThat(matchingResult).hasSize(1);
    }

    @Test
    @DisplayName("getScanHistoryById: returns item when scan found")
    void getScanHistoryById_returnsItem() {
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));
        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(malwareFindingRepository.countByApkAnalysisId(10L)).thenReturn(2L);
        when(iocRepository.countByApkAnalysisId(10L)).thenReturn(3L);
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(alertRepository.findByScanIdOrderByCreatedAtDesc(100L)).thenReturn(Collections.emptyList());

        ScanHistoryItemDto item = scanHistoryService.getScanHistoryById(100L);

        assertThat(item).isNotNull();
        assertThat(item.id()).isEqualTo(100L);
        assertThat(item.status()).isEqualTo("COMPLETED");
    }

    @Test
    @DisplayName("getScanHistoryById: throws NoSuchElementException when scan not found")
    void getScanHistoryById_whenNotFound_throwsException() {
        when(scanRepository.findById(999L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> scanHistoryService.getScanHistoryById(999L))
                .isInstanceOf(NoSuchElementException.class)
                .hasMessageContaining("Scan not found with id: 999");
    }

    @Test
    @DisplayName("getDashboardStats: aggregates counts for scans, risks, alerts, threat matches, and IOCs")
    void getDashboardStats_returnsAccurateStats() {
        when(scanRepository.count()).thenReturn(50L);
        when(scanRepository.countHighAndCriticalRisks()).thenReturn(15L);
        when(alertRepository.countByStatus(Alert.Status.NEW)).thenReturn(6L);
        when(alertRepository.countByStatus(Alert.Status.OPEN)).thenReturn(2L);
        when(threatMatchRepository.count()).thenReturn(30L);
        when(iocRepository.count()).thenReturn(120L);
        when(scanRepository.getAverageRiskScore()).thenReturn(62.85);

        when(scanRepository.findTop10ByOrderByCreatedAtDesc()).thenReturn(List.of(sampleScan));
        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(alertRepository.findByScanIdOrderByCreatedAtDesc(100L)).thenReturn(Collections.emptyList());

        Alert sampleAlert = new Alert("Critical Alert", "Trojan found", Alert.Severity.CRITICAL, "Engine", sampleScan);
        when(alertRepository.findTop10ByOrderByCreatedAtDesc()).thenReturn(List.of(sampleAlert));
        when(alertService.toDto(sampleAlert)).thenReturn(new AlertDtos.AlertDto(
                1L, 100L, "finance-update.apk", "Critical Alert", "Trojan found",
                "CRITICAL", "NEW", "Engine", "MALWARE", null, null, null, Instant.now(), Instant.now()
        ));

        DashboardStatsDto stats = scanHistoryService.getDashboardStats();

        assertThat(stats.totalScans()).isEqualTo(50L);
        assertThat(stats.highCriticalRisks()).isEqualTo(15L);
        assertThat(stats.newAlerts()).isEqualTo(8L);
        assertThat(stats.threatMatches()).isEqualTo(30L);
        assertThat(stats.totalIocs()).isEqualTo(120L);
        assertThat(stats.avgRiskScore()).isEqualTo(62.9);
        assertThat(stats.recentScans()).hasSize(1);
        assertThat(stats.recentAlerts()).hasSize(1);
    }
}
