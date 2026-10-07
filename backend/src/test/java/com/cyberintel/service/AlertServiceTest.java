package com.cyberintel.service;

import com.cyberintel.dto.AlertDtos.*;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AlertServiceTest {

    @Mock
    private AlertRepository alertRepository;
    @Mock
    private ScanRepository scanRepository;
    @Mock
    private RiskAssessmentRepository riskAssessmentRepository;
    @Mock
    private RiskIndicatorRepository riskIndicatorRepository;
    @Mock
    private ApkAnalysisRepository apkAnalysisRepository;

    private AlertService alertService;

    private Scan sampleScan;
    private User sampleUser;
    private ApkAnalysis sampleAnalysis;
    private RiskAssessment sampleAssessment;

    @BeforeEach
    void setUp() throws Exception {
        alertService = new AlertService(
                alertRepository,
                scanRepository,
                riskAssessmentRepository,
                riskIndicatorRepository,
                apkAnalysisRepository
        );

        sampleUser = new User("Analyst User", "analyst@cyberintel.com", "pass123");
        setEntityId(sampleUser, 1L);

        sampleScan = new Scan(Scan.ScanType.APK, "malicious.apk", sampleUser);
        setEntityId(sampleScan, 100L);
        sampleScan.setRiskScore(85);
        sampleScan.setRiskLevel(Scan.RiskLevel.CRITICAL);

        sampleAnalysis = new ApkAnalysis();
        sampleAnalysis.id = 10L;
        sampleAnalysis.scan = sampleScan;
        sampleAnalysis.applicationName = "BankBot Trojan";
        sampleAnalysis.packageName = "com.evil.bankbot";

        sampleAssessment = new RiskAssessment();
        sampleAssessment.setId(50L);
        sampleAssessment.setScanId(100L);
        sampleAssessment.setApkAnalysisId(10L);
        sampleAssessment.setScore(85.0);
        sampleAssessment.setRiskLevel("CRITICAL");
        sampleAssessment.setConfidence("HIGH");
        sampleAssessment.setSummary("High severity banking trojan signals detected");
        sampleAssessment.setIsLatest(true);
    }

    private void setEntityId(Object entity, Long id) throws Exception {
        Field idField = entity.getClass().getDeclaredField("id");
        idField.setAccessible(true);
        idField.set(entity, id);
    }

    @Test
    @DisplayName("generateAlerts: creates alerts for CRITICAL risk assessment and threat intel indicators")
    void generateAlerts_createsAlertsForCriticalRiskAndThreatIntel() {
        RiskIndicator tiIndicator = new RiskIndicator();
        tiIndicator.setId(1L);
        tiIndicator.setCategory("THREAT_INTELLIGENCE");
        tiIndicator.setSeverity("CRITICAL");
        tiIndicator.setConfidence("HIGH");
        tiIndicator.setDescription("Matched BankingTrojan C2 feed");
        tiIndicator.setSourceType("THREAT_INTELLIGENCE");

        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.of(sampleAssessment));
        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskIndicatorRepository.findByRiskAssessmentId(50L)).thenReturn(List.of(tiIndicator));
        when(alertRepository.existsByScanIdAndTitle(anyLong(), anyString())).thenReturn(false);
        when(alertRepository.save(any(Alert.class))).thenAnswer(inv -> {
            Alert a = inv.getArgument(0);
            try { setEntityId(a, 999L); } catch (Exception ignored) {}
            return a;
        });

        List<Alert> alerts = alertService.generateAlertsFromAssessment(100L);

        assertThat(alerts).isNotEmpty();
        assertThat(alerts).anyMatch(a -> a.getTitle().contains("CRITICAL Risk Assessment") && a.getSeverity() == Alert.Severity.CRITICAL);
        assertThat(alerts).anyMatch(a -> a.getCategory().equals("THREAT_INTELLIGENCE"));
        verify(alertRepository, atLeastOnce()).save(any(Alert.class));
    }

    @Test
    @DisplayName("generateAlerts: prevents duplicate alerts when alert with same title exists")
    void generateAlerts_preventsDuplicateAlerts() {
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.of(sampleAssessment));
        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskIndicatorRepository.findByRiskAssessmentId(50L)).thenReturn(Collections.emptyList());
        when(alertRepository.existsByScanIdAndTitle(anyLong(), anyString())).thenReturn(true);

        List<Alert> alerts = alertService.generateAlertsFromAssessment(100L);

        assertThat(alerts).isEmpty();
        verify(alertRepository, never()).save(any(Alert.class));
    }

    @Test
    @DisplayName("generateAlerts: returns empty list when no risk assessment found")
    void generateAlerts_whenNoAssessment_returnsEmpty() {
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());

        List<Alert> alerts = alertService.generateAlertsFromAssessment(100L);

        assertThat(alerts).isEmpty();
        verify(alertRepository, never()).save(any(Alert.class));
    }

    @Test
    @DisplayName("generateAlerts: throws IllegalArgumentException when scan not found")
    void generateAlerts_whenScanNotFound_throwsException() {
        when(scanRepository.findById(999L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> alertService.generateAlertsFromAssessment(999L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Scan not found");
    }

    @Test
    @DisplayName("getAlerts: returns filtered alerts mapped to DTOs")
    void getAlerts_returnsMappedDtos() {
        Alert alert = new Alert("Malware Alert", "Trojan found", Alert.Severity.CRITICAL, "Scanner", sampleScan);
        alert.setStatus(Alert.Status.NEW);

        when(alertRepository.findFiltered(Alert.Status.NEW, Alert.Severity.CRITICAL, "Trojan"))
                .thenReturn(List.of(alert));

        List<AlertDto> dtos = alertService.getAlerts("NEW", "CRITICAL", "Trojan");

        assertThat(dtos).hasSize(1);
        assertThat(dtos.get(0).title()).isEqualTo("Malware Alert");
        assertThat(dtos.get(0).severity()).isEqualTo("CRITICAL");
        assertThat(dtos.get(0).status()).isEqualTo("NEW");
    }

    @Test
    @DisplayName("getAlertById: returns alert DTO when found")
    void getAlertById_returnsDto() {
        Alert alert = new Alert("Malware Alert", "Trojan found", Alert.Severity.HIGH, "Scanner", sampleScan);
        try { setEntityId(alert, 1L); } catch (Exception ignored) {}

        when(alertRepository.findById(1L)).thenReturn(Optional.of(alert));

        AlertDto dto = alertService.getAlertById(1L);

        assertThat(dto).isNotNull();
        assertThat(dto.id()).isEqualTo(1L);
        assertThat(dto.title()).isEqualTo("Malware Alert");
    }

    @Test
    @DisplayName("getAlertById: throws NoSuchElementException when alert not found")
    void getAlertById_whenNotFound_throwsException() {
        when(alertRepository.findById(999L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> alertService.getAlertById(999L))
                .isInstanceOf(NoSuchElementException.class)
                .hasMessageContaining("Alert not found with id: 999");
    }

    @Test
    @DisplayName("updateAlertStatus: updates status and notes")
    void updateAlertStatus_updatesStatusAndNotes() {
        Alert alert = new Alert("Malware Alert", "Trojan found", Alert.Severity.HIGH, "Scanner", sampleScan);
        alert.setStatus(Alert.Status.NEW);
        try { setEntityId(alert, 1L); } catch (Exception ignored) {}

        when(alertRepository.findById(1L)).thenReturn(Optional.of(alert));
        when(alertRepository.save(any(Alert.class))).thenAnswer(inv -> inv.getArgument(0));

        UpdateAlertStatusRequest req = new UpdateAlertStatusRequest("INVESTIGATING", "Analyst investigating C2 traffic");
        AlertDto updated = alertService.updateAlertStatus(1L, req);

        assertThat(updated.status()).isEqualTo("INVESTIGATING");
        assertThat(updated.notes()).isEqualTo("Analyst investigating C2 traffic");
    }

    @Test
    @DisplayName("resolveAlert: sets status to RESOLVED and records resolution timestamp")
    void resolveAlert_resolvesAndSetsTimestamp() {
        Alert alert = new Alert("Malware Alert", "Trojan found", Alert.Severity.HIGH, "Scanner", sampleScan);
        alert.setStatus(Alert.Status.INVESTIGATING);
        try { setEntityId(alert, 1L); } catch (Exception ignored) {}

        when(alertRepository.findById(1L)).thenReturn(Optional.of(alert));
        when(alertRepository.save(any(Alert.class))).thenAnswer(inv -> inv.getArgument(0));

        ResolveAlertRequest req = new ResolveAlertRequest("False positive verified", "Senior Analyst");
        AlertDto resolved = alertService.resolveAlert(1L, req);

        assertThat(resolved.status()).isEqualTo("RESOLVED");
        assertThat(resolved.notes()).isEqualTo("False positive verified");
        assertThat(resolved.resolvedBy()).isEqualTo("Senior Analyst");
        assertThat(resolved.resolvedAt()).isNotNull();
    }

    @Test
    @DisplayName("getAlertStats: returns accurate aggregate statistics")
    void getAlertStats_returnsCorrectMetrics() {
        when(alertRepository.count()).thenReturn(20L);
        when(alertRepository.countByStatus(Alert.Status.NEW)).thenReturn(5L);
        when(alertRepository.countByStatus(Alert.Status.OPEN)).thenReturn(3L);
        when(alertRepository.countByStatus(Alert.Status.INVESTIGATING)).thenReturn(4L);
        when(alertRepository.countByStatus(Alert.Status.ACKNOWLEDGED)).thenReturn(2L);
        when(alertRepository.countByStatus(Alert.Status.RESOLVED)).thenReturn(6L);
        when(alertRepository.countBySeverity(Alert.Severity.CRITICAL)).thenReturn(4L);
        when(alertRepository.countBySeverity(Alert.Severity.HIGH)).thenReturn(8L);
        when(alertRepository.countBySeverity(Alert.Severity.MEDIUM)).thenReturn(5L);
        when(alertRepository.countBySeverity(Alert.Severity.LOW)).thenReturn(3L);

        AlertStatsDto stats = alertService.getAlertStats();

        assertThat(stats.total()).isEqualTo(20L);
        assertThat(stats.newCount()).isEqualTo(8L);
        assertThat(stats.investigatingCount()).isEqualTo(6L);
        assertThat(stats.resolvedCount()).isEqualTo(6L);
        assertThat(stats.criticalCount()).isEqualTo(4L);
        assertThat(stats.highCount()).isEqualTo(8L);
    }
}
