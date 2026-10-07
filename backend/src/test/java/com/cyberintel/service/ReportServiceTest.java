package com.cyberintel.service;

import com.cyberintel.entity.*;
import com.cyberintel.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ReportServiceTest {

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
    private RiskAssessmentRepository riskAssessmentRepository;
    @Mock
    private RiskIndicatorRepository riskIndicatorRepository;
    @Mock
    private AlertRepository alertRepository;

    private ReportService reportService;

    private Scan sampleScan;
    private User sampleUser;
    private ApkAnalysis sampleAnalysis;
    private RiskAssessment sampleAssessment;
    private MalwareFinding sampleFinding;
    private IOC sampleIoc;
    private ThreatMatch sampleThreatMatch;
    private ThreatIntelligence sampleThreatIntel;

    @BeforeEach
    void setUp() throws Exception {
        reportService = new ReportService(
                scanRepository,
                apkAnalysisRepository,
                malwareFindingRepository,
                iocRepository,
                threatMatchRepository,
                riskAssessmentRepository,
                riskIndicatorRepository,
                alertRepository
        );

        sampleUser = new User("SecOps Analyst", "analyst@cyberintel.com", "pass123");
        setEntityId(sampleUser, 1L);

        sampleScan = new Scan(Scan.ScanType.APK, "banking-app.apk", sampleUser);
        setEntityId(sampleScan, 100L);
        sampleScan.setRiskScore(88);
        sampleScan.setRiskLevel(Scan.RiskLevel.CRITICAL);
        sampleScan.setStatus(Scan.Status.COMPLETED);

        sampleAnalysis = new ApkAnalysis();
        sampleAnalysis.id = 10L;
        sampleAnalysis.scan = sampleScan;
        sampleAnalysis.applicationName = "Banking Trojan App";
        sampleAnalysis.packageName = "com.trojan.bankbot";
        sampleAnalysis.sha256 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        sampleAnalysis.md5 = "1234567890abcdef1234567890abcdef";
        sampleAnalysis.fileSize = 2097152L;

        sampleAssessment = new RiskAssessment();
        sampleAssessment.setId(50L);
        sampleAssessment.setScanId(100L);
        sampleAssessment.setApkAnalysisId(10L);
        sampleAssessment.setScore(88.0);
        sampleAssessment.setRiskLevel("CRITICAL");
        sampleAssessment.setConfidence("HIGH");
        sampleAssessment.setSummary("High risk banking trojan detected with C2 domain communication.");
        sampleAssessment.setIsLatest(true);

        sampleFinding = new MalwareFinding();
        sampleFinding.id = 201L;
        sampleFinding.category = "DYNAMIC_LOADING";
        sampleFinding.title = "DexClassLoader Invocation";
        sampleFinding.description = "Loads dex payloads dynamically at runtime";
        sampleFinding.evidence = "dalvik.system.DexClassLoader";
        sampleFinding.severity = "HIGH";
        sampleFinding.confidence = "HIGH";
        sampleFinding.ruleId = "DYN_001";
        sampleFinding.source = "STATIC_YARA";

        sampleIoc = new IOC();
        sampleIoc.id = 301L;
        sampleIoc.type = "DOMAIN";
        sampleIoc.value = "c2-bankbot.com";
        sampleIoc.severity = "CRITICAL";
        sampleIoc.confidence = "HIGH";
        sampleIoc.source = "JADX";
        sampleIoc.description = "Known C2 domain";

        sampleThreatIntel = new ThreatIntelligence();
        sampleThreatIntel.id = 401L;
        sampleThreatIntel.indicator = "c2-bankbot.com";
        sampleThreatIntel.indicatorType = "DOMAIN";
        sampleThreatIntel.threatName = "BankBot C2";
        sampleThreatIntel.threatFamily = "BankBot";
        sampleThreatIntel.category = "MALWARE";

        sampleThreatMatch = new ThreatMatch();
        sampleThreatMatch.id = 501L;
        sampleThreatMatch.ioc = sampleIoc;
        sampleThreatMatch.threatIntelligence = sampleThreatIntel;
        sampleThreatMatch.matchType = "EXACT";
        sampleThreatMatch.severity = "CRITICAL";
        sampleThreatMatch.confidence = "HIGH";
        sampleThreatMatch.description = "Exact match on BankBot C2 infrastructure";
    }

    private void setEntityId(Object entity, Long id) throws Exception {
        Field idField = entity.getClass().getDeclaredField("id");
        idField.setAccessible(true);
        idField.set(entity, id);
    }

    @Test
    @DisplayName("generatePdfReport: generates non-empty PDF document with valid PDF header")
    void generatePdfReport_generatesValidPdf() {
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));
        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.of(sampleAssessment));
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(sampleFinding));
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(List.of(sampleIoc));
        when(threatMatchRepository.findMatchedByIocId(301L)).thenReturn(List.of(sampleThreatMatch));
        when(riskIndicatorRepository.findByRiskAssessmentIdOrderByContributionDesc(50L)).thenReturn(Collections.emptyList());
        when(alertRepository.findByScanIdOrderByCreatedAtDesc(100L)).thenReturn(Collections.emptyList());

        byte[] pdfBytes = reportService.generatePdfReport(100L);

        assertThat(pdfBytes).isNotEmpty();
        // PDF header starts with "%PDF-"
        String header = new String(Arrays.copyOfRange(pdfBytes, 0, 5), StandardCharsets.US_ASCII);
        assertThat(header).isEqualTo("%PDF-");
    }

    @Test
    @DisplayName("generatePdfReport: throws NoSuchElementException when scan not found")
    void generatePdfReport_whenScanNotFound_throwsException() {
        when(scanRepository.findById(999L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> reportService.generatePdfReport(999L))
                .isInstanceOf(NoSuchElementException.class)
                .hasMessageContaining("Scan not found for id: 999");
    }

    @Test
    @DisplayName("generateJsonReport: generates structured JSON document containing scan, APK, findings, IOCs, and alerts")
    void generateJsonReport_generatesValidJson() {
        RiskIndicator indicator = new RiskIndicator();
        indicator.setSourceType("malware_finding");
        indicator.setCategory("DYNAMIC_LOADING");
        indicator.setSeverity("HIGH");
        indicator.setConfidence("HIGH");
        sampleAssessment.addIndicator(indicator);
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));
        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.of(sampleAssessment));
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(sampleFinding));
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(List.of(sampleIoc));
        when(threatMatchRepository.findMatchedByIocId(301L)).thenReturn(List.of(sampleThreatMatch));
        when(riskIndicatorRepository.findByRiskAssessmentId(50L)).thenReturn(List.of(indicator));
        when(alertRepository.findByScanIdOrderByCreatedAtDesc(100L)).thenReturn(Collections.emptyList());

        byte[] jsonBytes = reportService.generateJsonReport(100L);

        assertThat(jsonBytes).isNotEmpty();
        String json = new String(jsonBytes, StandardCharsets.UTF_8);
        assertThat(json).contains("CyberIntel Security Report");
        assertThat(json).contains("Banking Trojan App");
        assertThat(json).contains("com.trojan.bankbot");
        assertThat(json).contains("DexClassLoader Invocation");
        assertThat(json).contains("c2-bankbot.com");
        assertThat(json).contains("malware_finding");
    }

    @Test
    @DisplayName("generateFindingsCsv: generates CSV with findings columns and data rows")
    void generateFindingsCsv_generatesValidCsv() {
        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(sampleFinding));

        byte[] csvBytes = reportService.generateFindingsCsv(100L);

        assertThat(csvBytes).isNotEmpty();
        String csv = new String(csvBytes, StandardCharsets.UTF_8);
        assertThat(csv).contains("Category,Severity,Confidence,Title,Description,Evidence,RuleId,Source");
        assertThat(csv).contains("DYNAMIC_LOADING");
        assertThat(csv).contains("DexClassLoader Invocation");
    }

    @Test
    @DisplayName("generateIocCsv: generates CSV with IOC columns and data rows")
    void generateIocCsv_generatesValidCsv() {
        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(List.of(sampleIoc));

        byte[] csvBytes = reportService.generateIocCsv(100L);

        assertThat(csvBytes).isNotEmpty();
        String csv = new String(csvBytes, StandardCharsets.UTF_8);
        assertThat(csv).contains("Type,Value,Severity,Confidence,Source,Description");
        assertThat(csv).contains("DOMAIN");
        assertThat(csv).contains("c2-bankbot.com");
    }

    @Test
    @DisplayName("generateThreatMatchCsv: generates CSV with matched threats")
    void generateThreatMatchCsv_generatesValidCsv() {
        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(List.of(sampleIoc));
        when(threatMatchRepository.findMatchedByIocId(301L)).thenReturn(List.of(sampleThreatMatch));

        byte[] csvBytes = reportService.generateThreatMatchCsv(100L);

        assertThat(csvBytes).isNotEmpty();
        String csv = new String(csvBytes, StandardCharsets.UTF_8);
        assertThat(csv).contains("Indicator,IndicatorType,ThreatName,ThreatFamily,Category,MatchType,Severity,Confidence,MatchedAt,Description");
        assertThat(csv).contains("c2-bankbot.com");
        assertThat(csv).contains("BankBot C2");
    }

    @Test
    @DisplayName("generateSummaryCsv: generates key-value summary CSV")
    void generateSummaryCsv_generatesValidCsv() {
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));
        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.of(sampleAssessment));
        when(malwareFindingRepository.countByApkAnalysisId(10L)).thenReturn(1L);
        when(iocRepository.countByApkAnalysisId(10L)).thenReturn(1L);
        when(alertRepository.findByScanIdOrderByCreatedAtDesc(100L)).thenReturn(Collections.emptyList());

        byte[] csvBytes = reportService.generateSummaryCsv(100L);

        assertThat(csvBytes).isNotEmpty();
        String csv = new String(csvBytes, StandardCharsets.UTF_8);
        assertThat(csv).contains("Metric,Value");
        assertThat(csv).contains("Scan ID");
        assertThat(csv).contains("100");
        assertThat(csv).contains("Banking Trojan App");
        assertThat(csv).contains("CRITICAL");
    }
}
