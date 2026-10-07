package com.cyberintel.service;

import com.cyberintel.config.RiskScoringProperties;
import com.cyberintel.config.RiskScoringProperties.ConfidenceMultipliers;
import com.cyberintel.config.RiskScoringProperties.SeverityMultipliers;
import com.cyberintel.config.RiskScoringProperties.Weights;
import com.cyberintel.dto.ApkDtos.Api;
import com.cyberintel.dto.ApkDtos.Component;
import com.cyberintel.dto.ApkDtos.Metadata;
import com.cyberintel.dto.ApkDtos.Permission;
import com.cyberintel.dto.ApkDtos.RiskAssessmentResult;
import com.cyberintel.dto.ApkDtos.RiskBreakdownDto;
import com.cyberintel.dto.ApkDtos.RiskIndicatorDto;
import com.cyberintel.dto.ApkDtos.RiskRecommendationDto;
import com.cyberintel.entity.ApkAnalysis;
import com.cyberintel.entity.ApiFinding;
import com.cyberintel.entity.ComponentFinding;
import com.cyberintel.entity.ExtractedString;
import com.cyberintel.entity.IOC;
import com.cyberintel.entity.MalwareFinding;
import com.cyberintel.entity.PermissionFinding;
import com.cyberintel.entity.RiskAssessment;
import com.cyberintel.entity.RiskIndicator;
import com.cyberintel.entity.Scan;
import com.cyberintel.entity.ThreatIntelligence;
import com.cyberintel.entity.ThreatMatch;
import com.cyberintel.entity.User;
import com.cyberintel.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RiskCorrelationServiceTest {

    @Mock
    private RiskAssessmentRepository riskAssessmentRepository;
    @Mock
    private RiskIndicatorRepository riskIndicatorRepository;
    @Mock
    private ApkAnalysisRepository apkAnalysisRepository;
    @Mock
    private MalwareFindingRepository malwareFindingRepository;
    @Mock
    private IocRepository iocRepository;
    @Mock
    private ThreatMatchRepository threatMatchRepository;
    @Mock
    private ScanRepository scanRepository;

    private RiskScoringProperties scoringProperties;
    private RiskCorrelationService riskCorrelationService;

    private ApkAnalysis sampleAnalysis;
    private Scan sampleScan;
    private User sampleUser;

    @BeforeEach
    void setUp() throws Exception {
        scoringProperties = new RiskScoringProperties();

        riskCorrelationService = new RiskCorrelationService(
                scoringProperties,
                riskAssessmentRepository,
                riskIndicatorRepository,
                apkAnalysisRepository,
                malwareFindingRepository,
                iocRepository,
                threatMatchRepository,
                scanRepository
        );

        sampleUser = new User("Test User", "test@cyberintel.com", "password123");
        setEntityId(sampleUser, 1L);

        sampleScan = new Scan(Scan.ScanType.APK, "test.apk", sampleUser);
        setEntityId(sampleScan, 100L);

        sampleAnalysis = new ApkAnalysis();
        sampleAnalysis.id = 10L;
        sampleAnalysis.scan = sampleScan;
        sampleAnalysis.applicationName = "SecureBank App";
        sampleAnalysis.packageName = "com.securebank.app";
        sampleAnalysis.sourceSummary = "{}";
        sampleAnalysis.apiFindings = new ArrayList<>();
        sampleAnalysis.permissions = new ArrayList<>();
        sampleAnalysis.components = new ArrayList<>();
        sampleAnalysis.strings = new ArrayList<>();
    }

    private void setEntityId(Object entity, Long id) throws Exception {
        Field idField = entity.getClass().getDeclaredField("id");
        idField.setAccessible(true);
        idField.set(entity, id);
    }

    // =========================================================================
    // 1. CLEAN SCAN / 0 SCORE
    // =========================================================================

    @Test
    @DisplayName("Clean scan with no findings produces score 0.0, LOW risk level, LOW confidence, and fallback recommendation")
    void calculateRisk_cleanScan_returnsZeroScoreAndLowRisk() {
        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        assertThat(result).isNotNull();
        assertThat(result.score()).isEqualTo(0.0);
        assertThat(result.riskLevel()).isEqualTo("LOW");
        assertThat(result.confidence()).isEqualTo("LOW");
        assertThat(result.indicators()).isEmpty();

        RiskBreakdownDto breakdown = result.breakdown();
        assertThat(breakdown.staticFindings()).isEqualTo(0.0);
        assertThat(breakdown.threatIntelligence()).isEqualTo(0.0);
        assertThat(breakdown.apiCalls()).isEqualTo(0.0);
        assertThat(breakdown.permissions()).isEqualTo(0.0);
        assertThat(breakdown.iocs()).isEqualTo(0.0);
        assertThat(breakdown.urls()).isEqualTo(0.0);
        assertThat(breakdown.components()).isEqualTo(0.0);
        assertThat(breakdown.obfuscationNative()).isEqualTo(0.0);
        assertThat(breakdown.total()).isEqualTo(0.0);

        assertThat(result.recommendations()).hasSize(1);
        assertThat(result.recommendations().get(0).category()).isEqualTo("GENERAL");
        assertThat(result.recommendations().get(0).recommendation()).contains("standard security hygiene");

        verify(riskAssessmentRepository).save(any(RiskAssessment.class));
        verify(riskIndicatorRepository).saveAll(Collections.emptyList());
        verify(scanRepository).save(sampleScan);
        assertThat(sampleScan.getRiskScore()).isEqualTo(0);
        assertThat(sampleScan.getRiskLevel()).isEqualTo(Scan.RiskLevel.LOW);
    }

    // =========================================================================
    // 2. BOUNDARY TESTS (0-25 LOW, 26-50 MEDIUM, 51-75 HIGH, 76-100 CRITICAL)
    // =========================================================================

    @Test
    @DisplayName("Boundary: Score at exact 25.0 maps to LOW risk level")
    void calculateRisk_boundaryAt25_returnsLowRisk() {
        // Static findings weight = 25.0, CRITICAL (1.0) * HIGH (1.0) = 25.0
        MalwareFinding mf = createMalwareFinding("malware", "CRITICAL", "HIGH", "rule_1", "ev1");
        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mf));
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        assertThat(result.score()).isEqualTo(25.0);
        assertThat(result.riskLevel()).isEqualTo("LOW");
    }

    @Test
    @DisplayName("Boundary: Score at 26.0 maps to MEDIUM risk level")
    void calculateRisk_boundaryAt26_returnsMediumRisk() {
        // Threat intelligence: 30.0 * HIGH (0.75) * HIGH (1.0) = 22.5
        // Suspicious APIs: 15.0 * MEDIUM (0.50) * MEDIUM (0.75) = 5.625
        // Total = 22.5 + 5.625 = 28.125 -> 28.1
        IOC ioc = createIoc(201L, "DOMAIN", "evil.com", "HIGH", "HIGH");
        ThreatIntelligence ti = createThreatIntel("evil.com", "MALWARE");
        ThreatMatch tm = createThreatMatch(301L, ioc, ti, "HIGH", "HIGH");

        ApiFinding api = createApiFinding(401L, "exec", "java.lang.Runtime", "exec", "MEDIUM");
        sampleAnalysis.apiFindings.add(api);

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(List.of(ioc));
        when(threatMatchRepository.findMatchedByIocId(201L)).thenReturn(List.of(tm));
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        assertThat(result.score()).isGreaterThanOrEqualTo(26.0).isLessThanOrEqualTo(50.0);
        assertThat(result.riskLevel()).isEqualTo("MEDIUM");
    }

    @Test
    @DisplayName("Boundary: Score at exact 50.0 maps to MEDIUM risk level")
    void calculateRisk_boundaryAt50_returnsMediumRisk() {
        // Static Findings (25.0 * 1.0 * 1.0 = 25.0) + Threat Intel (30.0 * 0.75 * 1.0 = 22.5) + IOC (10.0 * 0.25 * 1.0 = 2.5) = 50.0
        MalwareFinding mf = createMalwareFinding("exploit", "CRITICAL", "HIGH", "rule_1", "ev1");
        IOC ioc = createIoc(201L, "DOMAIN", "evil.com", "HIGH", "HIGH");
        ThreatIntelligence ti = createThreatIntel("evil.com", "MALWARE");
        ThreatMatch tm = createThreatMatch(301L, ioc, ti, "HIGH", "HIGH");
        IOC standaloneIoc = createIoc(202L, "IP", "1.2.3.4", "LOW", "HIGH");

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mf));
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(List.of(ioc, standaloneIoc));
        when(threatMatchRepository.findMatchedByIocId(201L)).thenReturn(List.of(tm));
        when(threatMatchRepository.findMatchedByIocId(202L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        assertThat(result.score()).isEqualTo(50.0);
        assertThat(result.riskLevel()).isEqualTo("MEDIUM");
    }

    @Test
    @DisplayName("Boundary: Score at 51.0+ maps to HIGH risk level")
    void calculateRisk_boundaryAt51_returnsHighRisk() {
        // Static Findings (25.0) + Threat Intel (30.0 * HIGH 0.75 * HIGH 1.0 = 22.5) + IOC (10.0 * HIGH 0.75 * HIGH 1.0 = 7.5)
        // Total = 25.0 + 22.5 + 7.5 = 55.0
        MalwareFinding mf = createMalwareFinding("exploit", "CRITICAL", "HIGH", "rule_1", "ev1");
        IOC ioc = createIoc(201L, "DOMAIN", "evil.com", "HIGH", "HIGH");
        ThreatIntelligence ti = createThreatIntel("evil.com", "MALWARE");
        ThreatMatch tm = createThreatMatch(301L, ioc, ti, "HIGH", "HIGH");

        IOC standaloneIoc = createIoc(202L, "IP", "1.2.3.4", "HIGH", "HIGH");

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mf));
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(List.of(ioc, standaloneIoc));
        when(threatMatchRepository.findMatchedByIocId(201L)).thenReturn(List.of(tm));
        when(threatMatchRepository.findMatchedByIocId(202L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        assertThat(result.score()).isBetween(51.0, 75.0);
        assertThat(result.riskLevel()).isEqualTo("HIGH");
    }

    @Test
    @DisplayName("Boundary: Score at exact 75.0 maps to HIGH risk level")
    void calculateRisk_boundaryAt75_returnsHighRisk() {
        // Static Findings (25.0) + Threat Intel (30.0) + Suspicious APIs (15.0 cap) + IOCs (5.0) = 75.0
        MalwareFinding mf = createMalwareFinding("exploit", "CRITICAL", "HIGH", "rule_1", "ev1");

        IOC ioc = createIoc(201L, "DOMAIN", "evil.com", "CRITICAL", "HIGH");
        ThreatIntelligence ti = createThreatIntel("evil.com", "MALWARE");
        ThreatMatch tm = createThreatMatch(301L, ioc, ti, "CRITICAL", "HIGH");
        IOC standaloneIoc = createIoc(202L, "IP", "1.2.3.4", "CRITICAL", "LOW");

        ApiFinding api1 = createApiFinding(401L, "exec", "java.lang.Runtime", "exec", "CRITICAL");
        ApiFinding api2 = createApiFinding(402L, "loadLibrary", "java.lang.System", "loadLibrary", "CRITICAL");

        sampleAnalysis.apiFindings.add(api1);
        sampleAnalysis.apiFindings.add(api2);

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mf));
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(List.of(ioc, standaloneIoc));
        when(threatMatchRepository.findMatchedByIocId(201L)).thenReturn(List.of(tm));
        when(threatMatchRepository.findMatchedByIocId(202L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        assertThat(result.score()).isEqualTo(75.0);
        assertThat(result.riskLevel()).isEqualTo("HIGH");
    }

    @Test
    @DisplayName("Boundary: Score at 76.0+ maps to CRITICAL risk level")
    void calculateRisk_boundaryAt76_returnsCriticalRisk() {
        // Static (25) + Threat Intel (30) + APIs (11.25) + Permissions (7.5) + IOC (10) = 83.75 >= 76.0
        MalwareFinding mf = createMalwareFinding("exploit", "CRITICAL", "HIGH", "rule_1", "ev1");

        IOC ioc = createIoc(201L, "DOMAIN", "evil.com", "CRITICAL", "HIGH");
        ThreatIntelligence ti = createThreatIntel("evil.com", "MALWARE");
        ThreatMatch tm = createThreatMatch(301L, ioc, ti, "CRITICAL", "HIGH");
        IOC standaloneIoc = createIoc(202L, "IP", "1.2.3.4", "CRITICAL", "HIGH");

        ApiFinding api = createApiFinding(401L, "exec", "java.lang.Runtime", "exec", "CRITICAL");
        PermissionFinding perm = createPermissionFinding(501L, "android.permission.SEND_SMS", "CRITICAL");

        sampleAnalysis.apiFindings.add(api);
        sampleAnalysis.permissions.add(perm);

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mf));
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(List.of(ioc, standaloneIoc));
        when(threatMatchRepository.findMatchedByIocId(201L)).thenReturn(List.of(tm));
        when(threatMatchRepository.findMatchedByIocId(202L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        assertThat(result.score()).isGreaterThanOrEqualTo(76.0);
        assertThat(result.riskLevel()).isEqualTo("CRITICAL");
    }

    // =========================================================================
    // 3. SCORE CLAMPING TO 0..100
    // =========================================================================

    @Test
    @DisplayName("Score clamping: Multiple findings exceeding 100 sum to max 100.0")
    void calculateRisk_scoreClamping_max100() {
        // Add findings across all categories at max values
        MalwareFinding mf1 = createMalwareFinding("trojan", "CRITICAL", "HIGH", "rule_1", "ev1");
        MalwareFinding mf2 = createMalwareFinding("rootkit", "CRITICAL", "HIGH", "rule_2", "ev2");

        IOC ioc1 = createIoc(201L, "DOMAIN", "c2-server.com", "CRITICAL", "HIGH");
        ThreatIntelligence ti1 = createThreatIntel("c2-server.com", "MALWARE");
        ThreatMatch tm1 = createThreatMatch(301L, ioc1, ti1, "CRITICAL", "HIGH");

        IOC standaloneIoc = createIoc(202L, "IP", "10.0.0.1", "CRITICAL", "HIGH");

        ApiFinding api1 = createApiFinding(401L, "exec", "java.lang.Runtime", "exec", "CRITICAL");
        ApiFinding api2 = createApiFinding(402L, "loadLibrary", "java.lang.System", "loadLibrary", "CRITICAL");

        PermissionFinding perm1 = createPermissionFinding(501L, "android.permission.SEND_SMS", "CRITICAL");
        PermissionFinding perm2 = createPermissionFinding(502L, "android.permission.READ_SMS", "CRITICAL");

        ExtractedString url1 = createExtractedString(601L, "URL", "http://pastebin.com/malware1");
        ExtractedString url2 = createExtractedString(602L, "URL", "http://pastebin.com/malware2");
        ExtractedString url3 = createExtractedString(603L, "URL", "http://pastebin.com/malware3");

        ComponentFinding comp1 = createComponentFinding(701L, "receiver", "BootReceiver", true, "CRITICAL");
        ComponentFinding comp2 = createComponentFinding(702L, "receiver", "StartupReceiver", true, "CRITICAL");

        sampleAnalysis.apiFindings.addAll(List.of(api1, api2));
        sampleAnalysis.permissions.addAll(List.of(perm1, perm2));
        sampleAnalysis.strings.addAll(List.of(url1, url2, url3));
        sampleAnalysis.components.addAll(List.of(comp1, comp2));
        sampleAnalysis.sourceSummary = "Detected obfuscation and native binaries";

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mf1, mf2));
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(List.of(ioc1, standaloneIoc));
        when(threatMatchRepository.findMatchedByIocId(201L)).thenReturn(List.of(tm1));
        when(threatMatchRepository.findMatchedByIocId(202L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        assertThat(result.score()).isEqualTo(98.5);
        assertThat(result.riskLevel()).isEqualTo("CRITICAL");
        assertThat(result.breakdown().total()).isEqualTo(98.5);
    }

    // =========================================================================
    // 4. ALL EIGHT CONFIGURED WEIGHTS VERIFICATION
    // =========================================================================

    @Test
    @DisplayName("Verify exact 8 configured weights: 25% Static, 30% ThreatIntel, 15% APIs, 10% Perms, 10% IOCs, 5% URLs, 3% Components, 2% Obfuscation")
    void calculateRisk_allEightWeights_correspondToExactConfig() {
        Weights w = scoringProperties.getWeights();
        assertThat(w.getStaticFindings()).isEqualTo(25.0);
        assertThat(w.getThreatIntelligence()).isEqualTo(30.0);
        assertThat(w.getSuspiciousApis()).isEqualTo(15.0);
        assertThat(w.getSuspiciousPermissions()).isEqualTo(10.0);
        assertThat(w.getIocIndicators()).isEqualTo(10.0);
        assertThat(w.getSuspiciousUrls()).isEqualTo(5.0);
        assertThat(w.getSuspiciousComponents()).isEqualTo(3.0);
        assertThat(w.getObfuscationNative()).isEqualTo(2.0);

        double sum = w.getStaticFindings() + w.getThreatIntelligence() + w.getSuspiciousApis()
                + w.getSuspiciousPermissions() + w.getIocIndicators() + w.getSuspiciousUrls()
                + w.getSuspiciousComponents() + w.getObfuscationNative();
        assertThat(sum).isEqualTo(100.0);
    }

    // =========================================================================
    // 5. SEVERITY MULTIPLIERS (CRITICAL=1.0, HIGH=0.75, MEDIUM=0.50, LOW=0.25)
    // =========================================================================

    @Test
    @DisplayName("Severity Multipliers: CRITICAL=1.0, HIGH=0.75, MEDIUM=0.50, LOW=0.25")
    void calculateRisk_severityMultipliers_appliedCorrectly() {
        SeverityMultipliers sev = scoringProperties.getSeverity();
        assertThat(sev.getCritical()).isEqualTo(1.00);
        assertThat(sev.getHigh()).isEqualTo(0.75);
        assertThat(sev.getMedium()).isEqualTo(0.50);
        assertThat(sev.getLow()).isEqualTo(0.25);

        // Test CRITICAL severity on static findings (25.0 * 1.0 * 1.0 = 25.0)
        MalwareFinding mfCritical = createMalwareFinding("cat1", "CRITICAL", "HIGH", "r1", "ev1");
        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mfCritical));
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult criticalResult = riskCorrelationService.calculateRisk(100L);
        assertThat(criticalResult.breakdown().staticFindings()).isEqualTo(25.0);

        // Test HIGH severity on static findings (25.0 * 0.75 * 1.0 = 18.75 -> round1 is 18.8)
        MalwareFinding mfHigh = createMalwareFinding("cat1", "HIGH", "HIGH", "r1", "ev1");
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mfHigh));
        RiskAssessmentResult highResult = riskCorrelationService.calculateRisk(100L);
        assertThat(highResult.breakdown().staticFindings()).isEqualTo(18.8);

        // Test MEDIUM severity on static findings (25.0 * 0.50 * 1.0 = 12.5)
        MalwareFinding mfMed = createMalwareFinding("cat1", "MEDIUM", "HIGH", "r1", "ev1");
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mfMed));
        RiskAssessmentResult medResult = riskCorrelationService.calculateRisk(100L);
        assertThat(medResult.breakdown().staticFindings()).isEqualTo(12.5);

        // Test LOW severity on static findings (25.0 * 0.25 * 1.0 = 6.25 -> round1 is 6.3)
        MalwareFinding mfLow = createMalwareFinding("cat1", "LOW", "HIGH", "r1", "ev1");
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mfLow));
        RiskAssessmentResult lowResult = riskCorrelationService.calculateRisk(100L);
        assertThat(lowResult.breakdown().staticFindings()).isEqualTo(6.3);
    }

    // =========================================================================
    // 6. CONFIDENCE MULTIPLIERS (HIGH=1.0, MEDIUM=0.75, LOW=0.50)
    // =========================================================================

    @Test
    @DisplayName("Confidence Multipliers: HIGH=1.0, MEDIUM=0.75, LOW=0.50")
    void calculateRisk_confidenceMultipliers_appliedCorrectly() {
        ConfidenceMultipliers conf = scoringProperties.getConfidence();
        assertThat(conf.getHigh()).isEqualTo(1.00);
        assertThat(conf.getMedium()).isEqualTo(0.75);
        assertThat(conf.getLow()).isEqualTo(0.50);

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        // CRITICAL (1.0) * HIGH (1.0) * 25.0 = 25.0
        MalwareFinding mfHigh = createMalwareFinding("cat", "CRITICAL", "HIGH", "r1", "e1");
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mfHigh));
        RiskAssessmentResult rHigh = riskCorrelationService.calculateRisk(100L);
        assertThat(rHigh.breakdown().staticFindings()).isEqualTo(25.0);

        // CRITICAL (1.0) * MEDIUM (0.75) * 25.0 = 18.75 -> round1 is 18.8
        MalwareFinding mfMed = createMalwareFinding("cat", "CRITICAL", "MEDIUM", "r1", "e1");
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mfMed));
        RiskAssessmentResult rMed = riskCorrelationService.calculateRisk(100L);
        assertThat(rMed.breakdown().staticFindings()).isEqualTo(18.8);

        // CRITICAL (1.0) * LOW (0.50) * 25.0 = 12.5
        MalwareFinding mfLow = createMalwareFinding("cat", "CRITICAL", "LOW", "r1", "e1");
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mfLow));
        RiskAssessmentResult rLow = riskCorrelationService.calculateRisk(100L);
        assertThat(rLow.breakdown().staticFindings()).isEqualTo(12.5);
    }

    // =========================================================================
    // 7. EVIDENCE DEDUPLICATION
    // =========================================================================

    @Test
    @DisplayName("Deduplication: Duplicate malware findings with same category & evidence are deduplicated")
    void calculateRisk_malwareFindingDeduplication() {
        MalwareFinding mf1 = createMalwareFinding("TROJAN", "CRITICAL", "HIGH", "rule_1", "same-evidence-string");
        MalwareFinding mf2 = createMalwareFinding("TROJAN", "CRITICAL", "HIGH", "rule_2", "same-evidence-string");

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mf1, mf2));
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        // Only 1 indicator should be created, score capped at single finding 25.0
        assertThat(result.indicators()).hasSize(1);
        assertThat(result.breakdown().staticFindings()).isEqualTo(25.0);
    }

    @Test
    @DisplayName("Deduplication: Duplicate IOCs with same type and value are deduplicated")
    void calculateRisk_iocDeduplication() {
        IOC ioc1 = createIoc(201L, "DOMAIN", "bad-domain.com", "CRITICAL", "HIGH");
        IOC ioc2 = createIoc(202L, "DOMAIN", "bad-domain.com", "CRITICAL", "HIGH");

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(List.of(ioc1, ioc2));
        when(threatMatchRepository.findMatchedByIocId(201L)).thenReturn(Collections.emptyList());
        when(threatMatchRepository.findMatchedByIocId(202L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        assertThat(result.indicators()).hasSize(1);
        assertThat(result.breakdown().iocs()).isEqualTo(10.0);
    }

    @Test
    @DisplayName("Deduplication: Threat match IOCs are excluded from standalone IOC category")
    void calculateRisk_threatMatchExcludesFromStandaloneIocs() {
        IOC ioc = createIoc(201L, "DOMAIN", "matched-domain.com", "CRITICAL", "HIGH");
        ThreatIntelligence ti = createThreatIntel("matched-domain.com", "MALWARE");
        ThreatMatch tm = createThreatMatch(301L, ioc, ti, "CRITICAL", "HIGH");

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(List.of(ioc));
        when(threatMatchRepository.findMatchedByIocId(201L)).thenReturn(List.of(tm));
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        assertThat(result.breakdown().threatIntelligence()).isEqualTo(30.0);
        assertThat(result.breakdown().iocs()).isEqualTo(0.0);
    }

    // =========================================================================
    // 8. DETERMINISTIC CALCULATION AND RECOMMENDATIONS
    // =========================================================================

    @Test
    @DisplayName("Determinism: Repeated calculations on identical data yield identical score and indicators")
    void calculateRisk_deterministicCalculation() {
        MalwareFinding mf = createMalwareFinding("TROJAN", "HIGH", "HIGH", "r1", "ev1");
        ApiFinding api = createApiFinding(401L, "exec", "java.lang.Runtime", "exec", "HIGH");
        sampleAnalysis.apiFindings.add(api);

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mf));
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult res1 = riskCorrelationService.calculateRisk(100L);
        RiskAssessmentResult res2 = riskCorrelationService.calculateRisk(100L);

        assertThat(res1.score()).isEqualTo(res2.score());
        assertThat(res1.riskLevel()).isEqualTo(res2.riskLevel());
        assertThat(res1.confidence()).isEqualTo(res2.confidence());
        assertThat(res1.breakdown()).isEqualTo(res2.breakdown());
        assertThat(res1.recommendations()).hasSameSizeAs(res2.recommendations());
    }

    @Test
    @DisplayName("Recommendations: Generates specific recommendations for Threat Intel, Dynamic Loading, SMS, Persistence, URLs, Exfiltration, Root, Ransomware")
    void calculateRisk_deterministicRecommendations() {
        MalwareFinding mfDyn = createMalwareFinding("dynamic_loading", "HIGH", "HIGH", "r1", "classloader invoke");
        MalwareFinding mfExfil = createMalwareFinding("data_exfiltration", "HIGH", "HIGH", "r2", "steal contacts");
        MalwareFinding mfRoot = createMalwareFinding("root_escalation", "HIGH", "HIGH", "r3", "su binary execution");
        MalwareFinding mfCrypto = createMalwareFinding("crypto_ransom", "HIGH", "HIGH", "r4", "encrypt files");

        IOC ioc = createIoc(201L, "DOMAIN", "bank-trojan.com", "CRITICAL", "HIGH");
        ThreatIntelligence ti = createThreatIntel("bank-trojan.com", "MALWARE");
        ThreatMatch tm = createThreatMatch(301L, ioc, ti, "CRITICAL", "HIGH");
        tm.description = "Banking trojan detected";

        PermissionFinding permSms = createPermissionFinding(501L, "android.permission.SEND_SMS", "CRITICAL");
        ComponentFinding compBoot = createComponentFinding(601L, "receiver", "BootCompletedReceiver", true, "HIGH");
        ExtractedString url = createExtractedString(701L, "URL", "http://tinyurl.com/xyz");

        sampleAnalysis.permissions.add(permSms);
        sampleAnalysis.components.add(compBoot);
        sampleAnalysis.strings.add(url);

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(List.of(mfDyn, mfExfil, mfRoot, mfCrypto));
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(List.of(ioc));
        when(threatMatchRepository.findMatchedByIocId(201L)).thenReturn(List.of(tm));
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        List<String> categories = result.recommendations().stream().map(RiskRecommendationDto::category).toList();
        assertThat(categories).contains(
                "THREAT_INTELLIGENCE",
                "DYNAMIC_CODE_LOADING",
                "SMS_ABUSE",
                "PERSISTENCE",
                "SUSPICIOUS_INFRASTRUCTURE",
                "DATA_EXFILTRATION",
                "PRIVILEGE_ESCALATION",
                "RANSOMWARE"
        );
    }

    // =========================================================================
    // 9. INDIVIDUAL CONTRIBUTION TESTS FOR EACH OF THE 8 CATEGORIES
    // =========================================================================

    @Test
    @DisplayName("Contribution: Threat Intelligence contribution (30% max weight)")
    void calculateRisk_threatIntelligenceContribution() {
        IOC ioc = createIoc(201L, "DOMAIN", "threat.com", "CRITICAL", "HIGH");
        ThreatIntelligence ti = createThreatIntel("threat.com", "THREAT_INTEL");
        ThreatMatch tm = createThreatMatch(301L, ioc, ti, "CRITICAL", "HIGH");

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(List.of(ioc));
        when(threatMatchRepository.findMatchedByIocId(201L)).thenReturn(List.of(tm));
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        assertThat(result.breakdown().threatIntelligence()).isEqualTo(30.0);
        assertThat(result.indicators()).hasSize(1);
        assertThat(result.indicators().get(0).category()).isEqualTo("THREAT_INTELLIGENCE");
        assertThat(result.indicators().get(0).contribution()).isEqualTo(30.0);
    }

    @Test
    @DisplayName("Contribution: Suspicious APIs contribution (15% max weight)")
    void calculateRisk_apiContribution() {
        ApiFinding api = createApiFinding(401L, "exec", "java.lang.Runtime", "exec", "CRITICAL");
        sampleAnalysis.apiFindings.add(api);

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        // Category weight = 15.0, CRITICAL (1.0) * MEDIUM (0.75) = 11.25 -> round1 11.3
        assertThat(result.breakdown().apiCalls()).isEqualTo(11.3);
        assertThat(result.indicators()).hasSize(1);
        assertThat(result.indicators().get(0).category()).isEqualTo("SUSPICIOUS_API");
    }

    @Test
    @DisplayName("Contribution: Suspicious Permissions contribution (10% max weight)")
    void calculateRisk_permissionContribution() {
        PermissionFinding perm = createPermissionFinding(501L, "android.permission.RECORD_AUDIO", "CRITICAL");
        sampleAnalysis.permissions.add(perm);

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        // Category weight = 10.0, CRITICAL (1.0) * MEDIUM (0.75) = 7.5
        assertThat(result.breakdown().permissions()).isEqualTo(7.5);
        assertThat(result.indicators()).hasSize(1);
        assertThat(result.indicators().get(0).category()).isEqualTo("SUSPICIOUS_PERMISSION");
    }

    @Test
    @DisplayName("Contribution: Suspicious URLs/Domains contribution (5% max weight)")
    void calculateRisk_urlContribution() {
        ExtractedString url = createExtractedString(601L, "DOMAIN", "test-domain.tk");
        sampleAnalysis.strings.add(url);

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        // Category weight = 5.0, MEDIUM (0.50) * MEDIUM (0.75) = 0.375 * 5.0 = 1.875 -> round1 1.9
        assertThat(result.breakdown().urls()).isEqualTo(1.9);
        assertThat(result.indicators()).hasSize(1);
        assertThat(result.indicators().get(0).category()).isEqualTo("SUSPICIOUS_URL");
    }

    @Test
    @DisplayName("Contribution: Suspicious Components contribution (3% max weight)")
    void calculateRisk_componentContribution() {
        ComponentFinding comp = createComponentFinding(701L, "service", "AccessibilityAdminService", true, "CRITICAL");
        sampleAnalysis.components.add(comp);

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        // Category weight = 3.0, CRITICAL (1.0) * MEDIUM (0.75) = 0.75 * 3.0 = 2.25 -> round1 2.3
        assertThat(result.breakdown().components()).isEqualTo(2.3);
        assertThat(result.indicators()).hasSize(1);
        assertThat(result.indicators().get(0).category()).isEqualTo("SUSPICIOUS_COMPONENT");
    }

    @Test
    @DisplayName("Contribution: Obfuscation/Native code contribution (2% max weight)")
    void calculateRisk_obfuscationNativeContribution() {
        sampleAnalysis.sourceSummary = "DexGuard obfuscation detected with native libraries in /lib/arm64";

        when(apkAnalysisRepository.findByScanId(100L)).thenReturn(Optional.of(sampleAnalysis));
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.empty());
        when(malwareFindingRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(iocRepository.findByApkAnalysisId(10L)).thenReturn(Collections.emptyList());
        when(scanRepository.findById(100L)).thenReturn(Optional.of(sampleScan));

        RiskAssessmentResult result = riskCorrelationService.calculateRisk(100L);

        // Category weight = 2.0, MEDIUM (0.50) * LOW (0.50) = 0.25 * 2.0 = 0.5
        assertThat(result.breakdown().obfuscationNative()).isEqualTo(0.5);
        assertThat(result.indicators()).hasSize(1);
        assertThat(result.indicators().get(0).category()).isEqualTo("OBFUSCATION_NATIVE");
    }

    // =========================================================================
    // 10. REPOSITORY LOOKUPS & QUERY METHODS
    // =========================================================================

    @Test
    @DisplayName("getLatestRisk: returns existing latest assessment with reconstructed breakdown & recommendations")
    void getLatestRisk_existingAssessment_returnsResult() {
        RiskAssessment assessment = new RiskAssessment();
        assessment.setId(50L);
        assessment.setScanId(100L);
        assessment.setApkAnalysisId(10L);
        assessment.setScore(80.0);
        assessment.setRiskLevel("CRITICAL");
        assessment.setConfidence("HIGH");
        assessment.setSummary("Critical threat detected");
        assessment.setIsLatest(true);
        assessment.setCreatedAt(Instant.now());

        RiskIndicator indicator = new RiskIndicator();
        indicator.setId(1L);
        indicator.setRiskAssessment(assessment);
        indicator.setCategory("THREAT_INTELLIGENCE");
        indicator.setSourceType("threat_match");
        indicator.setSeverity("CRITICAL");
        indicator.setConfidence("HIGH");
        indicator.setContribution(30.0);
        indicator.setDescription("Matched banking trojan");
        indicator.setEvidence("bank.dex");
        indicator.setCreatedAt(Instant.now());

        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.of(assessment));
        when(riskIndicatorRepository.findByRiskAssessmentIdOrderByContributionDesc(50L)).thenReturn(List.of(indicator));

        RiskAssessmentResult result = riskCorrelationService.getLatestRisk(100L);

        assertThat(result).isNotNull();
        assertThat(result.id()).isEqualTo(50L);
        assertThat(result.score()).isEqualTo(80.0);
        assertThat(result.riskLevel()).isEqualTo("CRITICAL");
        assertThat(result.breakdown().threatIntelligence()).isEqualTo(30.0);
        assertThat(result.indicators()).hasSize(1);
        assertThat(result.recommendations()).hasSize(1);
        assertThat(result.recommendations().get(0).category()).isEqualTo("THREAT_INTELLIGENCE");
    }

    @Test
    @DisplayName("getIndicators: returns indicator DTO list")
    void getIndicators_returnsMappedDtoList() {
        RiskAssessment assessment = new RiskAssessment();
        assessment.setId(50L);

        RiskIndicator indicator = new RiskIndicator();
        indicator.setId(10L);
        indicator.setCategory("MALWARE_FINDING");
        indicator.setSourceType("malware_finding");
        indicator.setSourceId(101L);
        indicator.setSeverity("HIGH");
        indicator.setConfidence("HIGH");
        indicator.setContribution(18.8);
        indicator.setDescription("Spyware detected");
        indicator.setEvidence("spyware.apk");
        indicator.setCreatedAt(Instant.now());

        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.of(assessment));
        when(riskIndicatorRepository.findByRiskAssessmentIdOrderByContributionDesc(50L)).thenReturn(List.of(indicator));

        List<RiskIndicatorDto> indicators = riskCorrelationService.getIndicators(100L);

        assertThat(indicators).hasSize(1);
        assertThat(indicators.get(0).id()).isEqualTo(10L);
        assertThat(indicators.get(0).category()).isEqualTo("MALWARE_FINDING");
        assertThat(indicators.get(0).contribution()).isEqualTo(18.8);
    }

    @Test
    @DisplayName("getBreakdown: aggregates category contributions from saved indicators")
    void getBreakdown_returnsAggregatedBreakdown() {
        RiskAssessment assessment = new RiskAssessment();
        assessment.setId(50L);

        RiskIndicator i1 = new RiskIndicator();
        i1.setCategory("MALWARE_FINDING");
        i1.setContribution(25.0);

        RiskIndicator i2 = new RiskIndicator();
        i2.setCategory("THREAT_INTELLIGENCE");
        i2.setContribution(30.0);

        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.of(assessment));
        when(riskIndicatorRepository.findByRiskAssessmentId(50L)).thenReturn(List.of(i1, i2));

        RiskBreakdownDto breakdown = riskCorrelationService.getBreakdown(100L);

        assertThat(breakdown.staticFindings()).isEqualTo(25.0);
        assertThat(breakdown.threatIntelligence()).isEqualTo(30.0);
        assertThat(breakdown.total()).isEqualTo(55.0);
    }

    @Test
    @DisplayName("getRecommendations: generates recommendation list from saved indicators")
    void getRecommendations_returnsGeneratedRecommendations() {
        RiskAssessment assessment = new RiskAssessment();
        assessment.setId(50L);

        RiskIndicator indicator = new RiskIndicator();
        indicator.setCategory("SMS_ABUSE");

        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(100L)).thenReturn(Optional.of(assessment));
        when(riskIndicatorRepository.findByRiskAssessmentId(50L)).thenReturn(List.of(indicator));

        List<RiskRecommendationDto> recs = riskCorrelationService.getRecommendations(100L);

        assertThat(recs).hasSize(1);
        assertThat(recs.get(0).category()).isEqualTo("SMS_ABUSE");
        assertThat(recs.get(0).recommendation()).contains("Review SMS access");
    }

    @Test
    @DisplayName("Exception handling: throws IllegalArgumentException when analysis not found for scanId")
    void calculateRisk_whenAnalysisNotFound_throwsIllegalArgumentException() {
        when(apkAnalysisRepository.findByScanId(999L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> riskCorrelationService.calculateRisk(999L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("APK analysis not found for scanId: 999");
    }

    @Test
    @DisplayName("Exception handling: throws IllegalArgumentException when assessment not found")
    void getLatestRisk_whenAssessmentNotFound_throwsIllegalArgumentException() {
        when(riskAssessmentRepository.findByScanIdAndIsLatestTrue(999L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> riskCorrelationService.getLatestRisk(999L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No risk assessment found for scanId: 999");
    }

    // =========================================================================
    // HELPER FIXTURE METHODS
    // =========================================================================

    private MalwareFinding createMalwareFinding(String category, String severity, String confidence, String ruleId, String evidence) {
        MalwareFinding mf = new MalwareFinding();
        mf.id = 1000L + (long) (Math.random() * 1000);
        mf.category = category;
        mf.title = "Malware finding " + category;
        mf.description = "Suspicious code detected in " + category;
        mf.evidence = evidence;
        mf.severity = severity;
        mf.confidence = confidence;
        mf.ruleId = ruleId;
        return mf;
    }

    private IOC createIoc(Long id, String type, String value, String severity, String confidence) {
        IOC ioc = new IOC();
        ioc.id = id;
        ioc.type = type;
        ioc.value = value;
        ioc.severity = severity;
        ioc.confidence = confidence;
        ioc.description = "IOC description for " + value;
        return ioc;
    }

    private ThreatIntelligence createThreatIntel(String indicator, String category) {
        ThreatIntelligence ti = new ThreatIntelligence();
        ti.id = 3000L + (long) (Math.random() * 1000);
        ti.indicator = indicator;
        ti.indicatorType = "DOMAIN";
        ti.threatName = "BankBot Trojan";
        ti.threatFamily = "BankingTrojan";
        ti.category = category;
        return ti;
    }

    private ThreatMatch createThreatMatch(Long id, IOC ioc, ThreatIntelligence ti, String severity, String confidence) {
        ThreatMatch tm = new ThreatMatch();
        tm.id = id;
        tm.ioc = ioc;
        tm.threatIntelligence = ti;
        tm.severity = severity;
        tm.confidence = confidence;
        tm.description = "Threat match for " + ti.threatName;
        return tm;
    }

    private ApiFinding createApiFinding(Long id, String apiName, String className, String methodName, String severity) {
        ApiFinding api = new ApiFinding();
        api.id = id;
        api.apiName = apiName;
        api.className = className;
        api.methodName = methodName;
        api.severity = severity;
        return api;
    }

    private PermissionFinding createPermissionFinding(Long id, String permissionName, String severity) {
        PermissionFinding perm = new PermissionFinding();
        perm.id = id;
        perm.permissionName = permissionName;
        perm.severity = severity;
        return perm;
    }

    private ExtractedString createExtractedString(Long id, String kind, String value) {
        ExtractedString str = new ExtractedString();
        str.id = id;
        str.kind = kind;
        str.value = value;
        return str;
    }

    private ComponentFinding createComponentFinding(Long id, String type, String name, boolean exported, String severity) {
        ComponentFinding comp = new ComponentFinding();
        comp.id = id;
        comp.componentType = type;
        comp.componentName = name;
        comp.exported = exported;
        comp.severity = severity;
        return comp;
    }
}