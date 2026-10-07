package com.cyberintel.service;

import com.cyberintel.entity.*;
import com.cyberintel.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

class ThreatIntelligenceMatchingServiceTest {

    @Mock
    private ThreatIntelligenceRepository threatIntelRepo;
    @Mock
    private ThreatMatchRepository threatMatchRepo;
    @Mock
    private IocRepository iocRepo;
    @Mock
    private ApkAnalysisRepository analysisRepo;

    private ThreatIntelligenceMatchingService service;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        service = new ThreatIntelligenceMatchingService(threatIntelRepo, threatMatchRepo, iocRepo, analysisRepo);
    }

    @Test
    void correlate_createsMatchesForExactIndicatorMatches() {
        ApkAnalysis analysis = createApkAnalysis(1L, 1L);
        IOC ioc1 = createIoc(1L, 1L, "http://malware-c2.example.com/payload.apk", "URL");
        IOC ioc2 = createIoc(2L, 1L, "192.0.2.156", "IP");
        IOC ioc3 = createIoc(3L, 1L, "unknown-domain.com", "DOMAIN");

        ThreatIntelligence ti1 = createThreatIntelligence(1L, "http://malware-c2.example.com/payload.apk", "URL", "BankBot C2", "BankBot", "C2_INFRASTRUCTURE", "CRITICAL", "HIGH");
        ThreatIntelligence ti2 = createThreatIntelligence(2L, "192.0.2.156", "IP", "Ransomware Distribution", "WannaLocker", "PAYLOAD_DELIVERY", "CRITICAL", "MEDIUM");

        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));
        when(iocRepo.findByApkAnalysisId(1L)).thenReturn(List.of(ioc1, ioc2, ioc3));
        when(threatIntelRepo.findByIndicatorAndType("http://malware-c2.example.com/payload.apk", "URL")).thenReturn(List.of(ti1));
        when(threatIntelRepo.findByIndicatorAndType("192.0.2.156", "IP")).thenReturn(List.of(ti2));
        when(threatIntelRepo.findByIndicatorAndType("unknown-domain.com", "DOMAIN")).thenReturn(List.of());
        when(threatMatchRepo.findByIocId(anyLong())).thenReturn(List.of());
        when(threatMatchRepo.save(any(ThreatMatch.class))).thenAnswer(inv -> inv.getArgument(0));

        ThreatIntelligenceMatchingService.CorrelationResult result = service.correlate(1L);

        assertThat(result.scanId()).isEqualTo(1L);
        assertThat(result.totalIocs()).isEqualTo(3);
        assertThat(result.matched()).isEqualTo(2);
        assertThat(result.noMatch()).isEqualTo(1);
        assertThat(result.critical()).isEqualTo(2);
        assertThat(result.categories()).containsExactlyInAnyOrder("C2_INFRASTRUCTURE", "PAYLOAD_DELIVERY");
        assertThat(result.families()).containsExactlyInAnyOrder("BankBot", "WannaLocker");
    }

    @Test
    void correlate_handlesNoIocs() {
        ApkAnalysis analysis = createApkAnalysis(1L, 1L);
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));
        when(iocRepo.findByApkAnalysisId(1L)).thenReturn(List.of());

        ThreatIntelligenceMatchingService.CorrelationResult result = service.correlate(1L);

        assertThat(result.totalIocs()).isEqualTo(0);
        assertThat(result.matched()).isEqualTo(0);
        assertThat(result.noMatch()).isEqualTo(0);
    }

    @Test
    void getCorrelationSummary_returnsSummaryFromExistingMatches() {
        ApkAnalysis analysis = createApkAnalysis(1L, 1L);
        IOC ioc1 = createIoc(1L, 1L, "http://malware-c2.example.com/payload.apk", "URL");
        IOC ioc2 = createIoc(2L, 1L, "unknown.com", "DOMAIN");

        ThreatIntelligence ti1 = createThreatIntelligence(1L, "http://malware-c2.example.com/payload.apk", "URL", "BankBot C2", "BankBot", "C2_INFRASTRUCTURE", "CRITICAL", "HIGH");
        ThreatMatch match1 = createThreatMatch(1L, ioc1, ti1, "EXACT", "MATCHED", "HIGH", "CRITICAL");

        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));
        when(iocRepo.findByApkAnalysisId(1L)).thenReturn(List.of(ioc1, ioc2));
        when(threatMatchRepo.findMatchedByIocId(1L)).thenReturn(List.of(match1));
        when(threatMatchRepo.findMatchedByIocId(2L)).thenReturn(List.of());

        ThreatIntelligenceMatchingService.CorrelationSummary summary = service.getCorrelationSummary(1L);

        assertThat(summary.scanId()).isEqualTo(1L);
        assertThat(summary.totalIocs()).isEqualTo(2);
        assertThat(summary.matched()).isEqualTo(1);
        assertThat(summary.noMatch()).isEqualTo(1);
        assertThat(summary.critical()).isEqualTo(1);
        assertThat(summary.categories()).contains("C2_INFRASTRUCTURE");
        assertThat(summary.families()).contains("BankBot");
    }

    @Test
    void matchIoc_returnsExactMatch() {
        IOC ioc = createIoc(1L, 1L, "http://evil.com", "URL");
        ThreatIntelligence ti = createThreatIntelligence(1L, "http://evil.com", "URL", "Test Threat", "Family", "MALWARE", "HIGH", "HIGH");

        when(threatIntelRepo.findByIndicatorAndType("http://evil.com", "URL")).thenReturn(List.of(ti));
        when(threatMatchRepo.findByIocId(1L)).thenReturn(List.of());
        when(threatMatchRepo.save(any(ThreatMatch.class))).thenAnswer(inv -> inv.getArgument(0));

        ThreatIntelligenceMatchingService.MatchResult result = service.matchIoc(ioc);

        assertThat(result.matched()).isTrue();
        assertThat(result.threatIntelligence()).isEqualTo(ti);
    }

    @Test
    void matchIoc_returnsNoMatchWhenNotFound() {
        IOC ioc = createIoc(1L, 1L, "http://unknown.com", "URL");

        when(threatIntelRepo.findByIndicatorAndType("http://unknown.com", "URL")).thenReturn(List.of());

        ThreatIntelligenceMatchingService.MatchResult result = service.matchIoc(ioc);

        assertThat(result.matched()).isFalse();
        assertThat(result.threatIntelligence()).isNull();
    }

    @Test
    void search_returnsMatchingThreatIntelligence() {
        ThreatIntelligence ti = createThreatIntelligence(1L, "http://evil.com", "URL", "Test Threat", "Family", "MALWARE", "HIGH", "HIGH");
        when(threatIntelRepo.findByIndicatorExact("http://evil.com")).thenReturn(List.of(ti));

        List<ThreatIntelligenceMatchingService.ThreatIntelligenceSearchResult> results = service.search("http://evil.com");

        assertThat(results).hasSize(1);
        assertThat(results.get(0).indicator()).isEqualTo("http://evil.com");
        assertThat(results.get(0).threatName()).isEqualTo("Test Threat");
    }

    @Test
    void clearMatches_deletesAllMatchesForScan() {
        ApkAnalysis analysis = createApkAnalysis(1L, 1L);
        IOC ioc1 = createIoc(1L, 1L, "http://evil.com", "URL");
        IOC ioc2 = createIoc(2L, 1L, "192.0.2.1", "IP");

        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));
        when(iocRepo.findByApkAnalysisId(1L)).thenReturn(List.of(ioc1, ioc2));
        doNothing().when(threatMatchRepo).deleteByIocId(anyLong());

        service.clearMatches(1L);

        verify(threatMatchRepo, times(2)).deleteByIocId(anyLong());
    }

    private ApkAnalysis createApkAnalysis(Long id, Long scanId) {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = id;
        return analysis;
    }

    private IOC createIoc(Long id, Long apkAnalysisId, String value, String type) {
        IOC ioc = new IOC();
        ioc.id = id;
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = apkAnalysisId;
        ioc.apkAnalysis = analysis;
        ioc.value = value;
        ioc.type = type;
        ioc.source = "STATIC_ANALYSIS";
        ioc.severity = "MEDIUM";
        ioc.confidence = "MEDIUM";
        ioc.description = "Test IOC";
        ioc.firstSeen = Instant.now();
        ioc.lastSeen = Instant.now();
        return ioc;
    }

    private ThreatIntelligence createThreatIntelligence(Long id, String indicator, String type, String threatName,
                                                        String threatFamily, String category, String severity, String confidence) {
        ThreatIntelligence ti = new ThreatIntelligence();
        ti.id = id;
        ti.indicator = indicator;
        ti.indicatorType = type;
        ti.threatName = threatName;
        ti.threatFamily = threatFamily;
        ti.category = category;
        ti.severity = severity;
        ti.confidence = confidence;
        ti.description = "Description";
        ti.source = "TEST";
        ti.tags = "tags";
        ti.firstSeen = Instant.now();
        ti.lastSeen = Instant.now();
        ti.active = true;
        ti.createdAt = Instant.now();
        ti.updatedAt = Instant.now();
        return ti;
    }

    private ThreatMatch createThreatMatch(Long id, IOC ioc, ThreatIntelligence ti, String matchType, String status,
                                          String confidence, String severity) {
        ThreatMatch tm = new ThreatMatch();
        tm.id = id;
        tm.ioc = ioc;
        tm.threatIntelligence = ti;
        tm.matchType = matchType;
        tm.status = status;
        tm.confidence = confidence;
        tm.severity = severity;
        tm.description = "Test match";
        tm.matchedAt = Instant.now();
        return tm;
    }
}