package com.cyberintel.controller;

import com.cyberintel.dto.ApkDtos.StaticAnalysisSummary;
import com.cyberintel.entity.ApkAnalysis;
import com.cyberintel.entity.IOC;
import com.cyberintel.entity.MalwareFinding;
import com.cyberintel.repository.ApkAnalysisRepository;
import com.cyberintel.repository.IocRepository;
import com.cyberintel.repository.MalwareFindingRepository;
import com.cyberintel.service.IocExtractionService;
import com.cyberintel.service.StaticMalwareAnalysisService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class StaticAnalysisControllerTest {

    @Mock StaticMalwareAnalysisService malwareService;
    @Mock IocExtractionService iocService;
    @Mock ApkAnalysisRepository analysisRepo;
    @Mock MalwareFindingRepository malwareRepo;
    @Mock IocRepository iocRepo;

    @InjectMocks StaticAnalysisController controller;

    @Test
    void runAnalysis_whenScanNotFound_throwsException() {
        when(analysisRepo.findByScanId(999L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.runAnalysis(999L, false))
            .isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void runAnalysis_callsServicesAndReturnsSummary() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));

        StaticAnalysisSummary expected = new StaticAnalysisSummary(5, 0, 2, 2, 1, 10, 1, 2);
        when(malwareService.analyze(eq(1L), any(), eq(false))).thenReturn(expected);

        ResponseEntity<StaticAnalysisSummary> response = controller.runAnalysis(1L, false);

        assertThat(response.getStatusCodeValue()).isEqualTo(200);
        assertThat(response.getBody()).isEqualTo(expected);
        verify(malwareService).analyze(eq(1L), any(), eq(false));
        verify(iocService).extractAndStore(eq(1L), any(), eq(false));
    }

    @Test
    void runAnalysis_withMockFlag_passesToServices() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));
        when(malwareService.analyze(anyLong(), any(), anyBoolean())).thenReturn(new StaticAnalysisSummary(0,0,0,0,0,0,0,0));

        controller.runAnalysis(1L, true);

        verify(malwareService).analyze(eq(1L), any(), eq(true));
        verify(iocService).extractAndStore(eq(1L), any(), eq(true));
    }

    @Test
    void getSummary_returnsSummary() {
        when(malwareService.getSummary(1L)).thenReturn(new StaticAnalysisSummary(3, 0, 1, 1, 1, 5, 1, 2));

        ResponseEntity<StaticAnalysisSummary> response = controller.getSummary(1L);

        assertThat(response.getStatusCodeValue()).isEqualTo(200);
        assertThat(response.getBody().totalFindings()).isEqualTo(3);
    }

    @Test
    void getFindings_returnsMappedDtos() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));

        MalwareFinding mf1 = new MalwareFinding();
        mf1.id = 1L; mf1.category = "TEST_CAT"; mf1.title = "Test Finding"; mf1.description = "Desc"; mf1.evidence = "Evidence";
        mf1.severity = "HIGH"; mf1.confidence = "MEDIUM"; mf1.source = "API_CALL"; mf1.ruleId = "RULE_1"; mf1.createdAt = java.time.Instant.now();

        MalwareFinding mf2 = new MalwareFinding();
        mf2.id = 2L; mf2.category = "TEST_CAT2"; mf2.title = "Test Finding 2"; mf2.description = "Desc2"; mf2.evidence = "Evidence2";
        mf2.severity = "LOW"; mf2.confidence = "LOW"; mf2.source = "PERMISSION"; mf2.ruleId = "RULE_2"; mf2.createdAt = java.time.Instant.now();

        when(malwareRepo.findByApkAnalysisId(1L)).thenReturn(List.of(mf1, mf2));

        ResponseEntity<List<StaticAnalysisController.MalwareFindingDto>> response = controller.getFindings(1L, null, null);

        assertThat(response.getStatusCodeValue()).isEqualTo(200);
        assertThat(response.getBody()).hasSize(2);
        assertThat(response.getBody().get(0).category()).isEqualTo("TEST_CAT");
        assertThat(response.getBody().get(0).severity()).isEqualTo("HIGH");
    }

    @Test
    void getFindings_filtersByCategory() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));

        MalwareFinding mf1 = new MalwareFinding();
        mf1.id = 1L; mf1.category = "SMS_ACTIVITY"; mf1.title = "SMS"; mf1.description = "Desc"; mf1.evidence = "Evidence";
        mf1.severity = "HIGH"; mf1.confidence = "MEDIUM"; mf1.source = "PERMISSION"; mf1.ruleId = "RULE_1"; mf1.createdAt = java.time.Instant.now();

        MalwareFinding mf2 = new MalwareFinding();
        mf2.id = 2L; mf2.category = "NETWORK_ACTIVITY"; mf2.title = "Network"; mf2.description = "Desc"; mf2.evidence = "Evidence";
        mf2.severity = "LOW"; mf2.confidence = "LOW"; mf2.source = "API_CALL"; mf2.ruleId = "RULE_2"; mf2.createdAt = java.time.Instant.now();

        when(malwareRepo.findByApkAnalysisId(1L)).thenReturn(List.of(mf1, mf2));

        ResponseEntity<List<StaticAnalysisController.MalwareFindingDto>> response = controller.getFindings(1L, "SMS_ACTIVITY", null);

        assertThat(response.getStatusCodeValue()).isEqualTo(200);
        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).category()).isEqualTo("SMS_ACTIVITY");
    }

    @Test
    void getFindings_filtersBySeverity() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));

        MalwareFinding mf1 = new MalwareFinding();
        mf1.id = 1L; mf1.category = "TEST"; mf1.title = "High"; mf1.description = "Desc"; mf1.evidence = "Evidence";
        mf1.severity = "HIGH"; mf1.confidence = "MEDIUM"; mf1.source = "PERMISSION"; mf1.ruleId = "RULE_1"; mf1.createdAt = java.time.Instant.now();

        MalwareFinding mf2 = new MalwareFinding();
        mf2.id = 2L; mf2.category = "TEST"; mf2.title = "Low"; mf2.description = "Desc"; mf2.evidence = "Evidence";
        mf2.severity = "LOW"; mf2.confidence = "LOW"; mf2.source = "PERMISSION"; mf2.ruleId = "RULE_2"; mf2.createdAt = java.time.Instant.now();

        when(malwareRepo.findByApkAnalysisId(1L)).thenReturn(List.of(mf1, mf2));

        ResponseEntity<List<StaticAnalysisController.MalwareFindingDto>> response = controller.getFindings(1L, null, "HIGH");

        assertThat(response.getStatusCodeValue()).isEqualTo(200);
        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).severity()).isEqualTo("HIGH");
    }

    @Test
    void getIocs_returnsMappedDtos() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));

        IOC ioc1 = new IOC();
        ioc1.id = 1L; ioc1.value = "example.com"; ioc1.type = "DOMAIN"; ioc1.source = "JADX";
        ioc1.severity = "LOW"; ioc1.confidence = "MEDIUM"; ioc1.description = "Test"; ioc1.firstSeen = java.time.Instant.now(); ioc1.lastSeen = java.time.Instant.now(); ioc1.createdAt = java.time.Instant.now();

        IOC ioc2 = new IOC();
        ioc2.id = 2L; ioc2.value = "https://test.com"; ioc2.type = "URL"; ioc2.source = "JADX";
        ioc2.severity = "HIGH"; ioc2.confidence = "HIGH"; ioc2.description = "Test2"; ioc2.firstSeen = java.time.Instant.now(); ioc2.lastSeen = java.time.Instant.now(); ioc2.createdAt = java.time.Instant.now();

        when(iocRepo.findByApkAnalysisId(1L)).thenReturn(List.of(ioc1, ioc2));

        ResponseEntity<List<StaticAnalysisController.IOCDto>> response = controller.getIocs(1L, null, null);

        assertThat(response.getStatusCodeValue()).isEqualTo(200);
        assertThat(response.getBody()).hasSize(2);
        assertThat(response.getBody().get(0).type()).isEqualTo("DOMAIN");
        assertThat(response.getBody().get(0).value()).isEqualTo("example.com");
    }

    @Test
    void getIocs_filtersByType() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));

        IOC ioc1 = new IOC();
        ioc1.id = 1L; ioc1.value = "example.com"; ioc1.type = "DOMAIN"; ioc1.source = "JADX";
        ioc1.severity = "LOW"; ioc1.confidence = "MEDIUM"; ioc1.description = "Test"; ioc1.firstSeen = java.time.Instant.now(); ioc1.lastSeen = java.time.Instant.now(); ioc1.createdAt = java.time.Instant.now();

        IOC ioc2 = new IOC();
        ioc2.id = 2L; ioc2.value = "https://test.com"; ioc2.type = "URL"; ioc2.source = "JADX";
        ioc2.severity = "HIGH"; ioc2.confidence = "HIGH"; ioc2.description = "Test2"; ioc2.firstSeen = java.time.Instant.now(); ioc2.lastSeen = java.time.Instant.now(); ioc2.createdAt = java.time.Instant.now();

        when(iocRepo.findByApkAnalysisId(1L)).thenReturn(List.of(ioc1, ioc2));

        ResponseEntity<List<StaticAnalysisController.IOCDto>> response = controller.getIocs(1L, "URL", null);

        assertThat(response.getStatusCodeValue()).isEqualTo(200);
        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).type()).isEqualTo("URL");
    }

    @Test
    void getIocCountsByType_returnsGroupedCounts() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));

        IOC ioc1 = new IOC(); ioc1.type = "URL";
        IOC ioc2 = new IOC(); ioc2.type = "URL";
        IOC ioc3 = new IOC(); ioc3.type = "DOMAIN";
        IOC ioc4 = new IOC(); ioc4.type = "IP";

        when(iocRepo.findByApkAnalysisId(1L)).thenReturn(List.of(ioc1, ioc2, ioc3, ioc4));

        ResponseEntity<Map<String, Long>> response = controller.getIocCountsByType(1L);

        assertThat(response.getStatusCodeValue()).isEqualTo(200);
        assertThat(response.getBody().get("URL")).isEqualTo(2);
        assertThat(response.getBody().get("DOMAIN")).isEqualTo(1);
        assertThat(response.getBody().get("IP")).isEqualTo(1);
    }

    @Test
    void getFindingCountsByCategory_returnsGroupedCounts() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));

        MalwareFinding mf1 = new MalwareFinding(); mf1.category = "SMS_ACTIVITY";
        MalwareFinding mf2 = new MalwareFinding(); mf2.category = "SMS_ACTIVITY";
        MalwareFinding mf3 = new MalwareFinding(); mf3.category = "NETWORK_ACTIVITY";

        when(malwareRepo.findByApkAnalysisId(1L)).thenReturn(List.of(mf1, mf2, mf3));

        ResponseEntity<Map<String, Long>> response = controller.getFindingCountsByCategory(1L);

        assertThat(response.getStatusCodeValue()).isEqualTo(200);
        assertThat(response.getBody().get("SMS_ACTIVITY")).isEqualTo(2);
        assertThat(response.getBody().get("NETWORK_ACTIVITY")).isEqualTo(1);
    }
}