package com.cyberintel.service;

import com.cyberintel.dto.ApkDtos.Api;
import com.cyberintel.dto.ApkDtos.Component;
import com.cyberintel.dto.ApkDtos.Findings;
import com.cyberintel.dto.ApkDtos.Metadata;
import com.cyberintel.dto.ApkDtos.Permission;
import com.cyberintel.dto.ApkDtos.Text;
import com.cyberintel.entity.ApkAnalysis;
import com.cyberintel.entity.IOC;
import com.cyberintel.repository.ApkAnalysisRepository;
import com.cyberintel.repository.IocRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IocExtractionServiceTest {

    @Mock IocRepository iocRepo;
    @Mock ApkAnalysisRepository analysisRepo;
    @Captor ArgumentCaptor<List<IOC>> listCaptor;

    @InjectMocks IocExtractionService service;

    @Test
    void extractAndStore_whenScanNotFound_throwsException() {
        when(analysisRepo.findByScanId(999L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.extractAndStore(999L, new Findings(), false))
            .isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void extractAndStore_deletesExistingIocs() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));
        when(iocRepo.saveAll(any())).thenReturn(new ArrayList<>());

        Findings findings = new Findings();
        findings.metadata = new Metadata("com.test.app", "Test App", "1.0", "1", "21", "30");
        findings.strings = List.of();
        findings.permissions = List.of();
        findings.components = List.of();
        findings.apis = List.of();

        List<IOC> result = service.extractAndStore(1L, findings, false);

        verify(iocRepo).deleteByApkAnalysisId(1L);
        verify(iocRepo).saveAll(any());
    }

    @Test
    void extractAndStore_extractsPackageFromMetadata() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));
        when(iocRepo.saveAll(any())).thenAnswer(inv -> inv.getArgument(0));

        Findings findings = new Findings();
        findings.metadata = new Metadata("com.test.myapp", "Test App", "1.0", "1", "21", "30");

        List<IOC> result = service.extractAndStore(1L, findings, false);

        verify(iocRepo).saveAll(listCaptor.capture());
        assertThat(listCaptor.getValue()).anyMatch(i -> "PACKAGE".equals(i.type) && "com.test.myapp".equals(i.value));
    }

    @Test
    void extractAndStore_extractsUrlsFromStrings() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));
        when(iocRepo.saveAll(any())).thenAnswer(inv -> inv.getArgument(0));

        Findings findings = new Findings();
        findings.strings = List.of(
            new Text("https://example.com/api", "URL", "JADX"),
            new Text("http://malicious.com/download.apk", "URL", "JADX")
        );

        List<IOC> result = service.extractAndStore(1L, findings, false);

        verify(iocRepo).saveAll(listCaptor.capture());
        List<IOC> saved = listCaptor.getValue();
        assertThat(saved).hasSize(2);
        assertThat(saved).allMatch(i -> "URL".equals(i.type));
    }

    @Test
    void extractAndStore_extractsDomainsFromStrings() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));
        when(iocRepo.saveAll(any())).thenAnswer(inv -> inv.getArgument(0));

        Findings findings = new Findings();
        findings.strings = List.of(
            new Text("example.com", "DOMAIN", "JADX"),
            new Text("sub.domain.org", "DOMAIN", "JADX")
        );

        List<IOC> result = service.extractAndStore(1L, findings, false);

        verify(iocRepo).saveAll(listCaptor.capture());
        assertThat(listCaptor.getValue()).allMatch(i -> "DOMAIN".equals(i.type));
    }

    @Test
    void extractAndStore_extractsIpsFromStrings() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));
        when(iocRepo.saveAll(any())).thenAnswer(inv -> inv.getArgument(0));

        Findings findings = new Findings();
        findings.strings = List.of(
            new Text("192.168.1.1", "IP", "JADX"),
            new Text("10.0.0.1", "IP", "JADX")
        );

        List<IOC> result = service.extractAndStore(1L, findings, false);

        verify(iocRepo).saveAll(listCaptor.capture());
        assertThat(listCaptor.getValue()).allMatch(i -> "IP".equals(i.type));
    }

    @Test
    void extractAndStore_extractsHashesFromStrings() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));
        when(iocRepo.saveAll(any())).thenAnswer(inv -> inv.getArgument(0));

        Findings findings = new Findings();
        findings.strings = List.of(
            new Text("abcdef1234567890abcdef1234567890abcdef12", "HASH", "JADX"),
            new Text("0123456789abcdef0123456789abcdef", "HASH", "JADX")
        );

        List<IOC> result = service.extractAndStore(1L, findings, false);

        verify(iocRepo).saveAll(listCaptor.capture());
        assertThat(listCaptor.getValue()).allMatch(i -> "HASH".equals(i.type));
    }

    @Test
    void extractAndStore_extractsApisFromPermissionAndComponents() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));
        when(iocRepo.saveAll(any())).thenAnswer(inv -> inv.getArgument(0));

        Findings findings = new Findings();
        findings.permissions = List.of(new Permission("android.permission.INTERNET", "PERMISSION", "LOW", "Internet"));
        findings.components = List.of(new Component("ACTIVITY", "com.test.MainActivity", false, null, "LOW"));
        findings.apis = List.of(new Api("java.lang.Runtime", "exec", "Runtime.exec", "EXECUTION", "HIGH", "Executes commands"));

        List<IOC> result = service.extractAndStore(1L, findings, false);

        verify(iocRepo).saveAll(listCaptor.capture());
        List<IOC> saved = listCaptor.getValue();
        assertThat(saved).anyMatch(i -> "API".equals(i.type) && i.value.contains("INTERNET"));
        assertThat(saved).anyMatch(i -> "API".equals(i.type) && i.value.contains("MainActivity"));
        assertThat(saved).anyMatch(i -> "API".equals(i.type) && i.value.contains("Runtime.exec"));
    }

    @Test
    void extractAndStore_deduplicatesIocs() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));
        when(iocRepo.saveAll(any())).thenAnswer(inv -> inv.getArgument(0));

        Findings findings = new Findings();
        findings.strings = List.of(
            new Text("https://example.com/api", "URL", "JADX"),
            new Text("https://example.com/api", "URL", "APKTOOL")
        );

        List<IOC> result = service.extractAndStore(1L, findings, false);

        verify(iocRepo).saveAll(listCaptor.capture());
        assertThat(listCaptor.getValue()).hasSize(1);
    }

    @Test
    void extractAndStore_setsSeverityForMaliciousUrls() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));
        when(iocRepo.saveAll(any())).thenAnswer(inv -> inv.getArgument(0));

        Findings findings = new Findings();
        findings.strings = List.of(new Text("http://192.168.1.1/login.apk", "URL", "JADX"));

        List<IOC> result = service.extractAndStore(1L, findings, false);

        verify(iocRepo).saveAll(listCaptor.capture());
        assertThat(listCaptor.getValue()).anyMatch(i -> "HIGH".equals(i.severity));
    }

    @Test
    void getAllIocs_returnsIocs() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));

        IOC ioc1 = new IOC();
        ioc1.value = "example.com";
        ioc1.type = "DOMAIN";
        IOC ioc2 = new IOC();
        ioc2.value = "https://test.com";
        ioc2.type = "URL";

        when(iocRepo.findByApkAnalysisId(1L)).thenReturn(List.of(ioc1, ioc2));

        List<IOC> result = service.getAllIocs(1L);

        assertThat(result).hasSize(2);
    }

    @Test
    void getIocsByType_returnsFilteredIocs() {
        ApkAnalysis analysis = new ApkAnalysis();
        analysis.id = 1L;
        when(analysisRepo.findByScanId(1L)).thenReturn(Optional.of(analysis));

        IOC ioc = new IOC();
        ioc.value = "example.com";
        ioc.type = "DOMAIN";

        when(iocRepo.findByApkAnalysisIdAndType(1L, "DOMAIN")).thenReturn(List.of(ioc));

        List<IOC> result = service.getIocsByType(1L, "DOMAIN");

        assertThat(result).hasSize(1);
        assertThat(result.get(0).type).isEqualTo("DOMAIN");
    }
}