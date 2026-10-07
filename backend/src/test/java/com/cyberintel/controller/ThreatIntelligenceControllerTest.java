package com.cyberintel.controller;

import com.cyberintel.dto.ApkDtos.ImportResult;
import com.cyberintel.dto.ApkDtos.ThreatIntelligenceDto;
import com.cyberintel.dto.ApkDtos.ThreatIntelligenceSourceDto;
import com.cyberintel.entity.ThreatIntelligence;
import com.cyberintel.entity.ThreatIntelligenceSource;
import com.cyberintel.repository.ThreatIntelligenceRepository;
import com.cyberintel.repository.ThreatIntelligenceSourceRepository;
import com.cyberintel.repository.ThreatMatchRepository;
import com.cyberintel.service.ThreatIntelligenceMatchingService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ThreatIntelligenceControllerTest {

    @Mock
    private ThreatIntelligenceRepository threatIntelRepo;
    @Mock
    private ThreatIntelligenceSourceRepository sourceRepo;
    @Mock
    private ThreatMatchRepository threatMatchRepo;
    @Mock
    private ThreatIntelligenceMatchingService matchingService;

    private ThreatIntelligenceController controller;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        controller = new ThreatIntelligenceController(threatIntelRepo, sourceRepo, threatMatchRepo, matchingService);
    }

    @Test
    void getAll_returnsActiveThreatIntelligence() {
        ThreatIntelligence ti = createThreatIntelligence("http://evil.com", "URL", "Test Threat");
        when(threatIntelRepo.findByActiveTrue()).thenReturn(List.of(ti));

        ResponseEntity<List<ThreatIntelligenceDto>> response = controller.getAll(null, null, null, null);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).indicator()).isEqualTo("http://evil.com");
    }

    @Test
    void getAll_withTypeFilter_returnsFiltered() {
        ThreatIntelligence ti = createThreatIntelligence("evil.com", "DOMAIN", "Test Threat");
        when(threatIntelRepo.findByIndicatorType("DOMAIN")).thenReturn(List.of(ti));

        ResponseEntity<List<ThreatIntelligenceDto>> response = controller.getAll("DOMAIN", null, null, null);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).indicatorType()).isEqualTo("DOMAIN");
    }

    @Test
    void getById_returnsThreatIntelligence() {
        ThreatIntelligence ti = createThreatIntelligence("http://evil.com", "URL", "Test Threat");
        ti.id = 1L;
        when(threatIntelRepo.findById(1L)).thenReturn(Optional.of(ti));

        ResponseEntity<ThreatIntelligenceDto> response = controller.getById(1L);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody().id()).isEqualTo(1L);
    }

    @Test
    void search_returnsMatchingIndicators() {
        ThreatIntelligence ti = createThreatIntelligence("http://evil.com", "URL", "Test Threat");
        when(threatIntelRepo.findByIndicatorExact("http://evil.com")).thenReturn(List.of(ti));

        ResponseEntity<List<ThreatIntelligenceDto>> response = controller.search("http://evil.com");

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).hasSize(1);
    }

    @Test
    void getByType_returnsFilteredByType() {
        ThreatIntelligence ti = createThreatIntelligence("192.168.1.1", "IP", "Test Threat");
        when(threatIntelRepo.findByIndicatorType("IP")).thenReturn(List.of(ti));

        ResponseEntity<List<ThreatIntelligenceDto>> response = controller.getByType("IP");

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).indicatorType()).isEqualTo("IP");
    }

    @Test
    void create_savesNewThreatIntelligence() {
        ThreatIntelligenceDto dto = new ThreatIntelligenceDto(null, "http://new.com", "URL", "New Threat", "Family",
                "MALWARE", "HIGH", "HIGH", "Description", "SOURCE", "tags", null, null, true, null, null);
        when(threatIntelRepo.save(any(ThreatIntelligence.class))).thenAnswer(inv -> {
            ThreatIntelligence t = inv.getArgument(0);
            t.id = 1L;
            return t;
        });

        ResponseEntity<ThreatIntelligenceDto> response = controller.create(dto);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody().indicator()).isEqualTo("http://new.com");
        verify(threatIntelRepo).save(any(ThreatIntelligence.class));
    }

    @Test
    void update_modifiesExistingThreatIntelligence() {
        ThreatIntelligence existing = createThreatIntelligence("http://old.com", "URL", "Old Threat");
        existing.id = 1L;
        when(threatIntelRepo.findById(1L)).thenReturn(Optional.of(existing));
        when(threatIntelRepo.save(any(ThreatIntelligence.class))).thenAnswer(inv -> inv.getArgument(0));

        ThreatIntelligenceDto dto = new ThreatIntelligenceDto(null, "http://updated.com", "URL", "Updated Threat", "Family",
                "MALWARE", "HIGH", "HIGH", "Description", "SOURCE", "tags", null, null, true, null, null);

        ResponseEntity<ThreatIntelligenceDto> response = controller.update(1L, dto);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody().indicator()).isEqualTo("http://updated.com");
        assertThat(response.getBody().threatName()).isEqualTo("Updated Threat");
    }

    @Test
    void delete_removesThreatIntelligence() {
        doNothing().when(threatIntelRepo).deleteById(1L);

        ResponseEntity<Void> response = controller.delete(1L);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        verify(threatIntelRepo).deleteById(1L);
    }

    @Test
    void importCsv_importsValidRecords() {
        String csvContent = "indicator,indicatorType,threatName,threatFamily,category,severity,confidence,description,source,tags\n" +
                "http://imported.com,URL,Imported Threat,Family,MALWARE,HIGH,HIGH,Description,CSV_IMPORT,tag1";
        MockMultipartFile file = new MockMultipartFile("file", "test.csv", "text/csv", csvContent.getBytes());

        when(threatIntelRepo.findByIndicatorAndType("http://imported.com", "URL")).thenReturn(List.of());
        when(threatIntelRepo.save(any(ThreatIntelligence.class))).thenAnswer(inv -> {
            ThreatIntelligence t = inv.getArgument(0);
            t.id = 1L;
            return t;
        });

        ResponseEntity<ImportResult> response = controller.importCsv(file);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody().imported()).isEqualTo(1);
        assertThat(response.getBody().errors()).isEqualTo(0);
    }

    @Test
    void importCsv_updatesExistingRecords() {
        String csvContent = "indicator,indicatorType,threatName,threatFamily,category,severity,confidence,description,source,tags\n" +
                "http://existing.com,URL,Updated Threat,Family,MALWARE,HIGH,HIGH,Description,CSV_IMPORT,tag1";
        MockMultipartFile file = new MockMultipartFile("file", "test.csv", "text/csv", csvContent.getBytes());

        ThreatIntelligence existing = createThreatIntelligence("http://existing.com", "URL", "Old Threat");
        existing.id = 1L;
        when(threatIntelRepo.findByIndicatorAndType("http://existing.com", "URL")).thenReturn(List.of(existing));
        when(threatIntelRepo.save(any(ThreatIntelligence.class))).thenAnswer(inv -> inv.getArgument(0));

        ResponseEntity<ImportResult> response = controller.importCsv(file);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody().imported()).isEqualTo(1);
        verify(threatIntelRepo).save(any(ThreatIntelligence.class));
    }

    @Test
    void importCsv_rejectsInvalidEnumValues() {
        String csvContent = "indicator,indicatorType,threatName,threatFamily,category,severity,confidence,description,source,tags\n" +
                "http://bad.com,INVALID,Threat,Family,MALWARE,HIGH,HIGH,Description,CSV_IMPORT,tag1";
        MockMultipartFile file = new MockMultipartFile("file", "test.csv", "text/csv", csvContent.getBytes());

        ResponseEntity<ImportResult> response = controller.importCsv(file);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody().imported()).isEqualTo(0);
        assertThat(response.getBody().errors()).isEqualTo(1);
    }

    @Test
    void exportCsv_returnsCsvData() {
        ThreatIntelligence ti = createThreatIntelligence("http://export.com", "URL", "Export Threat");
        ti.id = 1L;
        when(threatIntelRepo.findByActiveTrue()).thenReturn(List.of(ti));

        ResponseEntity<byte[]> response = controller.exportCsv();

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getHeaders().getContentDisposition().toString()).contains("attachment");
        String csv = new String(response.getBody());
        assertThat(csv).contains("http://export.com");
        assertThat(csv).contains("Export Threat");
    }

    @Test
    void correlate_delegatesToMatchingService() {
        ThreatIntelligenceMatchingService.CorrelationResult mockResult =
            new ThreatIntelligenceMatchingService.CorrelationResult(1L, 10, 5, 5, 0, 2, 1, 1, 1,
                Set.of("MALWARE"), Set.of("Family"), List.of());
        when(matchingService.correlate(1L)).thenReturn(mockResult);

        ResponseEntity<ThreatIntelligenceMatchingService.CorrelationResult> response = controller.correlate(1L);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody().totalIocs()).isEqualTo(10);
        assertThat(response.getBody().matched()).isEqualTo(5);
    }

    @Test
    void getCorrelationSummary_delegatesToMatchingService() {
        ThreatIntelligenceMatchingService.CorrelationSummary mockSummary =
            new ThreatIntelligenceMatchingService.CorrelationSummary(1L, 10, 5, 5, 0, 2, 1, 1, 1,
                Set.of("MALWARE"), Set.of("Family"));
        when(matchingService.getCorrelationSummary(1L)).thenReturn(mockSummary);

        ResponseEntity<ThreatIntelligenceMatchingService.CorrelationSummary> response = controller.getCorrelationSummary(1L);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody().totalIocs()).isEqualTo(10);
        assertThat(response.getBody().matched()).isEqualTo(5);
    }

    @Test
    void getSources_returnsEnabledSources() {
        ThreatIntelligenceSource source = new ThreatIntelligenceSource();
        source.id = 1L;
        source.name = "Test Source";
        source.description = "Description";
        source.sourceType = "LOCAL";
        source.url = "http://source.com";
        source.enabled = true;
        source.createdAt = Instant.now();
        when(sourceRepo.findByEnabledTrue()).thenReturn(List.of(source));

        ResponseEntity<List<ThreatIntelligenceSourceDto>> response = controller.getSources();

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).name()).isEqualTo("Test Source");
    }

    @Test
    void createSource_savesNewSource() {
        ThreatIntelligenceSourceDto dto =
            new ThreatIntelligenceSourceDto(null, "New Source", "Description", "LOCAL", "http://new.com", true, null);
        when(sourceRepo.save(any(ThreatIntelligenceSource.class))).thenAnswer(inv -> {
            ThreatIntelligenceSource s = inv.getArgument(0);
            s.id = 1L;
            return s;
        });

        ResponseEntity<ThreatIntelligenceSourceDto> response = controller.createSource(dto);

        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody().name()).isEqualTo("New Source");
        verify(sourceRepo).save(any(ThreatIntelligenceSource.class));
    }

    private ThreatIntelligence createThreatIntelligence(String indicator, String type, String threatName) {
        ThreatIntelligence ti = new ThreatIntelligence();
        ti.indicator = indicator;
        ti.indicatorType = type;
        ti.threatName = threatName;
        ti.threatFamily = "Family";
        ti.category = "MALWARE";
        ti.severity = "HIGH";
        ti.confidence = "HIGH";
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
}