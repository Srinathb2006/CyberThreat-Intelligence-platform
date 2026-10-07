package com.cyberintel.controller;

import com.cyberintel.dto.ScanHistoryDtos.ScanHistoryItemDto;
import com.cyberintel.service.ScanHistoryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ScanHistoryControllerTest {

    @Mock
    private ScanHistoryService scanHistoryService;

    private ScanHistoryController controller;

    private ScanHistoryItemDto sampleItem;

    @BeforeEach
    void setUp() {
        controller = new ScanHistoryController(scanHistoryService);

        sampleItem = new ScanHistoryItemDto(
                100L, "APK", "finance.apk", "finance.apk", 1048576L,
                "com.sample.finance", "Finance App", "sha256hash",
                "COMPLETED", 78, "CRITICAL", 5L, 3L, 2L, 1L,
                Instant.now(), Instant.now()
        );
    }

    @Test
    @DisplayName("getScanHistory: returns list of scan history items")
    void getScanHistory_returnsList() {
        when(scanHistoryService.getScanHistory(null, null, null, null)).thenReturn(List.of(sampleItem));

        ResponseEntity<List<ScanHistoryItemDto>> response = controller.getScanHistory(null, null, null, null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).id()).isEqualTo(100L);
        verify(scanHistoryService).getScanHistory(null, null, null, null);
    }

    @Test
    @DisplayName("getScanHistoryById: returns single scan history item")
    void getScanHistoryById_returnsItem() {
        when(scanHistoryService.getScanHistoryById(100L)).thenReturn(sampleItem);

        ResponseEntity<ScanHistoryItemDto> response = controller.getScanHistoryById(100L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().applicationName()).isEqualTo("Finance App");
        verify(scanHistoryService).getScanHistoryById(100L);
    }
}
