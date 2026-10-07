package com.cyberintel.controller;

import com.cyberintel.dto.AlertDtos.*;
import com.cyberintel.entity.Alert;
import com.cyberintel.entity.Scan;
import com.cyberintel.entity.User;
import com.cyberintel.service.AlertService;
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
class AlertControllerTest {

    @Mock
    private AlertService alertService;

    private AlertController controller;

    private AlertDto sampleAlertDto;
    private AlertStatsDto sampleStatsDto;

    @BeforeEach
    void setUp() {
        controller = new AlertController(alertService);

        sampleAlertDto = new AlertDto(
                1L, 100L, "sample.apk", "Critical Threat Detected",
                "Malware matched known banking trojan", "CRITICAL", "NEW",
                "Scanner", "MALWARE", null, null, null,
                Instant.now(), Instant.now()
        );

        sampleStatsDto = new AlertStatsDto(
                10L, 4L, 2L, 4L, 2L, 4L, 3L, 1L
        );
    }

    @Test
    @DisplayName("getAlerts: returns list of alerts")
    void getAlerts_returnsList() {
        when(alertService.getAlerts(null, null, null)).thenReturn(List.of(sampleAlertDto));

        ResponseEntity<List<AlertDto>> response = controller.getAlerts(null, null, null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).title()).isEqualTo("Critical Threat Detected");
        verify(alertService).getAlerts(null, null, null);
    }

    @Test
    @DisplayName("getAlertById: returns alert detail")
    void getAlertById_returnsDetail() {
        when(alertService.getAlertById(1L)).thenReturn(sampleAlertDto);

        ResponseEntity<AlertDto> response = controller.getAlertById(1L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().id()).isEqualTo(1L);
        verify(alertService).getAlertById(1L);
    }

    @Test
    @DisplayName("updateStatus: updates alert status")
    void updateStatus_updatesAndReturns() {
        UpdateAlertStatusRequest req = new UpdateAlertStatusRequest("INVESTIGATING", "Investigating");
        AlertDto updated = new AlertDto(
                1L, 100L, "sample.apk", "Critical Threat Detected",
                "Malware matched known banking trojan", "CRITICAL", "INVESTIGATING",
                "Scanner", "MALWARE", "Investigating", null, null,
                Instant.now(), Instant.now()
        );
        when(alertService.updateAlertStatus(1L, req)).thenReturn(updated);

        ResponseEntity<AlertDto> response = controller.updateStatus(1L, req);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().status()).isEqualTo("INVESTIGATING");
        verify(alertService).updateAlertStatus(1L, req);
    }

    @Test
    @DisplayName("resolveAlert: resolves alert and returns updated DTO")
    void resolveAlert_resolvesAndReturns() {
        ResolveAlertRequest req = new ResolveAlertRequest("Resolved", "Lead Analyst");
        AlertDto resolved = new AlertDto(
                1L, 100L, "sample.apk", "Critical Threat Detected",
                "Malware matched known banking trojan", "CRITICAL", "RESOLVED",
                "Scanner", "MALWARE", "Resolved", "Lead Analyst", Instant.now(),
                Instant.now(), Instant.now()
        );
        when(alertService.resolveAlert(1L, req)).thenReturn(resolved);

        ResponseEntity<AlertDto> response = controller.resolveAlert(1L, req);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().status()).isEqualTo("RESOLVED");
        verify(alertService).resolveAlert(1L, req);
    }

    @Test
    @DisplayName("getAlertStats: returns alert statistics")
    void getAlertStats_returnsStats() {
        when(alertService.getAlertStats()).thenReturn(sampleStatsDto);

        ResponseEntity<AlertStatsDto> response = controller.getAlertStats();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().total()).isEqualTo(10L);
        verify(alertService).getAlertStats();
    }
}
