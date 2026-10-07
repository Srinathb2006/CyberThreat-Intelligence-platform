package com.cyberintel.controller;

import com.cyberintel.dto.ApkDtos.*;
import com.cyberintel.service.RiskCorrelationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RiskCorrelationControllerTest {

    @Mock
    private RiskCorrelationService riskCorrelationService;

    private RiskCorrelationController controller;

    private RiskBreakdownDto sampleBreakdown;
    private RiskAssessmentResult sampleAssessmentResult;
    private List<RiskIndicatorDto> sampleIndicators;
    private List<RiskRecommendationDto> sampleRecommendations;

    @BeforeEach
    void setUp() {
        controller = new RiskCorrelationController(riskCorrelationService);

        sampleBreakdown = new RiskBreakdownDto(
                25.0, 30.0, 15.0, 10.0, 10.0, 5.0, 3.0, 2.0, 100.0
        );

        sampleIndicators = List.of(
                new RiskIndicatorDto(1L, "malware_finding", 101L, "MALWARE_FINDING",
                        "Trojan detected", "CRITICAL", "HIGH", 25.0, "trojan.dex", Instant.now())
        );

        sampleRecommendations = List.of(
                new RiskRecommendationDto("THREAT_INTELLIGENCE", "Quarantine the APK and investigate the associated threat intelligence indicators.")
        );

        sampleAssessmentResult = new RiskAssessmentResult(
                10L, 1L, 85.5, "CRITICAL", "HIGH",
                "High risk application detected", sampleBreakdown,
                sampleIndicators, sampleRecommendations, Instant.now()
        );
    }

    @Test
    void calculateRisk_delegatesToServiceAndReturnsResult() {
        Long scanId = 1L;
        when(riskCorrelationService.calculateRisk(scanId)).thenReturn(sampleAssessmentResult);

        ResponseEntity<RiskAssessmentResult> response = controller.calculateRisk(scanId);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().id()).isEqualTo(10L);
        assertThat(response.getBody().scanId()).isEqualTo(1L);
        assertThat(response.getBody().score()).isEqualTo(85.5);
        assertThat(response.getBody().riskLevel()).isEqualTo("CRITICAL");
        assertThat(response.getBody().breakdown()).isEqualTo(sampleBreakdown);
        assertThat(response.getBody().indicators()).hasSize(1);
        assertThat(response.getBody().recommendations()).hasSize(1);

        verify(riskCorrelationService, times(1)).calculateRisk(scanId);
    }

    @Test
    void calculateRisk_whenAnalysisNotFound_propagatesException() {
        Long scanId = 999L;
        when(riskCorrelationService.calculateRisk(scanId))
                .thenThrow(new IllegalArgumentException("APK analysis not found for scanId: 999"));

        assertThatThrownBy(() -> controller.calculateRisk(scanId))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("APK analysis not found for scanId: 999");

        verify(riskCorrelationService, times(1)).calculateRisk(scanId);
    }

    @Test
    void getLatestRisk_delegatesToServiceAndReturnsResult() {
        Long scanId = 1L;
        when(riskCorrelationService.getLatestRisk(scanId)).thenReturn(sampleAssessmentResult);

        ResponseEntity<RiskAssessmentResult> response = controller.getLatestRisk(scanId);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().id()).isEqualTo(10L);
        assertThat(response.getBody().score()).isEqualTo(85.5);
        assertThat(response.getBody().riskLevel()).isEqualTo("CRITICAL");

        verify(riskCorrelationService, times(1)).getLatestRisk(scanId);
    }

    @Test
    void getLatestRisk_whenNotFound_propagatesException() {
        Long scanId = 999L;
        when(riskCorrelationService.getLatestRisk(scanId))
                .thenThrow(new IllegalArgumentException("No risk assessment found for scanId: 999"));

        assertThatThrownBy(() -> controller.getLatestRisk(scanId))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No risk assessment found for scanId: 999");

        verify(riskCorrelationService, times(1)).getLatestRisk(scanId);
    }

    @Test
    void getIndicators_delegatesToServiceAndReturnsList() {
        Long scanId = 1L;
        when(riskCorrelationService.getIndicators(scanId)).thenReturn(sampleIndicators);

        ResponseEntity<List<RiskIndicatorDto>> response = controller.getIndicators(scanId);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).category()).isEqualTo("MALWARE_FINDING");
        assertThat(response.getBody().get(0).contribution()).isEqualTo(25.0);

        verify(riskCorrelationService, times(1)).getIndicators(scanId);
    }

    @Test
    void getIndicators_whenNotFound_propagatesException() {
        Long scanId = 999L;
        when(riskCorrelationService.getIndicators(scanId))
                .thenThrow(new IllegalArgumentException("No risk assessment found for scanId: 999"));

        assertThatThrownBy(() -> controller.getIndicators(scanId))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No risk assessment found for scanId: 999");

        verify(riskCorrelationService, times(1)).getIndicators(scanId);
    }

    @Test
    void getBreakdown_delegatesToServiceAndReturnsBreakdown() {
        Long scanId = 1L;
        when(riskCorrelationService.getBreakdown(scanId)).thenReturn(sampleBreakdown);

        ResponseEntity<RiskBreakdownDto> response = controller.getBreakdown(scanId);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().staticFindings()).isEqualTo(25.0);
        assertThat(response.getBody().threatIntelligence()).isEqualTo(30.0);
        assertThat(response.getBody().apiCalls()).isEqualTo(15.0);
        assertThat(response.getBody().permissions()).isEqualTo(10.0);
        assertThat(response.getBody().iocs()).isEqualTo(10.0);
        assertThat(response.getBody().urls()).isEqualTo(5.0);
        assertThat(response.getBody().components()).isEqualTo(3.0);
        assertThat(response.getBody().obfuscationNative()).isEqualTo(2.0);
        assertThat(response.getBody().total()).isEqualTo(100.0);

        verify(riskCorrelationService, times(1)).getBreakdown(scanId);
    }

    @Test
    void getBreakdown_whenNotFound_propagatesException() {
        Long scanId = 999L;
        when(riskCorrelationService.getBreakdown(scanId))
                .thenThrow(new IllegalArgumentException("No risk assessment found for scanId: 999"));

        assertThatThrownBy(() -> controller.getBreakdown(scanId))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No risk assessment found for scanId: 999");

        verify(riskCorrelationService, times(1)).getBreakdown(scanId);
    }

    @Test
    void getRecommendations_delegatesToServiceAndReturnsList() {
        Long scanId = 1L;
        when(riskCorrelationService.getRecommendations(scanId)).thenReturn(sampleRecommendations);

        ResponseEntity<List<RiskRecommendationDto>> response = controller.getRecommendations(scanId);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody()).hasSize(1);
        assertThat(response.getBody().get(0).category()).isEqualTo("THREAT_INTELLIGENCE");
        assertThat(response.getBody().get(0).recommendation()).contains("Quarantine the APK");

        verify(riskCorrelationService, times(1)).getRecommendations(scanId);
    }

    @Test
    void getRecommendations_whenNotFound_propagatesException() {
        Long scanId = 999L;
        when(riskCorrelationService.getRecommendations(scanId))
                .thenThrow(new IllegalArgumentException("No risk assessment found for scanId: 999"));

        assertThatThrownBy(() -> controller.getRecommendations(scanId))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No risk assessment found for scanId: 999");

        verify(riskCorrelationService, times(1)).getRecommendations(scanId);
    }
}
