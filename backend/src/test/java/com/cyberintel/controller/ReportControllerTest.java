package com.cyberintel.controller;

import com.cyberintel.service.ReportService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ReportControllerTest {

    @Mock
    private ReportService reportService;

    private ReportController controller;

    @BeforeEach
    void setUp() {
        controller = new ReportController(reportService);
    }

    @Test
    @DisplayName("getPdfReport: returns PDF attachment")
    void getPdfReport_returnsPdf() {
        byte[] pdfData = "%PDF-1.4 test".getBytes(StandardCharsets.US_ASCII);
        when(reportService.generatePdfReport(100L)).thenReturn(pdfData);

        ResponseEntity<byte[]> response = controller.getPdfReport(100L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PDF);
        assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION)).contains("cyberintel-report-100.pdf");
        assertThat(response.getBody()).isEqualTo(pdfData);
    }

    @Test
    @DisplayName("getJsonReport: returns JSON attachment")
    void getJsonReport_returnsJson() {
        byte[] jsonData = "{\"reportTitle\":\"Test\"}".getBytes(StandardCharsets.UTF_8);
        when(reportService.generateJsonReport(100L)).thenReturn(jsonData);

        ResponseEntity<byte[]> response = controller.getJsonReport(100L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION)).contains("cyberintel-report-100.json");
        assertThat(response.getBody()).isEqualTo(jsonData);
    }

    @Test
    @DisplayName("getFindingsCsv: returns findings CSV attachment")
    void getFindingsCsv_returnsCsv() {
        byte[] csvData = "Category,Severity\nTEST,HIGH".getBytes(StandardCharsets.UTF_8);
        when(reportService.generateFindingsCsv(100L)).thenReturn(csvData);

        ResponseEntity<byte[]> response = controller.getFindingsCsv(100L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION)).contains("findings-100.csv");
        assertThat(response.getBody()).isEqualTo(csvData);
    }

    @Test
    @DisplayName("getIocCsv: returns IOC CSV attachment")
    void getIocCsv_returnsCsv() {
        byte[] csvData = "Type,Value\nIP,1.2.3.4".getBytes(StandardCharsets.UTF_8);
        when(reportService.generateIocCsv(100L)).thenReturn(csvData);

        ResponseEntity<byte[]> response = controller.getIocCsv(100L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION)).contains("iocs-100.csv");
    }

    @Test
    @DisplayName("getThreatMatchCsv: returns ThreatMatch CSV attachment")
    void getThreatMatchCsv_returnsCsv() {
        byte[] csvData = "Indicator,ThreatName\nevil.com,Trojan".getBytes(StandardCharsets.UTF_8);
        when(reportService.generateThreatMatchCsv(100L)).thenReturn(csvData);

        ResponseEntity<byte[]> response = controller.getThreatMatchCsv(100L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION)).contains("threat-matches-100.csv");
    }

    @Test
    @DisplayName("getSummaryCsv: returns summary CSV attachment")
    void getSummaryCsv_returnsCsv() {
        byte[] csvData = "Metric,Value\nScan ID,100".getBytes(StandardCharsets.UTF_8);
        when(reportService.generateSummaryCsv(100L)).thenReturn(csvData);

        ResponseEntity<byte[]> response = controller.getSummaryCsv(100L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION)).contains("summary-100.csv");
    }
}
