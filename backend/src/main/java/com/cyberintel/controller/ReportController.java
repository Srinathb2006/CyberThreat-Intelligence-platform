package com.cyberintel.controller;

import com.cyberintel.service.ReportService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping({"/api/v1/reports", "/api/reports"})
public class ReportController {

    private final ReportService reportService;

    public ReportController(ReportService reportService) {
        this.reportService = reportService;
    }

    @GetMapping("/{scanId}/pdf")
    public ResponseEntity<byte[]> getPdfReport(@PathVariable Long scanId) {
        byte[] pdf = reportService.generatePdfReport(scanId);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"cyberintel-report-" + scanId + ".pdf\"")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdf);
    }

    @GetMapping("/{scanId}/json")
    public ResponseEntity<byte[]> getJsonReport(@PathVariable Long scanId) {
        byte[] json = reportService.generateJsonReport(scanId);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"cyberintel-report-" + scanId + ".json\"")
                .contentType(MediaType.APPLICATION_JSON)
                .body(json);
    }

    @GetMapping("/{scanId}/findings.csv")
    public ResponseEntity<byte[]> getFindingsCsv(@PathVariable Long scanId) {
        byte[] csv = reportService.generateFindingsCsv(scanId);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"findings-" + scanId + ".csv\"")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(csv);
    }

    @GetMapping("/{scanId}/iocs.csv")
    public ResponseEntity<byte[]> getIocCsv(@PathVariable Long scanId) {
        byte[] csv = reportService.generateIocCsv(scanId);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"iocs-" + scanId + ".csv\"")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(csv);
    }

    @GetMapping("/{scanId}/threat-matches.csv")
    public ResponseEntity<byte[]> getThreatMatchCsv(@PathVariable Long scanId) {
        byte[] csv = reportService.generateThreatMatchCsv(scanId);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"threat-matches-" + scanId + ".csv\"")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(csv);
    }

    @GetMapping("/{scanId}/summary.csv")
    public ResponseEntity<byte[]> getSummaryCsv(@PathVariable Long scanId) {
        byte[] csv = reportService.generateSummaryCsv(scanId);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"summary-" + scanId + ".csv\"")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(csv);
    }
}
