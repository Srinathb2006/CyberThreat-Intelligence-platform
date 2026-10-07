package com.cyberintel.controller;

import com.cyberintel.dto.ScanHistoryDtos.ScanHistoryItemDto;
import com.cyberintel.service.ScanHistoryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping({"/api/v1/scan-history", "/api/scan-history"})
public class ScanHistoryController {

    private final ScanHistoryService scanHistoryService;

    public ScanHistoryController(ScanHistoryService scanHistoryService) {
        this.scanHistoryService = scanHistoryService;
    }

    @GetMapping
    public ResponseEntity<List<ScanHistoryItemDto>> getScanHistory(
            @RequestParam(required = false) String search,
            @RequestParam(required = false) String packageName,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String riskLevel) {
        List<ScanHistoryItemDto> history = scanHistoryService.getScanHistory(search, packageName, status, riskLevel);
        return ResponseEntity.ok(history);
    }

    @GetMapping("/{scanId}")
    public ResponseEntity<ScanHistoryItemDto> getScanHistoryById(@PathVariable Long scanId) {
        ScanHistoryItemDto item = scanHistoryService.getScanHistoryById(scanId);
        return ResponseEntity.ok(item);
    }
}
