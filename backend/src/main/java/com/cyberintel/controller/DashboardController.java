package com.cyberintel.controller;

import com.cyberintel.dto.ScanHistoryDtos.DashboardStatsDto;
import com.cyberintel.service.ScanHistoryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/v1/dashboard", "/api/dashboard"})
public class DashboardController {

    private final ScanHistoryService scanHistoryService;

    public DashboardController(ScanHistoryService scanHistoryService) {
        this.scanHistoryService = scanHistoryService;
    }

    @GetMapping("/stats")
    public ResponseEntity<DashboardStatsDto> getDashboardStats() {
        DashboardStatsDto stats = scanHistoryService.getDashboardStats();
        return ResponseEntity.ok(stats);
    }
}
