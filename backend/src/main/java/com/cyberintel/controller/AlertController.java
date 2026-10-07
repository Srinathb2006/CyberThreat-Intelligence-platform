package com.cyberintel.controller;

import com.cyberintel.dto.AlertDtos.*;
import com.cyberintel.entity.Alert;
import com.cyberintel.service.AlertService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping({"/api/v1/alerts", "/api/alerts"})
public class AlertController {

    private final AlertService alertService;

    public AlertController(AlertService alertService) {
        this.alertService = alertService;
    }

    @GetMapping
    public ResponseEntity<List<AlertDto>> getAlerts(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String search) {
        List<AlertDto> alerts = alertService.getAlerts(status, severity, search);
        return ResponseEntity.ok(alerts);
    }

    @GetMapping("/{id}")
    public ResponseEntity<AlertDto> getAlertById(@PathVariable Long id) {
        AlertDto alert = alertService.getAlertById(id);
        return ResponseEntity.ok(alert);
    }

    @PatchMapping("/{id}/status")
    public ResponseEntity<AlertDto> updateStatus(
            @PathVariable Long id,
            @RequestBody UpdateAlertStatusRequest request) {
        AlertDto updated = alertService.updateAlertStatus(id, request);
        return ResponseEntity.ok(updated);
    }

    @PostMapping("/{id}/resolve")
    public ResponseEntity<AlertDto> resolveAlert(
            @PathVariable Long id,
            @RequestBody(required = false) ResolveAlertRequest request) {
        AlertDto resolved = alertService.resolveAlert(id, request);
        return ResponseEntity.ok(resolved);
    }

    @GetMapping("/stats")
    public ResponseEntity<AlertStatsDto> getAlertStats() {
        AlertStatsDto stats = alertService.getAlertStats();
        return ResponseEntity.ok(stats);
    }

    @PostMapping("/generate/{scanId}")
    public ResponseEntity<List<AlertDto>> generateAlerts(@PathVariable Long scanId) {
        List<Alert> alerts = alertService.generateAlertsFromAssessment(scanId);
        return ResponseEntity.ok(alerts.stream().map(alertService::toDto).toList());
    }
}
