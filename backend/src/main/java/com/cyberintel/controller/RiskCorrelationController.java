package com.cyberintel.controller;

import com.cyberintel.dto.ApkDtos;
import com.cyberintel.service.RiskCorrelationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;


@RestController
@RequestMapping({"/api/v1/risk-correlation", "/api/risk-correlation"})
public class RiskCorrelationController {

    private final RiskCorrelationService riskCorrelationService;

    public RiskCorrelationController(RiskCorrelationService riskCorrelationService) {
        this.riskCorrelationService = riskCorrelationService;
    }

    @PostMapping("/{scanId}/calculate")
    public ResponseEntity<ApkDtos.RiskAssessmentResult> calculateRisk(@PathVariable Long scanId) {
        ApkDtos.RiskAssessmentResult result = riskCorrelationService.calculateRisk(scanId);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/{scanId}")
    public ResponseEntity<ApkDtos.RiskAssessmentResult> getLatestRisk(@PathVariable Long scanId) {
        ApkDtos.RiskAssessmentResult result = riskCorrelationService.getLatestRisk(scanId);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/{scanId}/indicators")
    public ResponseEntity<List<ApkDtos.RiskIndicatorDto>> getIndicators(@PathVariable Long scanId) {
        List<ApkDtos.RiskIndicatorDto> indicators = riskCorrelationService.getIndicators(scanId);
        return ResponseEntity.ok(indicators);
    }

    @GetMapping("/{scanId}/breakdown")
    public ResponseEntity<ApkDtos.RiskBreakdownDto> getBreakdown(@PathVariable Long scanId) {
        ApkDtos.RiskBreakdownDto breakdown = riskCorrelationService.getBreakdown(scanId);
        return ResponseEntity.ok(breakdown);
    }

    @GetMapping("/{scanId}/recommendations")
    public ResponseEntity<List<ApkDtos.RiskRecommendationDto>> getRecommendations(@PathVariable Long scanId) {
        List<ApkDtos.RiskRecommendationDto> recommendations = riskCorrelationService.getRecommendations(scanId);
        return ResponseEntity.ok(recommendations);
    }
}