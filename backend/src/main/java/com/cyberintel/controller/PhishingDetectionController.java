package com.cyberintel.controller;

import com.cyberintel.dto.PhishingDtos.*;
import com.cyberintel.service.PhishingDetectionService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/phishing")
public class PhishingDetectionController {
    private final PhishingDetectionService service;
    public PhishingDetectionController(PhishingDetectionService service) { this.service = service; }
    @PostMapping("/analyze")
    public Result analyze(@Valid @RequestBody Request request) { return service.analyze(request.url()); }
}
