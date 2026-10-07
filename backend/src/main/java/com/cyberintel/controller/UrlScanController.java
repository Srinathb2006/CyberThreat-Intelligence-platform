package com.cyberintel.controller;

import com.cyberintel.dto.UrlScanDtos.*;
import com.cyberintel.service.UrlScanService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/api/url-scans")
public class UrlScanController {
    private final UrlScanService service;
    public UrlScanController(UrlScanService service) { this.service = service; }
    @PostMapping @ResponseStatus(HttpStatus.CREATED)
    public Result create(@Valid @RequestBody Request request, Principal principal) {
        return service.create(request.url(), principal.getName());
    }
    @GetMapping
    public List<Result> history(Principal principal) { return service.history(principal.getName()); }
    @GetMapping("/{scanId}")
    public Result get(@PathVariable Long scanId, Principal principal) { return service.get(scanId, principal.getName()); }
}
