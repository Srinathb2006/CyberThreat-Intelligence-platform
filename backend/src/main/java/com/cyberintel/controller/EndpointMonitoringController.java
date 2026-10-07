package com.cyberintel.controller;

import com.cyberintel.dto.EndpointDtos;
import com.cyberintel.service.EndpointMonitoringService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/api/endpoints")
public class EndpointMonitoringController {
    private final EndpointMonitoringService service;
    public EndpointMonitoringController(EndpointMonitoringService service) { this.service = service; }
    @PostMapping @ResponseStatus(HttpStatus.CREATED)
    public EndpointDtos.Endpoint register(@Valid @RequestBody EndpointDtos.RegisterRequest request, Principal principal) { return service.register(request, principal.getName()); }
    @GetMapping public List<EndpointDtos.Endpoint> list(Principal principal) { return service.list(principal.getName()); }
    @GetMapping("/{id}") public EndpointDtos.EndpointDetail detail(@PathVariable Long id, Principal principal,
            @RequestParam(defaultValue = "false") boolean suspiciousOnly) { return service.detail(id, principal.getName(), suspiciousOnly); }
    @GetMapping("/{id}/events") public List<EndpointDtos.Event> events(@PathVariable Long id, Principal principal,
            @RequestParam(defaultValue = "false") boolean suspiciousOnly) { return service.eventList(id, principal.getName(), suspiciousOnly); }
}
