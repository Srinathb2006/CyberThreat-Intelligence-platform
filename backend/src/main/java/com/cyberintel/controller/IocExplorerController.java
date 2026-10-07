package com.cyberintel.controller;

import com.cyberintel.dto.IocExplorerDtos;
import com.cyberintel.service.IocExplorerService;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/api/ioc-explorer")
public class IocExplorerController {
    private final IocExplorerService service;
    public IocExplorerController(IocExplorerService service) { this.service = service; }

    @GetMapping
    public List<IocExplorerDtos.Ioc> search(Principal principal,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) String type,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String confidence,
            @RequestParam(required = false) Long scanId) {
        return service.search(principal.getName(), search, type, severity, confidence, scanId);
    }

    @GetMapping("/{iocId}")
    public IocExplorerDtos.Ioc get(@PathVariable Long iocId, Principal principal) {
        return service.get(iocId, principal.getName());
    }
}
