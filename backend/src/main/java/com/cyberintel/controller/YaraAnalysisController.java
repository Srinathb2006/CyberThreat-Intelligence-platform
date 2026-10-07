package com.cyberintel.controller;

import com.cyberintel.service.YaraAnalysisService;
import java.security.Principal;
import org.springframework.web.bind.annotation.*;

@RestController @RequestMapping("/api/apk-analysis/{scanId}/yara")
public class YaraAnalysisController {
 private final YaraAnalysisService service;
 public YaraAnalysisController(YaraAnalysisService service){this.service=service;}
 @GetMapping public YaraAnalysisService.Result get(@PathVariable long scanId,Principal principal){return service.get(scanId,principal.getName());}
 @PostMapping public YaraAnalysisService.Result run(@PathVariable long scanId,Principal principal){return service.run(scanId,principal.getName());}
}
