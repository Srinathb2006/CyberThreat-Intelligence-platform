package com.cyberintel.controller;
import com.cyberintel.service.AnalysisToolService;
import java.util.*;
import org.springframework.web.bind.annotation.*;
@RestController @RequestMapping("/api")
public class PlatformController {
 private final List<AnalysisToolService> tools;
 public PlatformController(List<AnalysisToolService> tools){this.tools=tools;}
 @GetMapping("/platform/status") public Map<String,String> status(){return Map.of("status","ready","stage","reverse-engineering","analysis","static APK inspection");}
 @GetMapping("/admin/tools") public List<ToolStatus> tools(){return tools.stream().map(t->new ToolStatus(t.toolName(),t.enabled(),t instanceof com.cyberintel.service.StaticToolAnalyzer analyzer?(analyzer.available()?"AVAILABLE":"UNAVAILABLE"):"NOT_IMPLEMENTED")).toList();}
 public record ToolStatus(String name,boolean enabled,String status){}
}
