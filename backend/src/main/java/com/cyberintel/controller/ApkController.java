package com.cyberintel.controller;
import com.cyberintel.dto.ApkDtos.*;
import com.cyberintel.service.*;
import com.cyberintel.config.AnalysisProperties;
import java.security.Principal;
import java.util.*;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
@RestController @RequestMapping("/api")
public class ApkController {
 private final ApkUploadService upload;private final ApkAnalysisState state;private final ApkAnalysisOrchestrator orchestrator;private final AnalysisProperties config;private final AnalysisProcessRunner runner;
 public ApkController(ApkUploadService upload,ApkAnalysisState state,ApkAnalysisOrchestrator orchestrator,AnalysisProperties config,AnalysisProcessRunner runner){this.upload=upload;this.state=state;this.orchestrator=orchestrator;this.config=config;this.runner=runner;}
 @GetMapping("/apk/config") public Map<String,Object> config(){
  Map<String,Object> tools=new LinkedHashMap<>();
  for(String name:List.of("jadx","apktool","aapt")){var tool=config.getTools().get(name);tools.put(name,Map.of("available",runner.available(name),"enabled",tool!=null&&tool.isEnabled()));}
  return Map.of("maxApkSize",config.getMaxApkSize().toBytes(),"tools",tools);
 }
 @PostMapping(value="/apk/upload",consumes=MediaType.MULTIPART_FORM_DATA_VALUE) @ResponseStatus(HttpStatus.CREATED)
 public UploadResponse upload(@RequestPart("file") MultipartFile file,Principal principal){return upload.upload(file,principal.getName());}
 @GetMapping("/apk-analysis") public List<Result> history(Principal p){return state.history(p.getName());}
 @GetMapping("/apk-analysis/{id}") public Result get(@PathVariable long id,Principal p){return state.get(id,p.getName());}
 @PostMapping("/apk-analysis/{id}/start") @ResponseStatus(HttpStatus.ACCEPTED) public Result start(@PathVariable long id,Principal p){return orchestrator.start(id,p.getName());}
 @PostMapping("/apk-analysis/{id}/cancel") public Result cancel(@PathVariable long id,Principal p){return orchestrator.cancel(id,p.getName());}
}
