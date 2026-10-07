package com.cyberintel.controller;

import com.cyberintel.dto.ApkDtos.Findings;
import com.cyberintel.dto.ApkDtos.Metadata;
import com.cyberintel.dto.ApkDtos.Permission;
import com.cyberintel.dto.ApkDtos.Component;
import com.cyberintel.dto.ApkDtos.Api;
import com.cyberintel.dto.ApkDtos.Text;
import com.cyberintel.dto.ApkDtos.StaticAnalysisSummary;
import com.cyberintel.entity.ApkAnalysis;
import com.cyberintel.entity.MalwareFinding;
import com.cyberintel.entity.IOC;
import com.cyberintel.repository.ApkAnalysisRepository;
import com.cyberintel.repository.MalwareFindingRepository;
import com.cyberintel.repository.IocRepository;
import com.cyberintel.service.StaticMalwareAnalysisService;
import com.cyberintel.service.IocExtractionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.*;
import java.util.stream.*;

@RestController
@RequestMapping({"/api/v1/static-analysis", "/api/static-analysis"})
public class StaticAnalysisController {
 private final StaticMalwareAnalysisService malwareService;
 private final IocExtractionService iocService;
 private final ApkAnalysisRepository analysisRepo;
 private final MalwareFindingRepository malwareRepo;
 private final IocRepository iocRepo;

 public StaticAnalysisController(StaticMalwareAnalysisService malwareService, IocExtractionService iocService,
                                 ApkAnalysisRepository analysisRepo, MalwareFindingRepository malwareRepo,
                                 IocRepository iocRepo) {
  this.malwareService = malwareService;
  this.iocService = iocService;
  this.analysisRepo = analysisRepo;
  this.malwareRepo = malwareRepo;
  this.iocRepo = iocRepo;
 }

 @PostMapping("/{scanId}")
 public ResponseEntity<StaticAnalysisSummary> runAnalysis(@PathVariable Long scanId,
                                                          @RequestParam(defaultValue = "false") boolean mock) {
  var analysis = analysisRepo.findByScanId(scanId).orElseThrow();
  Findings findings = buildFindingsFromAnalysis(analysis);
  StaticAnalysisSummary summary = malwareService.analyze(scanId, findings, mock);
  iocService.extractAndStore(scanId, findings, mock);
  return ResponseEntity.ok(summary);
 }

 @GetMapping("/{scanId}/summary")
 public ResponseEntity<StaticAnalysisSummary> getSummary(@PathVariable Long scanId) {
  return ResponseEntity.ok(malwareService.getSummary(scanId));
 }

 @GetMapping("/{scanId}/findings")
 public ResponseEntity<List<MalwareFindingDto>> getFindings(@PathVariable Long scanId,
                                                            @RequestParam(required = false) String category,
                                                            @RequestParam(required = false) String severity) {
  var analysis = analysisRepo.findByScanId(scanId).orElseThrow();
  List<MalwareFinding> findings = malwareRepo.findByApkAnalysisId(analysis.id);

  if (category != null) {
   findings = findings.stream().filter(f -> f.category != null && f.category.equalsIgnoreCase(category)).toList();
  }
  if (severity != null) {
   findings = findings.stream().filter(f -> f.severity != null && f.severity.equalsIgnoreCase(severity)).toList();
  }

  return ResponseEntity.ok(findings.stream().map(this::toDto).toList());
 }

 @GetMapping("/{scanId}/iocs")
 public ResponseEntity<List<IOCDto>> getIocs(@PathVariable Long scanId,
                                             @RequestParam(required = false) String type,
                                             @RequestParam(required = false) String severity) {
  var analysis = analysisRepo.findByScanId(scanId).orElseThrow();
  List<IOC> iocs = iocRepo.findByApkAnalysisId(analysis.id);

  if (type != null) {
   iocs = iocs.stream().filter(i -> i.type != null && i.type.equalsIgnoreCase(type)).toList();
  }
  if (severity != null) {
   iocs = iocs.stream().filter(i -> i.severity != null && i.severity.equalsIgnoreCase(severity)).toList();
  }

  return ResponseEntity.ok(iocs.stream().map(this::toDto).toList());
 }

 @GetMapping("/{scanId}/iocs/by-type")
 public ResponseEntity<Map<String, Long>> getIocCountsByType(@PathVariable Long scanId) {
  var analysis = analysisRepo.findByScanId(scanId).orElseThrow();
  List<IOC> iocs = iocRepo.findByApkAnalysisId(analysis.id);
  Map<String, Long> counts = iocs.stream().collect(Collectors.groupingBy(i -> i.type != null ? i.type : "UNKNOWN", Collectors.counting()));
  return ResponseEntity.ok(counts);
 }

 @GetMapping("/{scanId}/findings/by-category")
 public ResponseEntity<Map<String, Long>> getFindingCountsByCategory(@PathVariable Long scanId) {
  var analysis = analysisRepo.findByScanId(scanId).orElseThrow();
  List<MalwareFinding> findings = malwareRepo.findByApkAnalysisId(analysis.id);
  Map<String, Long> counts = findings.stream().collect(Collectors.groupingBy(f -> f.category != null ? f.category : "UNKNOWN", Collectors.counting()));
  return ResponseEntity.ok(counts);
 }

 private Findings buildFindingsFromAnalysis(ApkAnalysis analysis) {
  Findings findings = new Findings();
  findings.metadata = new Metadata(
   analysis.packageName,
   analysis.applicationName,
   analysis.versionName,
   analysis.versionCode,
   analysis.minSdk,
   analysis.targetSdk
  );

  if (analysis.permissions != null) {
   findings.permissions = analysis.permissions.stream()
    .map(p -> new Permission(p.permissionName, p.category, p.severity, p.description))
    .toList();
  }

  if (analysis.components != null) {
   findings.components = analysis.components.stream()
    .map(c -> new Component(c.componentType, c.componentName, c.exported, c.permission, c.severity))
    .toList();
  }

  if (analysis.apiFindings != null) {
   findings.apis = analysis.apiFindings.stream()
    .map(a -> new Api(a.className, a.methodName, a.apiName, a.category, a.severity, a.description))
    .toList();
  }

  if (analysis.strings != null) {
   findings.strings = analysis.strings.stream()
    .map(s -> new Text(s.value, s.kind, s.source))
    .toList();
  }

  return findings;
 }

 private MalwareFindingDto toDto(MalwareFinding mf) {
  return new MalwareFindingDto(mf.id, mf.category, mf.title, mf.description,
   mf.evidence, mf.severity, mf.confidence, mf.source, mf.ruleId, mf.createdAt);
 }

 private IOCDto toDto(IOC ioc) {
  return new IOCDto(ioc.id, ioc.value, ioc.type, ioc.source,
   ioc.severity, ioc.confidence, ioc.description, ioc.firstSeen, ioc.lastSeen, ioc.createdAt);
 }

 public record MalwareFindingDto(Long id, String category, String title, String description, String evidence,
                                 String severity, String confidence, String source, String ruleId, java.time.Instant createdAt) {}
 public record IOCDto(Long id, String value, String type, String source, String severity, String confidence,
                      String description, java.time.Instant firstSeen, java.time.Instant lastSeen, java.time.Instant createdAt) {}
}