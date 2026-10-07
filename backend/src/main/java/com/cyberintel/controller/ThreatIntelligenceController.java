package com.cyberintel.controller;

import com.cyberintel.dto.ApkDtos;
import com.cyberintel.entity.ThreatIntelligence;
import com.cyberintel.entity.ThreatIntelligenceSource;
import com.cyberintel.repository.ThreatIntelligenceRepository;
import com.cyberintel.repository.ThreatIntelligenceSourceRepository;
import com.cyberintel.repository.ThreatMatchRepository;
import com.cyberintel.service.ThreatIntelligenceMatchingService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.*;
import java.time.Instant;
import java.util.*;
import java.util.stream.*;

@RestController
@RequestMapping({"/api/v1/threat-intelligence", "/api/threat-intelligence"})
public class ThreatIntelligenceController {
 private final ThreatIntelligenceRepository threatIntelRepo;
 private final ThreatIntelligenceSourceRepository sourceRepo;
 private final ThreatMatchRepository threatMatchRepo;
 private final ThreatIntelligenceMatchingService matchingService;

 public ThreatIntelligenceController(ThreatIntelligenceRepository threatIntelRepo,
                                     ThreatIntelligenceSourceRepository sourceRepo,
                                     ThreatMatchRepository threatMatchRepo,
                                     ThreatIntelligenceMatchingService matchingService) {
  this.threatIntelRepo = threatIntelRepo;
  this.sourceRepo = sourceRepo;
  this.threatMatchRepo = threatMatchRepo;
  this.matchingService = matchingService;
 }

 @GetMapping
 public ResponseEntity<List<ApkDtos.ThreatIntelligenceDto>> getAll(@RequestParam(required = false) String type,
                                                            @RequestParam(required = false) String severity,
                                                            @RequestParam(required = false) String category,
                                                            @RequestParam(required = false) String source) {
  List<ThreatIntelligence> results;
  if (type != null) {
   results = threatIntelRepo.findByIndicatorType(type);
  } else if (severity != null) {
   results = threatIntelRepo.findBySeverity(severity);
  } else if (category != null) {
   results = threatIntelRepo.findByCategory(category);
  } else if (source != null) {
   results = threatIntelRepo.findBySource(source);
  } else {
   results = threatIntelRepo.findByActiveTrue();
  }
  return ResponseEntity.ok(results.stream().map(this::toDto).toList());
 }

 @GetMapping("/{id}")
 public ResponseEntity<ApkDtos.ThreatIntelligenceDto> getById(@PathVariable Long id) {
  ThreatIntelligence ti = threatIntelRepo.findById(id).orElseThrow();
  return ResponseEntity.ok(toDto(ti));
 }

 @GetMapping("/search")
 public ResponseEntity<List<ApkDtos.ThreatIntelligenceDto>> search(@RequestParam String indicator) {
  List<ThreatIntelligence> results = threatIntelRepo.findByIndicatorExact(indicator);
  return ResponseEntity.ok(results.stream().map(this::toDto).toList());
 }

 @GetMapping("/type/{type}")
 public ResponseEntity<List<ApkDtos.ThreatIntelligenceDto>> getByType(@PathVariable String type) {
  List<ThreatIntelligence> results = threatIntelRepo.findByIndicatorType(type);
  return ResponseEntity.ok(results.stream().map(this::toDto).toList());
 }

 @PostMapping
 @PreAuthorize("hasRole('ADMIN')")
 public ResponseEntity<ApkDtos.ThreatIntelligenceDto> create(@RequestBody ApkDtos.ThreatIntelligenceDto dto) {
  ThreatIntelligence ti = new ThreatIntelligence();
  updateEntityFromDto(ti, dto);
  ti.createdAt = Instant.now();
  ti.updatedAt = Instant.now();
  ThreatIntelligence saved = threatIntelRepo.save(ti);
  return ResponseEntity.ok(toDto(saved));
 }

 @PutMapping("/{id}")
 @PreAuthorize("hasRole('ADMIN')")
 public ResponseEntity<ApkDtos.ThreatIntelligenceDto> update(@PathVariable Long id, @RequestBody ApkDtos.ThreatIntelligenceDto dto) {
  ThreatIntelligence ti = threatIntelRepo.findById(id).orElseThrow();
  updateEntityFromDto(ti, dto);
  ti.updatedAt = Instant.now();
  ThreatIntelligence saved = threatIntelRepo.save(ti);
  return ResponseEntity.ok(toDto(saved));
 }

 @DeleteMapping("/{id}")
 @PreAuthorize("hasRole('ADMIN')")
 public ResponseEntity<Void> delete(@PathVariable Long id) {
  threatIntelRepo.deleteById(id);
  return ResponseEntity.noContent().build();
 }

 @PostMapping("/import")
 @PreAuthorize("hasRole('ADMIN')")
 public ResponseEntity<ApkDtos.ImportResult> importCsv(@RequestParam("file") MultipartFile file) {
  try (BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream()))) {
   String header = reader.readLine();
   if (header == null) {
    return ResponseEntity.badRequest().body(new ApkDtos.ImportResult(0, 0, List.of("Empty file")));
   }

   List<String> errors = new ArrayList<>();
   int imported = 0;
   int lineNum = 1;

   String line;
   while ((line = reader.readLine()) != null) {
    lineNum++;
    try {
     String[] fields = parseCsvLine(line);
     if (fields.length < 8) {
      errors.add("Line " + lineNum + ": Insufficient fields");
      continue;
     }
     String indicator = fields[0].trim();
     String indicatorType = fields[1].trim().toUpperCase();
     String threatName = fields[2].trim();
     String threatFamily = fields[3].trim();
     String category = fields[4].trim().toUpperCase();
     String severity = fields[5].trim().toUpperCase();
     String confidence = fields[6].trim().toUpperCase();
     String description = fields[7].trim();
     String source = fields.length > 8 ? fields[8].trim() : "CSV_IMPORT";
     String tags = fields.length > 9 ? fields[9].trim() : "";

     if (!isValidIndicatorType(indicatorType) || !isValidSeverity(severity) || !isValidConfidence(confidence)) {
      errors.add("Line " + lineNum + ": Invalid enum values");
      continue;
     }

     Optional<ThreatIntelligence> existing = threatIntelRepo.findByIndicatorAndType(indicator, indicatorType).stream().findFirst();
     if (existing.isPresent()) {
      ThreatIntelligence ti = existing.get();
      ti.threatName = threatName;
      ti.threatFamily = threatFamily;
      ti.category = category;
      ti.severity = severity;
      ti.confidence = confidence;
      ti.description = description;
      ti.source = source;
      ti.tags = tags;
      ti.updatedAt = Instant.now();
      threatIntelRepo.save(ti);
     } else {
      ThreatIntelligence ti = new ThreatIntelligence();
      ti.indicator = indicator;
      ti.indicatorType = indicatorType;
      ti.threatName = threatName;
      ti.threatFamily = threatFamily;
      ti.category = category;
      ti.severity = severity;
      ti.confidence = confidence;
      ti.description = description;
      ti.source = source;
      ti.tags = tags;
      ti.createdAt = Instant.now();
      ti.updatedAt = Instant.now();
      threatIntelRepo.save(ti);
     }
     imported++;
    } catch (Exception e) {
     errors.add("Line " + lineNum + ": " + e.getMessage());
    }
   }

   return ResponseEntity.ok(new ApkDtos.ImportResult(imported, errors.size(), errors));
  } catch (IOException e) {
   return ResponseEntity.badRequest().body(new ApkDtos.ImportResult(0, 1, List.of("Failed to read file: " + e.getMessage())));
  }
 }

 @GetMapping("/export")
 public ResponseEntity<byte[]> exportCsv() {
  List<ThreatIntelligence> all = threatIntelRepo.findByActiveTrue();
  StringBuilder csv = new StringBuilder();
  csv.append("indicator,indicatorType,threatName,threatFamily,category,severity,confidence,description,source,tags\n");
  for (ThreatIntelligence ti : all) {
   csv.append(escapeCsv(ti.indicator)).append(',')
    .append(escapeCsv(ti.indicatorType)).append(',')
    .append(escapeCsv(ti.threatName)).append(',')
    .append(escapeCsv(ti.threatFamily)).append(',')
    .append(escapeCsv(ti.category)).append(',')
    .append(escapeCsv(ti.severity)).append(',')
    .append(escapeCsv(ti.confidence)).append(',')
    .append(escapeCsv(ti.description)).append(',')
    .append(escapeCsv(ti.source)).append(',')
    .append(escapeCsv(ti.tags)).append('\n');
  }
  byte[] data = csv.toString().getBytes();
  return ResponseEntity.ok()
   .header("Content-Disposition", "attachment; filename=threat-intelligence-export.csv")
   .header("Content-Type", "text/csv")
   .body(data);
 }

 @PostMapping("/correlate/{scanId}")
 public ResponseEntity<ThreatIntelligenceMatchingService.CorrelationResult> correlate(@PathVariable Long scanId) {
  ThreatIntelligenceMatchingService.CorrelationResult result = matchingService.correlate(scanId);
  return ResponseEntity.ok(result);
 }

 @GetMapping("/correlate/{scanId}/summary")
 public ResponseEntity<ThreatIntelligenceMatchingService.CorrelationSummary> getCorrelationSummary(@PathVariable Long scanId) {
  ThreatIntelligenceMatchingService.CorrelationSummary summary = matchingService.getCorrelationSummary(scanId);
  return ResponseEntity.ok(summary);
 }

 @GetMapping("/sources")
 public ResponseEntity<List<ApkDtos.ThreatIntelligenceSourceDto>> getSources() {
  List<ThreatIntelligenceSource> sources = sourceRepo.findByEnabledTrue();
  return ResponseEntity.ok(sources.stream().map(this::toSourceDto).toList());
 }

 @PostMapping("/sources")
 @PreAuthorize("hasRole('ADMIN')")
 public ResponseEntity<ApkDtos.ThreatIntelligenceSourceDto> createSource(@RequestBody ApkDtos.ThreatIntelligenceSourceDto dto) {
  ThreatIntelligenceSource source = new ThreatIntelligenceSource();
  source.name = dto.name();
  source.description = dto.description();
  source.sourceType = dto.sourceType();
  source.url = dto.url();
  source.enabled = dto.enabled();
  source.createdAt = Instant.now();
  ThreatIntelligenceSource saved = sourceRepo.save(source);
  return ResponseEntity.ok(toSourceDto(saved));
 }

 private void updateEntityFromDto(ThreatIntelligence ti, ApkDtos.ThreatIntelligenceDto dto) {
  ti.indicator = dto.indicator();
  ti.indicatorType = dto.indicatorType();
  ti.threatName = dto.threatName();
  ti.threatFamily = dto.threatFamily();
  ti.category = dto.category();
  ti.severity = dto.severity();
  ti.confidence = dto.confidence();
  ti.description = dto.description();
  ti.source = dto.source();
  ti.tags = dto.tags();
 }

 private ApkDtos.ThreatIntelligenceDto toDto(ThreatIntelligence ti) {
  return new ApkDtos.ThreatIntelligenceDto(ti.id, ti.indicator, ti.indicatorType,
   ti.threatName, ti.threatFamily, ti.category, ti.severity,
   ti.confidence, ti.description, ti.source, ti.tags,
   ti.firstSeen, ti.lastSeen, ti.active, ti.createdAt, ti.updatedAt);
 }

 private ApkDtos.ThreatIntelligenceSourceDto toSourceDto(ThreatIntelligenceSource s) {
  return new ApkDtos.ThreatIntelligenceSourceDto(s.id, s.name, s.description, s.sourceType, s.url, s.enabled, s.createdAt);
 }

 private String[] parseCsvLine(String line) {
  List<String> fields = new ArrayList<>();
  StringBuilder current = new StringBuilder();
  boolean inQuotes = false;
  for (int i = 0; i < line.length(); i++) {
   char c = line.charAt(i);
   if (c == '"') {
    inQuotes = !inQuotes;
   } else if (c == ',' && !inQuotes) {
    fields.add(current.toString());
    current = new StringBuilder();
   } else {
    current.append(c);
   }
  }
  fields.add(current.toString());
  return fields.toArray(new String[0]);
 }

 private String escapeCsv(String value) {
  if (value == null) return "";
  if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
   return "\"" + value.replace("\"", "\"\"") + "\"";
  }
  return value;
 }

 private boolean isValidIndicatorType(String type) {
  return Set.of("URL", "DOMAIN", "IP", "HASH", "PACKAGE", "API", "STRING").contains(type);
 }

 private boolean isValidSeverity(String severity) {
  return Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL").contains(severity);
 }

 private boolean isValidConfidence(String confidence) {
  return Set.of("LOW", "MEDIUM", "HIGH").contains(confidence);
 }
}