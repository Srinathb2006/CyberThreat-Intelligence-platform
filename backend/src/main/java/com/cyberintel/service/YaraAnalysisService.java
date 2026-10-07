package com.cyberintel.service;

import com.cyberintel.entity.*;
import com.cyberintel.exception.ApiException;
import com.cyberintel.repository.*;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.io.IOException;
import java.util.List;

@Service
public class YaraAnalysisService {
 public record MatchDto(String ruleName,String severity,String description,String evidence) {}
 public record Result(String mode,String status,String message,List<MatchDto> matches) {}
 private final ApkAnalysisRepository analyses;
 private final YaraScanRepository scans;
 private final YaraAnalyzerService yara;
 private final MockAnalysisFactory demo;
 public YaraAnalysisService(ApkAnalysisRepository analyses,YaraScanRepository scans,YaraAnalyzerService yara,MockAnalysisFactory demo){this.analyses=analyses;this.scans=scans;this.yara=yara;this.demo=demo;}
 private ApkAnalysis owned(long scanId,String email){
  var analysis=analyses.findByScanId(scanId).orElseThrow(()->new ApiException(HttpStatus.NOT_FOUND,"APK scan not found."));
  if(!analysis.scan.getUser().getEmail().equals(email))throw new ApiException(HttpStatus.NOT_FOUND,"APK scan not found.");
  return analysis;
 }
 @Transactional(readOnly=true) public Result get(long scanId,String email){
  ApkAnalysis analysis=owned(scanId,email);
  return scans.findByAnalysisId(analysis.id).map(this::dto).orElse(new Result("NOT_RUN","NOT_RUN","Run YARA analysis to inspect extracted files.",List.of()));
 }
 @Transactional public Result run(long scanId,String email){
  ApkAnalysis analysis=owned(scanId,email);
  if(analysis.scan.getStatus()!=Scan.Status.COMPLETED)throw new ApiException(HttpStatus.CONFLICT,"Complete APK analysis before running YARA.");
  if(!analysis.artifactsRetained && yara.available())throw new ApiException(HttpStatus.CONFLICT,"Extracted files have expired. Upload the APK again.");
  YaraAnalyzerService.Outcome outcome;
  if(!yara.available())outcome=demoOutcome(analysis.sha256);
  else try{outcome=yara.analyze(scanId);}catch(IOException e){outcome=new YaraAnalyzerService.Outcome("FAILED","Local YARA scan could not read extracted files.",List.of());}
  if(outcome.status().equals("UNAVAILABLE"))outcome=demoOutcome(analysis.sha256);
  String mode=outcome.status().equals("DEMO")?"DEMO":"LOCAL";
  YaraScan scan=scans.findByAnalysisId(analysis.id).orElseGet(YaraScan::new);
  scan.analysis=analysis;scan.mode=mode;scan.status=outcome.status();scan.message=outcome.message();scan.scannedAt=java.time.Instant.now();scan.matches.clear();
  for(var found:outcome.matches()){
   YaraMatch match=new YaraMatch();match.scan=scan;match.ruleName=found.ruleName();match.severity=found.severity();match.description=found.description();match.evidence=found.evidence();scan.matches.add(match);
  }
  return dto(scans.saveAndFlush(scan));
 }
 private YaraAnalyzerService.Outcome demoOutcome(String hash){
  String marker=demo.create(hash).metadata.packageName();
  return new YaraAnalyzerService.Outcome("DEMO","DEMO / MOCK YARA ANALYSIS: local YARA or rules are unavailable. This is synthetic sample data, not a match from the APK.",
   List.of(new YaraAnalyzerService.Match("DEMO_SAMPLE_RULE","LOW","Synthetic demonstration rule. No YARA rule was executed.","DEMO: "+marker)));
 }
 private Result dto(YaraScan scan){return new Result(scan.mode,scan.status,scan.message,scan.matches.stream().map(m->new MatchDto(m.ruleName,m.severity,m.description,m.evidence)).toList());}
}
