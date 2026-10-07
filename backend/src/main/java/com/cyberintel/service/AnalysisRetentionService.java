package com.cyberintel.service;
import com.cyberintel.config.AnalysisRuntimeProperties;
import com.cyberintel.repository.ApkAnalysisRepository;
import com.cyberintel.entity.Scan;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.slf4j.*;
@Service
public class AnalysisRetentionService {
 private static final Logger log=LoggerFactory.getLogger(AnalysisRetentionService.class);
 private final ApkAnalysisRepository repository;private final AnalysisStorage storage;private final ApkAnalysisState state;private final AnalysisRuntimeProperties config;
 public AnalysisRetentionService(ApkAnalysisRepository repository,AnalysisStorage storage,ApkAnalysisState state,AnalysisRuntimeProperties config){this.repository=repository;this.storage=storage;this.state=state;this.config=config;}
 @Scheduled(fixedDelay=3600000,initialDelay=60000) @Transactional
 public void cleanExpired(){
  for(var candidate:repository.findByCreatedAtBeforeAndArtifactsRetainedTrue(Instant.now().minus(config.getRetentionDays(),ChronoUnit.DAYS))){
   var value=repository.lockByScanId(candidate.scan.getId()).orElseThrow();
   if(value.scan.getStatus()==Scan.Status.RUNNING || value.scan.getStatus()==Scan.Status.QUEUED)continue;
   // Cancellation is visible immediately; allow a grace period for process termination.
   if(value.completedAt!=null && value.completedAt.isAfter(Instant.now().minusSeconds(60)))continue;
   try{storage.deleteArtifacts(value.scan.getId(),value.storageKey);state.expireArtifacts(value.scan.getId());}
   catch(Exception e){log.warn("Retention cleanup failed for scan {}",value.scan.getId());}
  }
 }
}
