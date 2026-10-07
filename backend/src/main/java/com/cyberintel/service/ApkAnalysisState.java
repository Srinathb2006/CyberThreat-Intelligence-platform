package com.cyberintel.service;
import com.cyberintel.dto.ApkDtos.*;
import com.cyberintel.entity.*;
import com.cyberintel.exception.ApiException;
import com.cyberintel.repository.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpStatus;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

@Service
public class ApkAnalysisState {
 private final ApkAnalysisRepository analyses;private final ScanRepository scans;private final UserRepository users;private final ObjectMapper json;
 public ApkAnalysisState(ApkAnalysisRepository analyses,ScanRepository scans,UserRepository users,ObjectMapper json){this.analyses=analyses;this.scans=scans;this.users=users;this.json=json;}
 @Transactional public UploadResponse create(String email,String filename,AnalysisStorage.Stored stored){
  var user=users.findByEmail(email).orElseThrow(()->new ApiException(HttpStatus.UNAUTHORIZED,"Authentication required."));
  var scan=new Scan(Scan.ScanType.APK,filename,user);scan.setStatus(Scan.Status.UPLOADED);scans.save(scan);
  var analysis=new ApkAnalysis();analysis.scan=scan;analysis.storageKey=stored.key();analysis.fileSize=stored.size();analysis.sha256=stored.sha256();analysis.md5=stored.md5();analyses.saveAndFlush(analysis);
  return new UploadResponse(true,scan.getId(),filename,stored.size(),stored.sha256(),"UPLOADED");
 }
 private ApkAnalysis owned(long id,String email,boolean lock){
  var value=(lock?analyses.lockByScanId(id):analyses.findByScanId(id)).orElseThrow(()->new ApiException(HttpStatus.NOT_FOUND,"APK scan not found."));
  if(!value.scan.getUser().getEmail().equals(email))throw new ApiException(HttpStatus.NOT_FOUND,"APK scan not found.");
  return value;
 }
 @Transactional(readOnly=true,isolation=org.springframework.transaction.annotation.Isolation.REPEATABLE_READ) public Result get(long id,String email){return dto(owned(id,email,false));}
 @Transactional(readOnly=true,isolation=org.springframework.transaction.annotation.Isolation.REPEATABLE_READ) public List<Result> history(String email){return analyses.findTop50ByScanUserEmailOrderByCreatedAtDesc(email).stream().map(this::dto).toList();}
 public record Work(long scanId,String key,String sha256){}
 @Transactional public Work queue(long id,String email){
  var a=owned(id,email,true);
  if(a.scan.getStatus()!=Scan.Status.UPLOADED || !a.artifactsRetained)throw new ApiException(HttpStatus.CONFLICT,"Only a newly uploaded APK can be started.");
  a.scan.setStatus(Scan.Status.QUEUED);a.stage="Queued";a.message="Waiting for an analysis worker.";a.progress=5;
  return new Work(id,a.storageKey,a.sha256);
 }
 @Transactional public void update(long id,Consumer<ApkAnalysis> action){
  var a=analyses.lockByScanId(id).orElseThrow();
  if(a.scan.getStatus()==Scan.Status.CANCELLED || a.scan.getStatus()==Scan.Status.COMPLETED || a.scan.getStatus()==Scan.Status.FAILED)return;
  action.accept(a);
 }
 @Transactional public Result cancel(long id,String email){
  var a=owned(id,email,true);var status=a.scan.getStatus();
  if(status==Scan.Status.COMPLETED || status==Scan.Status.FAILED || status==Scan.Status.CANCELLED)return dto(a);
  a.scan.setStatus(Scan.Status.CANCELLED);a.scan.setCompletedAt(Instant.now());a.completedAt=Instant.now();a.stage="Cancelled";a.message="Analysis cancelled. No APK was executed.";
  for(String tool:List.of("jadx","apktool","aapt","androguard"))if(toolStatus(a,tool).equals("RUNNING"))setTool(a,tool,"CANCELLED");
  return dto(a);
 }
 @Transactional public void finish(long id,Findings result,String message){
  var a=analyses.lockByScanId(id).orElseThrow();if(a.scan.getStatus()!=Scan.Status.RUNNING)return;
  var m=result.metadata;a.packageName=m.packageName();a.applicationName=m.applicationName();a.versionName=m.versionName();a.versionCode=m.versionCode();a.minSdk=m.minSdk();a.targetSdk=m.targetSdk();
  for(var p:result.permissions){var e=new PermissionFinding();e.analysis=a;e.permissionName=p.permissionName();e.category=p.category();e.severity=p.severity();e.description=p.description();a.permissions.add(e);}
  for(var c:result.components){var e=new ComponentFinding();e.analysis=a;e.componentType=c.componentType();e.componentName=c.componentName();e.exported=c.exported();e.permission=c.permission();e.severity=c.severity();a.components.add(e);}
  for(var f:result.apis){var e=new ApiFinding();e.analysis=a;e.className=f.className();e.methodName=f.methodName();e.apiName=f.apiName();e.category=f.category();e.severity=f.severity();e.description=f.description();a.apiFindings.add(e);}
  for(var s:result.strings){var e=new ExtractedString();e.analysis=a;e.value=s.value();e.kind=s.kind();e.source=s.source();a.strings.add(e);}
  try{a.sourceSummary=json.writeValueAsString(result.summary);}catch(Exception e){throw new IllegalStateException(e);}
  a.scan.setStatus(Scan.Status.COMPLETED);a.scan.setCompletedAt(Instant.now());a.completedAt=Instant.now();a.stage="Analysis complete";a.progress=100;a.message=message;
 }
 @Transactional public void recoverInterrupted(){for(var a:analyses.findInterrupted()){a.scan.setStatus(Scan.Status.FAILED);a.stage="Interrupted";a.message="Server restarted during analysis. Upload again to retry.";a.completedAt=Instant.now();a.scan.setCompletedAt(a.completedAt);}}
 @Transactional public void expireArtifacts(long id){var a=analyses.lockByScanId(id).orElseThrow();a.artifactsRetained=false;if(a.scan.getStatus()==Scan.Status.UPLOADED){a.scan.setStatus(Scan.Status.FAILED);a.stage="Expired";a.message="Upload expired under the retention policy. Upload again to analyze.";a.completedAt=Instant.now();a.scan.setCompletedAt(a.completedAt);}}
 public static void setTool(ApkAnalysis a,String tool,String status){switch(tool){case "jadx"->a.jadxStatus=status;case "apktool"->a.apktoolStatus=status;case "aapt"->a.aaptStatus=status;case "androguard"->a.androguardStatus=status;default->throw new IllegalArgumentException();}}
 private static String toolStatus(ApkAnalysis a,String tool){return switch(tool){case "jadx"->a.jadxStatus;case "apktool"->a.apktoolStatus;case "aapt"->a.aaptStatus;case "androguard"->a.androguardStatus;default->throw new IllegalArgumentException();};}
 private Result dto(ApkAnalysis a){
  Map<String,Object> summary;try{summary=json.readValue(a.sourceSummary,new TypeReference<>(){});}catch(Exception e){summary=Map.of();}
  return new Result(a.scan.getId(),a.scan.getTarget(),a.fileSize,a.sha256,a.md5,a.scan.getStatus().name(),a.stage,a.progress,a.analysisMode,a.message,
   new Metadata(a.packageName,a.applicationName,a.versionName,a.versionCode,a.minSdk,a.targetSdk),Map.of("jadx",a.jadxStatus,"apktool",a.apktoolStatus,"aapt",a.aaptStatus,"androguard",a.androguardStatus),
   a.permissions.stream().map(p->new Permission(p.permissionName,p.category,p.severity,p.description)).toList(),
   a.components.stream().map(c->new Component(c.componentType,c.componentName,c.exported,c.permission,c.severity)).toList(),
   a.apiFindings.stream().map(f->new Api(f.className,f.methodName,f.apiName,f.category,f.severity,f.description)).toList(),
   a.strings.stream().map(s->new Text(s.value,s.kind,s.source)).toList(),a.strings.stream().filter(s->s.kind.equals("URL")).map(s->s.value).distinct().toList(),summary,a.startedAt,a.completedAt,a.createdAt);
 }
}
