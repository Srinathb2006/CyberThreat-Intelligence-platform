package com.cyberintel.service;
import com.cyberintel.entity.Scan;
import com.cyberintel.dto.ApkDtos.*;
import com.cyberintel.exception.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.context.event.EventListener;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import jakarta.annotation.PreDestroy;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.*;

@Service
public class ApkAnalysisOrchestrator {
 private static final Logger log=LoggerFactory.getLogger(ApkAnalysisOrchestrator.class);
 private final ApkAnalysisState state;private final AnalysisStorage storage;private final StaticFindingsExtractor extractor;private final MockAnalysisFactory mock;private final AndroguardAnalyzerService androguard;
 private final List<StaticToolAnalyzer> tools;
 private final Map<Long,AtomicBoolean> cancellations=new ConcurrentHashMap<>();
 private final java.util.concurrent.atomic.AtomicInteger threadCount = new java.util.concurrent.atomic.AtomicInteger();
 private final ExecutorService workers=new ThreadPoolExecutor(2,2,0,TimeUnit.MILLISECONDS,new ArrayBlockingQueue<>(8),
  r -> new Thread(r, "apk-analysis-" + threadCount.getAndIncrement()),
  new ThreadPoolExecutor.AbortPolicy());
 public ApkAnalysisOrchestrator(ApkAnalysisState state,AnalysisStorage storage,StaticFindingsExtractor extractor,MockAnalysisFactory mock,JadxAnalyzerService jadx,ApktoolAnalyzerService apktool,AaptAnalyzerService aapt,AndroguardAnalyzerService androguard){this.state=state;this.storage=storage;this.extractor=extractor;this.mock=mock;this.androguard=androguard;this.tools=List.of(jadx,apktool,aapt,androguard);}
 @EventListener(ApplicationReadyEvent.class) public void recover(){state.recoverInterrupted();}
 public synchronized Result start(long id,String email){
  var work=state.queue(id,email);var cancellation=new AtomicBoolean();cancellations.put(id,cancellation);
  try{workers.execute(()->run(work,cancellation));}
  catch(RejectedExecutionException e){cancellations.remove(id);state.update(id,a->{a.scan.setStatus(Scan.Status.UPLOADED);a.stage="Uploaded";a.message="Worker queue is full. Please retry shortly.";});throw new ApiException(HttpStatus.TOO_MANY_REQUESTS,"Analysis queue is full. Please retry shortly.");}
  return state.get(id,email);
 }
 public synchronized Result cancel(long id,String email){Result result=state.cancel(id,email);var flag=cancellations.get(id);if(flag!=null)flag.set(true);return result;}
 private void stage(long id,String name,int progress){state.update(id,a->{a.stage=name;a.progress=progress;});}
 private void run(ApkAnalysisState.Work work,AtomicBoolean cancelled){
  long id=work.scanId();
  try{
   if(cancelled.get())return;
   boolean real=tools.stream().anyMatch(StaticToolAnalyzer::available);
   state.update(id,a->{a.scan.setStatus(Scan.Status.RUNNING);a.startedAt=Instant.now();a.analysisMode=real?"REAL":"MOCK";a.message=real?"Static reverse engineering in progress.":"DEMO / MOCK ANALYSIS: no enabled static tool is available. Findings are synthetic.";});
   if(!real){
    stage(id,"Generating deterministic demo findings",70);
    state.update(id,a->{a.jadxStatus="MOCK";a.apktoolStatus="MOCK";a.aaptStatus="MOCK";a.androguardStatus="MOCK";});
    if(!cancelled.get())state.finish(id,mock.create(work.sha256()),"DEMO / MOCK ANALYSIS. Metadata and findings are synthetic; file hashes and size are real. No tools were executed.");
    return;
   }
   var apk=storage.upload(work.key());String badging="";List<String> warnings=new ArrayList<>();int successes=0;boolean androguardSucceeded=false;
   for(int i=0;i<tools.size();i++){
    if(cancelled.get())return;
    var tool=tools.get(i);String name=tool.toolName();stage(id,"Running "+name,15+i*17);state.update(id,a->ApkAnalysisState.setTool(a,name,"RUNNING"));
    var outcome=tool.analyze(apk,storage.area(id,name),cancelled::get);state.update(id,a->ApkAnalysisState.setTool(a,name,outcome.status()));
    if(outcome.status().equals("CANCELLED")||cancelled.get())return;
    if(outcome.status().equals("SUCCESS")){successes++;if(name.equals("aapt"))badging=outcome.output();if(name.equals("androguard"))androguardSucceeded=true;}
    else warnings.add(name+": "+outcome.status());
   }
   stage(id,"Extracting manifest and components",78);
   if(cancelled.get())return;
   stage(id,"Extracting APIs and strings",88);
   var findings=extractor.extract(storage.area(id,"jadx"),storage.area(id,"apktool"),badging);
   if(androguardSucceeded)try{androguard.merge(storage.area(id,"androguard"),findings);}catch(java.io.IOException e){
    successes--;warnings.add("androguard: FAILED");state.update(id,a->a.androguardStatus="FAILED");
   }
   if(successes==0)throw new ApiException(HttpStatus.UNPROCESSABLE_ENTITY,"No real tool completed successfully. Check the tool status and server configuration.");
   stage(id,"Storing results",96);
   if(!cancelled.get())state.finish(id,findings,warnings.isEmpty()?"Static extraction complete. Indicators are not a malware verdict.":"Partial real analysis. "+String.join("; ",warnings)+". No synthetic findings were added.");
  }catch(Exception e){
   log.warn("APK analysis {} failed: {}",id,e.getClass().getSimpleName());
   state.update(id,a->{a.scan.setStatus(Scan.Status.FAILED);a.completedAt=Instant.now();a.scan.setCompletedAt(a.completedAt);a.stage="Analysis failed";a.message=e instanceof ApiException?e.getMessage():"Static analysis failed. Check tool configuration, storage capacity, and server permissions.";
    if("RUNNING".equals(a.jadxStatus))a.jadxStatus="FAILED";if("RUNNING".equals(a.apktoolStatus))a.apktoolStatus="FAILED";if("RUNNING".equals(a.aaptStatus))a.aaptStatus="FAILED";if("RUNNING".equals(a.androguardStatus))a.androguardStatus="FAILED";
   });
  }finally{
   try{storage.cleanTemporary(id);}catch(Exception e){log.warn("Temporary cleanup failed for scan {}",id);}
   cancellations.remove(id);
  }
 }
 @PreDestroy public void shutdown(){cancellations.values().forEach(flag->flag.set(true));workers.shutdown();try{if(!workers.awaitTermination(10,TimeUnit.SECONDS))workers.shutdownNow();}catch(InterruptedException e){Thread.currentThread().interrupt();workers.shutdownNow();}}
}
