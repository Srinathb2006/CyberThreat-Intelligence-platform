package com.cyberintel.service;
import com.cyberintel.config.AnalysisProperties;
import org.springframework.stereotype.Service;
@Service public class JadxAnalyzerService extends PlannedAnalyzerService implements StaticToolAnalyzer {
 private final AnalysisProcessRunner runner;
 public JadxAnalyzerService(AnalysisProperties properties,AnalysisProcessRunner runner){super("jadx",properties);this.runner=runner;}
 public boolean available(){return runner.available("jadx");}
 public AnalysisProcessRunner.Outcome analyze(java.nio.file.Path apk,java.nio.file.Path output,java.util.function.BooleanSupplier cancelled)throws java.io.IOException{
  return runner.run("jadx",apk,output,java.util.List.of("--no-res","-j","1","-d",output.resolve("sources").toString(),apk.toString()),cancelled);
 }
}
