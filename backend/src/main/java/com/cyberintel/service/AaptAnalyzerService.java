package com.cyberintel.service;
import com.cyberintel.config.AnalysisProperties;
import org.springframework.stereotype.Service;
@Service public class AaptAnalyzerService extends PlannedAnalyzerService implements StaticToolAnalyzer {
 private final AnalysisProcessRunner runner;
 public AaptAnalyzerService(AnalysisProperties properties,AnalysisProcessRunner runner){super("aapt",properties);this.runner=runner;}
 public boolean available(){return runner.available("aapt");}
 public AnalysisProcessRunner.Outcome analyze(java.nio.file.Path apk,java.nio.file.Path output,java.util.function.BooleanSupplier cancelled)throws java.io.IOException{
  return runner.run("aapt",apk,output,java.util.List.of("dump","badging",apk.toString()),cancelled);
 }
}
