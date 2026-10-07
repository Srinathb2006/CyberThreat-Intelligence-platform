package com.cyberintel.service;
import com.cyberintel.config.AnalysisProperties;
import org.springframework.stereotype.Service;
@Service public class ApktoolAnalyzerService extends PlannedAnalyzerService implements StaticToolAnalyzer {
 private final AnalysisProcessRunner runner;
 public ApktoolAnalyzerService(AnalysisProperties properties,AnalysisProcessRunner runner){super("apktool",properties);this.runner=runner;}
 public boolean available(){return runner.available("apktool");}
 public AnalysisProcessRunner.Outcome analyze(java.nio.file.Path apk,java.nio.file.Path output,java.util.function.BooleanSupplier cancelled)throws java.io.IOException{
  return runner.run("apktool",apk,output,java.util.List.of("d","-f","-p",output.resolve("framework").toString(),"-o",output.resolve("decoded").toString(),apk.toString()),cancelled);
 }
}
