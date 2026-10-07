package com.cyberintel.service;
import java.nio.file.Path;
import java.io.IOException;
import java.util.function.BooleanSupplier;
public interface StaticToolAnalyzer {
 String toolName();
 boolean available();
 AnalysisProcessRunner.Outcome analyze(Path apk,Path output,BooleanSupplier cancelled)throws IOException;
}
