package com.cyberintel.service;
import java.nio.file.Path;
public interface AnalysisToolService {
 String toolName();
 boolean enabled();
 ToolResult analyze(Path validatedApk);
 record ToolResult(String tool,String status,String message){}
}
