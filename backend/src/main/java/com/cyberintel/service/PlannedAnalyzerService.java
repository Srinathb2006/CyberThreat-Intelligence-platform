package com.cyberintel.service;
import com.cyberintel.config.AnalysisProperties;
import java.nio.file.Path;
public abstract class PlannedAnalyzerService implements AnalysisToolService {
 private final String name;private final AnalysisProperties properties;
 protected PlannedAnalyzerService(String name,AnalysisProperties properties){this.name=name;this.properties=properties;}
 public String toolName(){return name;}
 public boolean enabled(){var tool=properties.getTools().get(name);return tool!=null && tool.isEnabled();}
 public ToolResult analyze(Path validatedApk){return new ToolResult(name,"NOT_IMPLEMENTED","Static analysis integration is reserved for Step 2. No process was started.");}
}
