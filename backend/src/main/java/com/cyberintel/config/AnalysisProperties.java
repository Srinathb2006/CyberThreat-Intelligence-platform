package com.cyberintel.config;
import java.util.*;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;
@Component @ConfigurationProperties(prefix="app")
public class AnalysisProperties {
 private String uploadDirectory="./data/uploads";
 private DataSize maxApkSize=DataSize.ofMegabytes(50);
 private Map<String,Tool> tools=new HashMap<>();
 public String getUploadDirectory(){return uploadDirectory;} public void setUploadDirectory(String value){uploadDirectory=value;}
 public DataSize getMaxApkSize(){return maxApkSize;} public void setMaxApkSize(DataSize value){if(value.toBytes()<=0)throw new IllegalArgumentException("MAX_APK_SIZE must be positive");maxApkSize=value;}
 public Map<String,Tool> getTools(){return tools;} public void setTools(Map<String,Tool> value){tools=value;}
 public static class Tool {
  private boolean enabled;private String path="";
  public boolean isEnabled(){return enabled;}public void setEnabled(boolean value){enabled=value;}
  public String getPath(){return path;}public void setPath(String value){path=value;}
 }
}
