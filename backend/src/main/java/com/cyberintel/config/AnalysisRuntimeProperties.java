package com.cyberintel.config;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;
import jakarta.validation.constraints.*;
@Component @Validated @ConfigurationProperties(prefix="analysis")
public class AnalysisRuntimeProperties {
 private String directory="./analysis";
 @Min(1) @Max(3600) private int timeoutSeconds=120;
 @Min(1) @Max(3650) private int retentionDays=7;
 @Min(1048576) private long maxExpandedBytes=268435456;
 @Min(1) @Max(100000) private int maxEntries=20000;
 @Min(1048576) private long maxOutputBytes=536870912;
 public String getDirectory(){return directory;} public void setDirectory(String v){directory=v;}
 public int getTimeoutSeconds(){return timeoutSeconds;}public void setTimeoutSeconds(int v){timeoutSeconds=v;}
 public int getRetentionDays(){return retentionDays;}public void setRetentionDays(int v){retentionDays=v;}
 public long getMaxExpandedBytes(){return maxExpandedBytes;}public void setMaxExpandedBytes(long v){maxExpandedBytes=v;}
 public int getMaxEntries(){return maxEntries;}public void setMaxEntries(int v){maxEntries=v;}
 public long getMaxOutputBytes(){return maxOutputBytes;}public void setMaxOutputBytes(long v){maxOutputBytes=v;}
}
