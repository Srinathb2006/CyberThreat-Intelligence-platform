package com.cyberintel.dto;
import java.time.Instant;
import java.util.*;
public final class ApkDtos {
 private ApkDtos(){}
 public record UploadResponse(boolean success,Long scanId,String fileName,long fileSize,String sha256,String status){}
 public record Metadata(String packageName,String applicationName,String versionName,String versionCode,String minSdk,String targetSdk){}
 public record Permission(String permissionName,String category,String severity,String description){}
 public record Component(String componentType,String componentName,Boolean exported,String permission,String severity){}
 public record Api(String className,String methodName,String apiName,String category,String severity,String description){}
 public record Text(String value,String kind,String source){}
 public record MalwareFinding(String category,String title,String description,String evidence,String severity,String confidence,String source,String ruleId){}
 public record IOC(String value,String type,String source,String severity,String confidence,String description){}
 public record StaticAnalysisSummary(int totalFindings,int critical,int high,int medium,int low,int iocCount,int suspiciousUrls,int suspiciousApis){}
 public record Result(Long scanId,String fileName,long fileSize,String sha256,String md5,String status,String stage,int progress,
  String analysisMode,String message,Metadata metadata,Map<String,String> toolStatus,List<Permission> permissions,
  List<Component> components,List<Api> apiFindings,List<Text> strings,List<String> urls,Map<String,Object> sourceSummary,
  Instant startedAt,Instant completedAt,Instant createdAt){}
 public static class Findings {
  public Metadata metadata=new Metadata(null,null,null,null,null,null);
  public List<Permission> permissions=new ArrayList<>();
  public List<Component> components=new ArrayList<>();
  public List<Api> apis=new ArrayList<>();
  public List<Text> strings=new ArrayList<>();
  public Map<String,Object> summary=new LinkedHashMap<>();
 }

 // Threat Intelligence DTOs
 public record ThreatIntelligenceDto(Long id, String indicator, String indicatorType,
                                     String threatName, String threatFamily, String category,
                                     String severity, String confidence, String description,
                                     String source, String tags, Instant firstSeen,
                                     Instant lastSeen, Boolean active,
                                     Instant createdAt, Instant updatedAt) {}

 public record ThreatIntelligenceSourceDto(Long id, String name, String description,
                                           String sourceType, String url, Boolean enabled,
                                           Instant createdAt) {}

 public record ImportResult(int imported, int errors, List<String> errorDetails) {}

 // Risk Correlation DTOs
 public record RiskAssessmentResult(Long id, Long scanId, Double score, String riskLevel,
                                     String confidence, String summary,
                                     RiskBreakdownDto breakdown,
                                     List<RiskIndicatorDto> indicators,
                                     List<RiskRecommendationDto> recommendations,
                                     Instant createdAt) {}

 public record RiskBreakdownDto(Double staticFindings, Double threatIntelligence,
                                 Double apiCalls, Double permissions,
                                 Double iocs, Double urls,
                                 Double components, Double obfuscationNative,
                                 Double total) {}

 public record RiskIndicatorDto(Long id, String sourceType, Long sourceId,
                                 String category, String description,
                                 String severity, String confidence,
                                 Double contribution, String evidence,
                                 Instant createdAt) {}

 public record RiskRecommendationDto(String category, String recommendation) {}
}