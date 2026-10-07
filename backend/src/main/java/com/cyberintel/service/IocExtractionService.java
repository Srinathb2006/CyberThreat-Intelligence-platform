package com.cyberintel.service;

import com.cyberintel.dto.ApkDtos.Findings;
import com.cyberintel.dto.ApkDtos.Metadata;
import com.cyberintel.dto.ApkDtos.Permission;
import com.cyberintel.dto.ApkDtos.Component;
import com.cyberintel.dto.ApkDtos.Api;
import com.cyberintel.dto.ApkDtos.Text;
import com.cyberintel.entity.ApkAnalysis;
import com.cyberintel.entity.IOC;
import com.cyberintel.repository.IocRepository;
import com.cyberintel.repository.ApkAnalysisRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.*;
import java.util.regex.*;

@Service
public class IocExtractionService {
 private final IocRepository iocRepo;
 private final ApkAnalysisRepository analysisRepo;

 public IocExtractionService(IocRepository iocRepo, ApkAnalysisRepository analysisRepo) {
  this.iocRepo = iocRepo;
  this.analysisRepo = analysisRepo;
 }

 @Transactional
 public List<IOC> extractAndStore(Long scanId, Findings findings, boolean isMock) {
  var analysis = analysisRepo.findByScanId(scanId).orElseThrow();

  iocRepo.deleteByApkAnalysisId(analysis.id);

  List<IOC> iocs = new ArrayList<>();
  Set<String> seen = new HashSet<>();

  extractFromMetadata(findings.metadata, iocs, seen, isMock);
  extractFromStrings(findings.strings, iocs, seen, isMock);
  extractFromPermissions(findings.permissions, iocs, seen, isMock);
  extractFromComponents(findings.components, iocs, seen, isMock);
  extractFromApis(findings.apis, iocs, seen, isMock);

  for (IOC ioc : iocs) {
   ioc.apkAnalysis = analysis;
  }

  iocRepo.saveAll(iocs);
  return iocs;
 }

 private void extractFromMetadata(Metadata metadata, List<IOC> iocs, Set<String> seen, boolean isMock) {
  if (metadata.packageName() != null) {
   addIoc(metadata.packageName(), "PACKAGE", "AAPT", iocs, seen, isMock);
  }
 }

 private void extractFromStrings(List<Text> strings, List<IOC> iocs, Set<String> seen, boolean isMock) {
  for (Text s : strings) {
   String val = s.value();
   String kind = s.kind();
   String source = s.source();

   switch (kind) {
    case "URL" -> addIoc(val, "URL", source, iocs, seen, isMock);
    case "DOMAIN" -> addIoc(val, "DOMAIN", source, iocs, seen, isMock);
    case "IP" -> addIoc(val, "IP", source, iocs, seen, isMock);
    case "HASH" -> addIoc(val, "HASH", source, iocs, seen, isMock);
    case "EMAIL" -> addIoc(val, "STRING", source, iocs, seen, isMock);
    case "FILE_PATH" -> addIoc(val, "STRING", source, iocs, seen, isMock);
    case "CRYPTO" -> addIoc(val, "STRING", source, iocs, seen, isMock);
    default -> {
     if (isLikelyUrl(val)) addIoc(val, "URL", source, iocs, seen, isMock);
     else if (isLikelyDomain(val)) addIoc(val, "DOMAIN", source, iocs, seen, isMock);
     else if (isLikelyIp(val)) addIoc(val, "IP", source, iocs, seen, isMock);
    }
   }
  }
 }

 private void extractFromPermissions(List<Permission> permissions, List<IOC> iocs, Set<String> seen, boolean isMock) {
  for (Permission p : permissions) {
   if (p.permissionName() != null) {
    addIoc(p.permissionName(), "API", "MANIFEST", iocs, seen, isMock);
   }
  }
 }

 private void extractFromComponents(List<Component> components, List<IOC> iocs, Set<String> seen, boolean isMock) {
  for (Component c : components) {
   if (c.componentName() != null) {
    addIoc(c.componentName(), "API", "MANIFEST", iocs, seen, isMock);
   }
  }
 }

 private void extractFromApis(List<Api> apis, List<IOC> iocs, Set<String> seen, boolean isMock) {
  for (Api a : apis) {
   String apiSig = a.apiName() != null ? a.apiName() : (a.className() + (a.methodName() != null ? "." + a.methodName() : ""));
   addIoc(apiSig, "API", "JADX", iocs, seen, isMock);
  }
 }

 private void addIoc(String value, String type, String source, List<IOC> iocs, Set<String> seen, boolean isMock) {
  String normalized = normalize(value, type);
  if (normalized == null || normalized.isBlank()) return;

  String key = type + ":" + normalized;
  if (seen.contains(key)) return;
  seen.add(key);

  IOC ioc = new IOC();
  ioc.value = normalized;
  ioc.type = type;
  ioc.source = source;
  ioc.severity = determineSeverity(normalized, type);
  ioc.confidence = determineConfidence(normalized, type);
  ioc.description = buildDescription(normalized, type, source);
  ioc.firstSeen = Instant.now();
  ioc.lastSeen = Instant.now();
  ioc.createdAt = Instant.now();
  iocs.add(ioc);
 }

 private String normalize(String value, String type) {
  if (value == null) return null;
  String v = value.trim();
  switch (type) {
   case "URL": return v.replaceAll("\\s+", "");
   case "DOMAIN": return v.toLowerCase().replaceAll("\\.$", "");
   case "IP": return v.matches("^\\d{1,3}(\\.\\d{1,3}){3}$") ? v : null;
   case "HASH": return v.toLowerCase();
   case "PACKAGE": return v.trim();
   case "API": return v.trim();
   case "PERMISSION": return v.trim();
   case "COMPONENT": return v.trim();
   case "STRING": return v.trim();
   default: return v.trim();
  }
 }

 private String determineSeverity(String value, String type) {
  String lower = value.toLowerCase();
  switch (type) {
   case "URL":
    if (lower.contains("pastebin.com/raw") || lower.contains("hastebin.com/raw") || lower.contains("rentry.co/raw")) return "HIGH";
    if (lower.matches(".*\\.(top|xyz|tk|ml|ga|cf|gq|pw|cc|onion|biz|club|work|loan)\\b.*")) return "HIGH";
    if (lower.matches("https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*")) return "HIGH";
    if (lower.contains("telegram.org/bot") || lower.contains("discord.com/api/webhooks")) return "CRITICAL";
    if (looksSuspiciousUrl(value)) return "HIGH";
    return "LOW";
   case "DOMAIN":
    if (lower.matches(".*\\.(top|xyz|tk|ml|ga|cf|gq|pw|cc|onion|biz|club|work|loan)\\b.*")) return "HIGH";
    if (looksMaliciousDomain(value)) return "HIGH";
    return "LOW";
   case "IP":
    if (isPrivateIp(value)) return "LOW";
    return "MEDIUM";
   case "PERMISSION":
    if (lower.contains("sms") || lower.contains("accessibility") || lower.contains("device_admin") ||
      lower.contains("install_packages") || lower.contains("system_alert_window")) return "HIGH";
    if (lower.contains("camera") || lower.contains("audio") || lower.contains("location") || lower.contains("contacts")) return "MEDIUM";
    return "LOW";
   case "API":
    if (lower.contains("dexclassloader") || lower.contains("pathclassloader") || lower.contains("runtime.exec") ||
      lower.contains("processbuilder") || lower.contains("accessibilityservice")) return "CRITICAL";
    if (lower.contains("reflect") || lower.contains("cipher") || lower.contains("smsmanager") || lower.contains("devicepolicymanager")) return "HIGH";
    return "LOW";
   default:
    return "LOW";
  }
 }

 private String determineConfidence(String value, String type) {
  switch (type) {
   case "IP": return "HIGH";
   case "HASH": return "HIGH";
   case "PERMISSION": return "HIGH";
   case "COMPONENT": return "HIGH";
   case "URL": return "MEDIUM";
   case "DOMAIN": return "MEDIUM";
   case "API": return "HIGH";
   default: return "LOW";
  }
 }

 private String buildDescription(String value, String type, String source) {
  return switch (type) {
   case "URL" -> "Extracted URL endpoint from " + source;
   case "DOMAIN" -> "Extracted domain name from " + source;
   case "IP" -> "Extracted IP address from " + source;
   case "HASH" -> "Cryptographic hash artifact from " + source;
   case "PACKAGE" -> "Application package identifier from " + source;
   case "PERMISSION" -> "Declared Android permission from " + source;
   case "COMPONENT" -> "Android application component from " + source;
   case "API" -> "Sensitive API signature invocation from " + source;
   default -> "Extracted indicator from " + source;
  };
 }

 private boolean isLikelyUrl(String s) {
  return s.startsWith("http://") || s.startsWith("https://") || s.startsWith("ftp://");
 }

 private boolean isLikelyDomain(String s) {
  return s.matches("^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}$") &&
   !s.endsWith(".png") && !s.endsWith(".jpg") && !s.endsWith(".xml") && !s.endsWith(".java") && !s.endsWith(".smali");
 }

 private boolean isLikelyIp(String s) {
  return s.matches("^\\d{1,3}(\\.\\d{1,3}){3}$");
 }

 private boolean looksSuspiciousUrl(String url) {
  String lower = url.toLowerCase();
  int indicators = 0;
  if (lower.length() > 100) indicators++;
  if (lower.matches(".*\\.(apk|exe|jar|dex|so|zip|rar)\\b")) indicators++;
  String[] suspicious = {"login", "verify", "update", "secure", "account", "password", "credential", "payment", "wallet", "download", "install"};
  for (String kw : suspicious) if (lower.contains(kw)) { indicators++; break; }
  if (lower.matches("https?://[^/]*:\\d{2,5}/")) indicators++;
  long dots = lower.chars().filter(ch -> ch == '.').count();
  if (dots > 3) indicators++;
  return indicators >= 2;
 }

 private boolean looksMaliciousDomain(String domain) {
  String lower = domain.toLowerCase();
  int indicators = 0;
  long dots = lower.chars().filter(ch -> ch == '.').count();
  if (dots > 3) indicators++;
  if (lower.length() > 50) indicators++;
  long digits = lower.chars().filter(Character::isDigit).count();
  if (digits > lower.length() * 0.4) indicators++;
  if (lower.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*")) indicators++;
  if (lower.startsWith("xn--")) indicators++;
  if (lower.matches(".*[a-z]{20,}.*")) indicators++;
  return indicators >= 2;
 }

 private boolean isPrivateIp(String ip) {
  String[] parts = ip.split("\\.");
  int a = Integer.parseInt(parts[0]);
  int b = Integer.parseInt(parts[1]);
  return a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || a == 127;
 }

 @Transactional(readOnly = true)
 public List<IOC> getIocsByType(Long scanId, String type) {
  var analysis = analysisRepo.findByScanId(scanId).orElseThrow();
  return iocRepo.findByApkAnalysisIdAndType(analysis.id, type);
 }

 @Transactional(readOnly = true)
 public List<IOC> getAllIocs(Long scanId) {
  var analysis = analysisRepo.findByScanId(scanId).orElseThrow();
  return iocRepo.findByApkAnalysisId(analysis.id);
 }
}