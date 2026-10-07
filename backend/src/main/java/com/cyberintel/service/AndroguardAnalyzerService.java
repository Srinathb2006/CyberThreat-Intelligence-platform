package com.cyberintel.service;

import com.cyberintel.config.AnalysisProperties;
import com.cyberintel.dto.ApkDtos.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

@Service
public class AndroguardAnalyzerService extends PlannedAnalyzerService implements StaticToolAnalyzer {
 private final AnalysisProperties properties;
 private final AnalysisProcessRunner runner;
 private final ObjectMapper json;
 public AndroguardAnalyzerService(AnalysisProperties properties,AnalysisProcessRunner runner,ObjectMapper json){super("androguard",properties);this.properties=properties;this.runner=runner;this.json=json;}
 public boolean available(){
  if(!runner.available("androguard"))return false;
  try{
   Path executable=Path.of(properties.getTools().get("androguard").getPath()).toAbsolutePath().normalize();
   Process process=new ProcessBuilder(executable.toString(),"-I","-c","import androguard.misc").redirectErrorStream(true).start();
   boolean done=process.waitFor(5,TimeUnit.SECONDS);
   if(!done){process.destroyForcibly();return false;}
   return process.exitValue()==0;
  }catch(IOException|InterruptedException|RuntimeException e){if(e instanceof InterruptedException)Thread.currentThread().interrupt();return false;}
 }
 public AnalysisProcessRunner.Outcome analyze(Path apk,Path output,BooleanSupplier cancelled)throws IOException{
  if(!available())return new AnalysisProcessRunner.Outcome("UNAVAILABLE","");
  Path script=output.resolve("androguard_scan.py");
  try(var source=getClass().getResourceAsStream("/androguard_scan.py")){
   if(source==null)throw new IOException("Androguard helper is missing.");
   Files.copy(source,script,StandardCopyOption.REPLACE_EXISTING);
  }
  return runner.run("androguard",apk,output,List.of("-I","-B",script.toString(),apk.toString(),output.resolve("result.json").toString()),cancelled);
 }
 public void merge(Path output,Findings findings)throws IOException{
  Path report=output.resolve("result.json");
  if(!Files.isRegularFile(report,LinkOption.NOFOLLOW_LINKS)||Files.size(report)>1_048_576)throw new IOException("Androguard result is missing or too large.");
  JsonNode result=json.readTree(report.toFile());
  if(result==null||!result.isObject()||!result.path("metadata").isObject()||!result.path("permissions").isArray()
   ||!result.path("apiFindings").isArray()||!result.path("dexFileNames").isArray()
   ||!result.path("dexClassCount").isIntegralNumber()||!result.path("dexMethodCount").isIntegralNumber())throw new IOException("Androguard result has an invalid format.");
  JsonNode metadata=result.path("metadata");Metadata old=findings.metadata;
  findings.metadata=new Metadata(prefer(old.packageName(),str(metadata,"packageName",255)),prefer(old.applicationName(),str(metadata,"applicationName",255)),
   prefer(old.versionName(),str(metadata,"versionName",255)),prefer(old.versionCode(),str(metadata,"versionCode",255)),
   prefer(old.minSdk(),str(metadata,"minSdk",255)),prefer(old.targetSdk(),str(metadata,"targetSdk",255)));
  JsonNode permissions=result.path("permissions");
  if(permissions.isArray())for(JsonNode value:permissions){
   if(findings.permissions.size()>=1000)break;
   String name=clip(value.asText(null),512);
   if(name!=null&&name.startsWith("android.permission.")&&findings.permissions.stream().noneMatch(p->p.permissionName().equals(name)))findings.permissions.add(StaticFindingsExtractor.permission(name));
  }
  JsonNode apis=result.path("apiFindings");
  if(apis.isArray())for(JsonNode value:apis){
   if(findings.apis.size()>=500)break;
   String name=str(value,"apiName",255),owner=str(value,"className",512),method=str(value,"methodName",512);
   if(name==null||owner==null||method==null||findings.apis.stream().anyMatch(a->a.apiName().equals(name)))continue;
   String category=str(value,"category",255),severity=str(value,"severity",16);
   if(!Set.of("LOW","MEDIUM","HIGH","CRITICAL").contains(severity))severity="MEDIUM";
   findings.apis.add(new Api(owner,method,name,category==null?"DEX_REFERENCE":category,severity,
    "Androguard DEX method reference; presence does not prove invocation."));
  }
  JsonNode names=result.path("dexFileNames");
  List<String> dexNames=new ArrayList<>();
  if(names.isArray())for(JsonNode name:names){if(dexNames.size()>=100)break;String item=clip(name.asText(null),255);if(item!=null)dexNames.add(item);}
  findings.summary.put("dexFileNames",dexNames);
  findings.summary.put("dexClassCount",Math.max(0,result.path("dexClassCount").asInt(0)));
  findings.summary.put("dexMethodCount",Math.max(0,result.path("dexMethodCount").asInt(0)));
 }
 private static String prefer(String current,String replacement){return current==null||current.isBlank()?replacement:current;}
 private static String str(JsonNode node,String field,int max){return clip(node.path(field).isTextual()?node.path(field).asText():null,max);}
 private static String clip(String value,int max){if(value==null||value.isBlank())return null;return value.substring(0,Math.min(max,value.length())).replace("\u0000","");}
}
