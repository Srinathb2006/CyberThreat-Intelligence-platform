package com.cyberintel.service;

import com.cyberintel.config.AnalysisProperties;
import com.cyberintel.config.AnalysisRuntimeProperties;
import org.springframework.stereotype.Service;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class YaraAnalyzerService {
 public record Match(String ruleName,String severity,String description,String evidence) {}
 public record Outcome(String status,String message,List<Match> matches) {}
 private static final Pattern LINE=Pattern.compile("^([A-Za-z_][A-Za-z_0-9]*)\\s+(?:\\[(.*)\\]\\s+)?(.+)$");
 private static final Pattern META=Pattern.compile("(?:^|,)\\s*(severity|description)\\s*=\\s*\"([^\"]{0,500})\"");
 private final AnalysisProperties properties;
 private final AnalysisRuntimeProperties limits;
 private final AnalysisStorage storage;
 public YaraAnalyzerService(AnalysisProperties properties,AnalysisRuntimeProperties limits,AnalysisStorage storage){this.properties=properties;this.limits=limits;this.storage=storage;}

 public boolean available(){
  var config=properties.getTools().get("yara");
  if(config==null || !config.isEnabled() || config.getPath()==null || config.getPath().isBlank() || config.getRulesDirectory()==null || config.getRulesDirectory().isBlank())return false;
  try{
   Path executable=Path.of(config.getPath()).toAbsolutePath().normalize(),rules=Path.of(config.getRulesDirectory()).toAbsolutePath().normalize();
   String name=executable.getFileName().toString().toLowerCase(Locale.ROOT);
   return Files.isRegularFile(executable,LinkOption.NOFOLLOW_LINKS) && Files.isExecutable(executable) && !Files.isSymbolicLink(executable)
    && !name.endsWith(".bat") && !name.endsWith(".cmd") && !name.endsWith(".ps1") && Files.isDirectory(rules,LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(rules);
  }catch(RuntimeException e){return false;}
 }

 public Outcome analyze(long scanId) throws IOException {
  if(!available())return new Outcome("UNAVAILABLE","Local YARA executable or rule directory is not configured.",List.of());
  var config=properties.getTools().get("yara");
  Path rulesRoot=Path.of(config.getRulesDirectory()).toAbsolutePath().normalize();
  List<Path> rules;
  try(var stream=Files.list(rulesRoot)){
   rules=stream.filter(p->{String name=p.getFileName().toString().toLowerCase(Locale.ROOT);return name.endsWith(".yar")||name.endsWith(".yara");}).sorted().toList();
  }
  if(rules.isEmpty())return new Outcome("UNAVAILABLE","No local .yar or .yara rules are configured.",List.of());
  if(rules.size()>50)return new Outcome("FAILED","Too many YARA rule files (maximum 50).",List.of());
  for(Path rule:rules)if(!Files.isRegularFile(rule,LinkOption.NOFOLLOW_LINKS)||Files.isSymbolicLink(rule)||Files.size(rule)>1_048_576)return new Outcome("FAILED","YARA rules must be regular files of at most 1 MiB.",List.of());
  List<Path> targets=List.of(storage.area(scanId,"jadx"),storage.area(scanId,"apktool").resolve("decoded"));
  List<Match> matches=new ArrayList<>();
  int files=0,visited=0;
  for(Path target:targets){
   if(!Files.isDirectory(target,LinkOption.NOFOLLOW_LINKS))continue;
   try(var stream=Files.walk(target)){
    var iterator=stream.iterator();
    while(iterator.hasNext()){
     Path path=iterator.next();
     if(++visited>limits.getMaxEntries())return new Outcome("FAILED","Extracted entry count exceeds scan limit.",List.of());
     if(Files.isSymbolicLink(path))return new Outcome("FAILED","Unsafe symbolic link in extracted files.",List.of());
     if(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)){
      if(++files>limits.getMaxEntries())return new Outcome("FAILED","Extracted file count exceeds scan limit.",List.of());
      if(Files.size(path)>limits.getMaxExpandedBytes())return new Outcome("FAILED","Extracted file exceeds scan limit.",List.of());
     }
    }
   }
  }
  if(files==0)return new Outcome("NO_ARTIFACTS","No extracted files are available for YARA scanning.",List.of());
  Path executable=Path.of(config.getPath()).toAbsolutePath().normalize();
  long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(limits.getTimeoutSeconds());
  for(Path rule:rules)for(Path target:targets){
   if(!Files.isDirectory(target,LinkOption.NOFOLLOW_LINKS))continue;
   long remaining=deadline-System.nanoTime();
   if(remaining<=0)return new Outcome("TIMEOUT","YARA scan timed out.",List.of());
   Process process=new ProcessBuilder(executable.toString(),"-r","-m",rule.toString(),target.toString()).redirectErrorStream(true).start();
   var output=new java.io.ByteArrayOutputStream();
   Thread drain=new Thread(()->{try(var input=process.getInputStream()) {byte[] buffer=new byte[4096];int n;while((n=input.read(buffer))!=-1){synchronized(output){if(output.size()<1_048_576)output.write(buffer,0,Math.min(n,1_048_576-output.size()));}}}catch(IOException ignored){}});
   drain.setDaemon(true);drain.start();
   boolean finished;
   try{finished=process.waitFor(remaining,TimeUnit.NANOSECONDS);}catch(InterruptedException e){Thread.currentThread().interrupt();finished=false;}
   if(!finished){process.descendants().forEach(ProcessHandle::destroyForcibly);process.destroyForcibly();return new Outcome("TIMEOUT","YARA scan timed out.",List.of());}
   try{drain.join(2000);}catch(InterruptedException e){Thread.currentThread().interrupt();return new Outcome("FAILED","YARA scan was interrupted.",List.of());}
   if(process.exitValue()!=0)return new Outcome("FAILED","YARA could not compile or apply the configured rules.",List.of());
   String text; synchronized(output){text=output.toString(StandardCharsets.UTF_8);}
   if(text.getBytes(StandardCharsets.UTF_8).length>=1_048_576)return new Outcome("FAILED","YARA output exceeded the 1 MiB limit.",List.of());
   matches.addAll(parse(text,target));
   if(matches.size()>500)return new Outcome("FAILED","YARA match count exceeded the 500 result limit.",List.of());
  }
  return new Outcome("SUCCESS","Local YARA rules scanned extracted files. Matches require review.",List.copyOf(matches));
 }

 static List<Match> parse(String output,Path root){
  List<Match> result=new ArrayList<>();
  for(String line:output.split("\\R")){
   Matcher match=LINE.matcher(line);if(!match.matches())continue;
   Path path;
   try{path=Path.of(match.group(3).strip()).toAbsolutePath().normalize();}catch(RuntimeException e){continue;}
   if(!path.startsWith(root.toAbsolutePath().normalize()))continue;
   String severity="MEDIUM",description="Matched a configured local YARA rule.";
   if(match.group(2)!=null){Matcher meta=META.matcher(match.group(2));while(meta.find()){
    if(meta.group(1).equals("severity")&&Set.of("LOW","MEDIUM","HIGH","CRITICAL").contains(meta.group(2).toUpperCase(Locale.ROOT)))severity=meta.group(2).toUpperCase(Locale.ROOT);
    if(meta.group(1).equals("description")&&!meta.group(2).isBlank())description=meta.group(2);
   }}
   String evidence=root.getFileName()+"/"+root.relativize(path).toString().replace('\\','/');
   result.add(new Match(match.group(1),severity,description,evidence.length()>1000?evidence.substring(0,1000):evidence));
  }
  return result;
 }
}
