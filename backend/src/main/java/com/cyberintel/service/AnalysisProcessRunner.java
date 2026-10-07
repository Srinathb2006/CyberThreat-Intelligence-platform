package com.cyberintel.service;
import com.cyberintel.config.*;
import org.springframework.stereotype.Service;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.BooleanSupplier;

@Service
public class AnalysisProcessRunner {
 public record Outcome(String status,String output){}
 private final AnalysisProperties config;
 private final AnalysisRuntimeProperties limits;
 private final AnalysisStorage storage;
 public AnalysisProcessRunner(AnalysisProperties config,AnalysisRuntimeProperties limits,AnalysisStorage storage){this.config=config;this.limits=limits;this.storage=storage;}
 public boolean available(String tool){
  var settings=config.getTools().get(tool);
  if(settings==null || !settings.isEnabled() || settings.getPath()==null || settings.getPath().isBlank())return false;
  try{
   Path path=Path.of(settings.getPath()).toAbsolutePath().normalize();
   String name=path.getFileName().toString().toLowerCase(Locale.ROOT);
   return Files.isRegularFile(path) && !name.endsWith(".bat") && !name.endsWith(".cmd") && !name.endsWith(".ps1")
    && (name.endsWith(".jar") || Files.isExecutable(path));
  }catch(RuntimeException e){return false;}
 }
 public Outcome run(String tool,Path apk,Path output,List<String> arguments,BooleanSupplier cancelled)throws IOException{
  if(!available(tool))return new Outcome("UNAVAILABLE","");
  Path executable=Path.of(config.getTools().get(tool).getPath()).toAbsolutePath().normalize();
  storage.checked(apk);storage.checked(output);
  Path temporary=storage.checked(output.getParent().resolve("temporary").resolve(tool));Files.createDirectories(temporary);
  List<String> command=new ArrayList<>();
  if(executable.toString().toLowerCase(Locale.ROOT).endsWith(".jar")){
   command.add(Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"java.exe":"java").toString());
   command.add("-Xmx512m");
   command.add("-Djava.io.tmpdir="+temporary);
   if(tool.equals("jadx")){command.add("-cp");command.add(executable.getParent().toString()+File.separator+"*");command.add("jadx.cli.JadxCLI");}
   else {command.add("-jar");command.add(executable.toString());}
  }else command.add(executable.toString());
  command.addAll(arguments);
  ProcessBuilder builder=new ProcessBuilder(command).directory(output.toFile()).redirectErrorStream(true);
  builder.environment().remove("JAVA_TOOL_OPTIONS");builder.environment().remove("_JAVA_OPTIONS");builder.environment().remove("JDK_JAVA_OPTIONS");
  builder.environment().put("TMP",temporary.toString());builder.environment().put("TEMP",temporary.toString());builder.environment().put("TMPDIR",temporary.toString());
  if(tool.equals("jadx")){
   builder.environment().put("JADX_CONFIG_DIR",temporary.resolve("config").toString());
   builder.environment().put("JADX_CACHE_DIR",temporary.resolve("cache").toString());
   builder.environment().put("JADX_TMP_DIR",temporary.toString());
   builder.environment().put("JADX_ZIP_MAX_ENTRIES_COUNT",Integer.toString(limits.getMaxEntries()));
   builder.environment().keySet().removeIf(key->key.startsWith("JADX_DISABLE_"));
  }
  Process process;
  try{process=builder.start();}catch(IOException e){return new Outcome("FAILED","");}
  var descendants=new HashSet<ProcessHandle>();var captured=new ByteArrayOutputStream();
  Thread drain=new Thread(()->{
   try(var stream=process.getInputStream();var log=Files.newOutputStream(output.resolve("tool.log"),StandardOpenOption.CREATE_NEW)){
    byte[] buffer=new byte[8192];int n,kept=0;
    while((n=stream.read(buffer))!=-1){int take=Math.min(n,262144-kept);if(take>0){log.write(buffer,0,take);synchronized(captured){captured.write(buffer,0,take);}kept+=take;}}
   }catch(IOException ignored){/* Process termination may close its stream. */}
  });
  drain.setDaemon(true);
  drain.start();
  long deadline=System.nanoTime()+Duration.ofSeconds(limits.getTimeoutSeconds()).toNanos();String status="FAILED";
  try{
   while(true){
    process.descendants().forEach(descendants::add);
    if(cancelled.getAsBoolean() || Thread.currentThread().isInterrupted()){status="CANCELLED";break;}
    if(System.nanoTime()>deadline){status="TIMEOUT";break;}
    if(outputExceeded(output.getParent())){status="OUTPUT_LIMIT";break;}
    if(process.waitFor(200,TimeUnit.MILLISECONDS)){status=process.exitValue()==0?"SUCCESS":"FAILED";break;}
   }
  }catch(InterruptedException e){Thread.currentThread().interrupt();status="CANCELLED";}
  finally{
   process.descendants().forEach(descendants::add);
   descendants.forEach(child->{if(child.isAlive())child.destroyForcibly();});
   if(process.isAlive())process.destroyForcibly();
   try{process.waitFor(5,TimeUnit.SECONDS);drain.join(5000);}catch(InterruptedException e){Thread.currentThread().interrupt();}
  }
  if(status.equals("SUCCESS") && outputExceeded(output.getParent()))status="OUTPUT_LIMIT";
  synchronized(captured){return new Outcome(status,captured.toString(StandardCharsets.UTF_8));}
 }
 private boolean outputExceeded(Path output)throws IOException{
  long total=0;int count=0;
  try(var paths=Files.walk(output)){
   var iterator=paths.iterator();
   while(iterator.hasNext()){
    Path path=iterator.next();
    if(Files.isSymbolicLink(path))return true;
    if(++count>limits.getMaxEntries())return true;
    if(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)){total+=Files.size(path);if(total>limits.getMaxOutputBytes())return true;}
   }
  }
  return false;
 }
}
