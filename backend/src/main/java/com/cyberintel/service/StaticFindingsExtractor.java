package com.cyberintel.service;

import com.cyberintel.dto.ApkDtos.*;
import com.cyberintel.util.SecureXml;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

@Service
public class StaticFindingsExtractor {
 private static final String ANDROID="http://schemas.android.com/apk/res/android";
 private static final int LIMIT=1000;
 private static final Pattern URLS=Pattern.compile("https?://[^\\s\\\"'<>\\\\]{3,1500}");
 private static final Map<String,String[]> APIS=new LinkedHashMap<>();
 static{
  APIS.put("SmsManager",new String[]{"SMS","HIGH"});APIS.put("Runtime",new String[]{"EXECUTION","HIGH"});
  APIS.put("DexClassLoader",new String[]{"DYNAMIC_LOADING","HIGH"});APIS.put("WebView",new String[]{"WEB","MEDIUM"});
  for(String name:List.of("HttpURLConnection","URL","Socket"))APIS.put(name,new String[]{"NETWORK","LOW"});
  APIS.put("TelephonyManager",new String[]{"TELEPHONY","MEDIUM"});APIS.put("LocationManager",new String[]{"LOCATION","HIGH"});
  APIS.put("PackageManager",new String[]{"SYSTEM","LOW"});APIS.put("NotificationManager",new String[]{"SYSTEM","LOW"});
  APIS.put("MediaRecorder",new String[]{"MEDIA","HIGH"});APIS.put("Camera",new String[]{"MEDIA","MEDIUM"});
 }
 public Findings extract(Path jadx,Path apktool,String badging)throws Exception{
  Findings result=new Findings();Path decoded=apktool.resolve("decoded");
  Path manifest=decoded.resolve("AndroidManifest.xml");
  if(safeFile(manifest,2097152))readManifest(manifest,result);
  readApktoolMetadata(decoded,result);readBadging(badging,result);
  Map<String,Integer> counts=new HashMap<>();Set<String> packages=new LinkedHashSet<>(),classes=new LinkedHashSet<>(),methods=new LinkedHashSet<>();
  long scanned=0;
  for(Path root:List.of(jadx,decoded)){
   if(!Files.isDirectory(root))continue;
   try(var paths=Files.walk(root)){
    var iterator=paths.iterator();int visited=0;
    while(iterator.hasNext() && ++visited<=20000){
     Path file=iterator.next();
     if(Files.isSymbolicLink(file))throw new IOException("Unsafe analysis output");
     if(!Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS))continue;
     String relative=root.relativize(file).toString().replace('\\','/'),name=file.getFileName().toString();
     if(name.endsWith(".java"))counts.merge("javaFiles",1,Integer::sum);
     if(name.endsWith(".smali"))counts.merge("smaliFiles",1,Integer::sum);
     if(relative.startsWith("res/"))counts.merge("resourceFiles",1,Integer::sum);
     if(relative.startsWith("assets/"))counts.merge("assets",1,Integer::sum);
     if(relative.startsWith("lib/") && name.endsWith(".so"))counts.merge("nativeLibraries",1,Integer::sum);
     if(!(name.endsWith(".java")||name.endsWith(".smali")||name.endsWith(".xml")||name.endsWith(".txt")||name.endsWith(".json")))continue;
     long size=Files.size(file);if(size>2097152 || scanned+size>16777216)continue;scanned+=size;
     String text;
     try{text=Files.readString(file);}catch(java.nio.charset.CharacterCodingException e){counts.merge("unreadableTextFiles",1,Integer::sum);continue;}
     String source=(root.equals(jadx)?"jadx/":"apktool/")+relative;
     Matcher pkg=Pattern.compile("(?m)^\\s*package\\s+([\\w.]+)").matcher(text);
     String pkgName = null;
     if(pkg.find()){
      pkgName = pkg.group(1);
      if(packages.size()<LIMIT)packages.add(pkgName);
     }
     String className=(pkgName != null ? pkgName+"." : "")+name.replaceFirst("\\.(java|smali)$","");
     if((name.endsWith(".java")||name.endsWith(".smali")) && classes.size()<LIMIT)classes.add(clip(className,512));
     Matcher method=Pattern.compile("(?m)(?:\\.method[^\\n]*?\\s|(?:public|private|protected)\\s+(?:static\\s+)?[\\w<>\\[\\]]+\\s+)([\\w$<>]+)\\(").matcher(text);
     while(method.find() && methods.size()<LIMIT)methods.add(clip(className+"#"+method.group(1),512));
     for(var entry:APIS.entrySet()){
      Matcher match=Pattern.compile("\\b"+entry.getKey()+"\\b").matcher(text);
      if(match.find() && result.apis.size()<500){
       if(entry.getKey().equals("Runtime") && !text.contains("exec"))continue;
       result.apis.add(new Api(clip(className,512),null,entry.getKey().equals("Runtime")?"Runtime.exec":entry.getKey(),entry.getValue()[0],entry.getValue()[1],
        "Potential API reference in decompiled code; heuristic evidence, not a malware verdict. Method attribution requires manual review."));
      }
     }
     extractText(text,clip(source,512),result);
    }
   }
  }
  for(String key:List.of("javaFiles","smaliFiles","resourceFiles","assets","nativeLibraries"))result.summary.put(key,counts.getOrDefault(key,0));
  result.summary.put("unreadableTextFiles",counts.getOrDefault("unreadableTextFiles",0));
  result.summary.put("packages",packages);result.summary.put("classes",classes);result.summary.put("methods",methods);
  result.summary.put("extractionLimits","At most 16 MiB readable text, 2 MiB per file, 1,000 strings/components/permissions, and 500 API references. Heuristic extraction may be incomplete.");
  return result;
 }
 public void readManifest(Path path,Findings result)throws Exception{
  Document document;
  try(var in=Files.newInputStream(path)){document=SecureXml.parse(in);}
  Element manifest=document.getDocumentElement();
  String pkg=attr(manifest,"package"),version=android(manifest,"versionName"),code=android(manifest,"versionCode");
  Element sdk=first(manifest,"uses-sdk"),app=first(manifest,"application");
  String min=sdk==null?null:android(sdk,"minSdkVersion"),target=sdk==null?null:android(sdk,"targetSdkVersion");
  String label=app==null?null:android(app,"label");
  if(label!=null && label.startsWith("@string/")){
   Path strings=path.getParent().resolve("res/values/strings.xml");
   if(safeFile(strings,2097152))try(var input=Files.newInputStream(strings)){
    var nodes=SecureXml.parse(input).getElementsByTagName("string");
    for(int i=0;i<nodes.getLength();i++){Element e=(Element)nodes.item(i);if(e.getAttribute("name").equals(label.substring(8))){label=clip(e.getTextContent(),255);break;}}
   }
  }
  result.metadata=new Metadata(pkg,label,version,code,min,target);
  for(String tag:List.of("uses-permission","uses-permission-sdk-23")){
   var permissions=manifest.getElementsByTagName(tag);
   for(int i=0;i<permissions.getLength() && result.permissions.size()<LIMIT;i++){String name=android((Element)permissions.item(i),"name");addPermission(name,result);}
  }
  if(app!=null)for(String type:List.of("activity","activity-alias","service","receiver","provider")){
   var nodes=app.getElementsByTagName(type);
   for(int i=0;i<nodes.getLength() && result.components.size()<LIMIT;i++){
    Element e=(Element)nodes.item(i);String name=android(e,"name");if(name==null)continue;
    if(name.startsWith(".")&&pkg!=null)name=pkg+name;else if(!name.contains(".")&&pkg!=null)name=pkg+"."+name;
    String declared=android(e,"exported");Boolean exported=null;
    if("true".equals(declared))exported=true;else if("false".equals(declared))exported=false;
    else if(type.equals("provider")){try{exported=Integer.parseInt(target==null?(min==null?"1":min):target)<=16;}catch(NumberFormatException ignored){}}
    else {boolean filter=e.getElementsByTagName("intent-filter").getLength()>0;exported=filter;try{if(filter && target!=null && Integer.parseInt(target)>=31)exported=null;}catch(NumberFormatException ignored){}}
    String permission=android(e,"permission");if(permission==null)permission=android(app,"permission");
    result.components.add(new Component(type.toUpperCase(Locale.ROOT).replace('-','_'),clip(name,512),exported,permission,Boolean.TRUE.equals(exported)&&permission==null?"MEDIUM":"LOW"));
   }
  }
 }
 public void readBadging(String text,Findings result){
  if(text==null||text.isBlank())return;
  Metadata m=result.metadata;
  result.metadata=new Metadata(prefer(find(text,"(?m)^package: name='([^']*)'"),m.packageName()),
   prefer(find(text,"(?m)^application-label:'([^']*)'"),m.applicationName()),
   prefer(find(text,"versionName='([^']*)'"),m.versionName()),prefer(find(text,"versionCode='([^']*)'"),m.versionCode()),
   prefer(find(text,"(?m)^(?:sdkVersion|minSdkVersion):'([^']*)'"),m.minSdk()),prefer(find(text,"(?m)^targetSdkVersion:'([^']*)'"),m.targetSdk()));
  Matcher permissions=Pattern.compile("uses-permission(?:-sdk-23)?: name='([^']*)'").matcher(text);
  while(permissions.find()&&result.permissions.size()<LIMIT)addPermission(permissions.group(1),result);
 }
 private void readApktoolMetadata(Path root,Findings result)throws IOException{
  Path yaml=root.resolve("apktool.yml");if(!safeFile(yaml,2097152))return;String text=Files.readString(yaml);Metadata m=result.metadata;
  result.metadata=new Metadata(m.packageName(),m.applicationName(),prefer(m.versionName(),yamlValue(text,"versionName")),prefer(m.versionCode(),yamlValue(text,"versionCode")),
   prefer(m.minSdk(),yamlValue(text,"minSdkVersion")),prefer(m.targetSdk(),yamlValue(text,"targetSdkVersion")));
 }
 private String yamlValue(String text,String key){return find(text,"(?m)^\\s*"+key+":\\s*['\"]?([^'\"\\r\\n]+)");}
 public static Permission permission(String name){
  String suffix=name.substring(name.lastIndexOf('.')+1),severity="LOW",category="GENERAL";
  if(Set.of("READ_SMS","SEND_SMS","RECEIVE_SMS","READ_CALL_LOG","WRITE_CALL_LOG").contains(suffix)){severity="HIGH";category="COMMUNICATION";}
  else if(Set.of("READ_CONTACTS","WRITE_CONTACTS","RECORD_AUDIO","CAMERA","ACCESS_FINE_LOCATION").contains(suffix)){severity="HIGH";category="PERSONAL_DATA";}
  else if(Set.of("SYSTEM_ALERT_WINDOW","REQUEST_INSTALL_PACKAGES").contains(suffix)){severity="HIGH";category="SYSTEM_ACCESS";}
  else if(Set.of("ACCESS_COARSE_LOCATION","RECEIVE_BOOT_COMPLETED").contains(suffix)){severity="MEDIUM";category="DEVICE_CONTEXT";}
  else if(suffix.equals("MASTER_CLEAR")){severity="CRITICAL";category="PRIVILEGED_SYSTEM";}
  return new Permission(clip(name,512),category,severity,"Capability indicator only. Assess purpose, implementation, and user consent before drawing security conclusions.");
 }
 private void addPermission(String name,Findings result){if(name!=null && result.permissions.stream().noneMatch(p->p.permissionName().equals(name)))result.permissions.add(permission(name));}
 private void extractText(String text,String source,Findings result){
  capture(URLS,text,"URL",source,result);
  capture(Pattern.compile("\\b(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,24}\\b"),text,"DOMAIN",source,result);
  capture(Pattern.compile("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"),text,"IP",source,result);
  capture(Pattern.compile("[\\w.+-]+@[\\w.-]+\\.[a-zA-Z]{2,24}"),text,"EMAIL",source,result);
  capture(Pattern.compile("/(?:data|system|sdcard|storage)/[^\\s\"'<>]{1,250}"),text,"PATH",source,result);
  capture(Pattern.compile("(?i)\\b(?:su|chmod|sh -c|Runtime\\.exec|keylog|password|token|credential)\\b"),text,"KEYWORD_OR_COMMAND",source,result);
  Matcher strings=Pattern.compile("\"([^\"\\r\\n]{4,500})\"").matcher(text);
  while(hasTextCapacity("STRING",result)&&strings.find())addText(strings.group(1),"STRING",source,result);
 }
 private boolean hasTextCapacity(String kind,Findings result){
  int limit=switch(kind){case "URL","STRING"->200;case "DOMAIN","KEYWORD_OR_COMMAND"->150;default->100;};
  return result.strings.size()<LIMIT && result.strings.stream().filter(s->s.kind().equals(kind)).count()<limit;
 }
 private void capture(Pattern pattern,String text,String kind,String source,Findings result){Matcher m=pattern.matcher(text);while(hasTextCapacity(kind,result)&&m.find())addText(m.group(),kind,source,result);}
 private void addText(String value,String kind,String source,Findings result){
  if(kind.equals("IP") && Arrays.stream(value.split("\\.")).anyMatch(part->Integer.parseInt(part)>255))return;
  String safe=clip(value,2000);if(result.strings.stream().noneMatch(s->s.kind().equals(kind)&&s.value().equals(safe)))result.strings.add(new Text(safe,kind,source));
 }
 private static boolean safeFile(Path p,long size)throws IOException{return Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)&&!Files.isSymbolicLink(p)&&Files.size(p)<=size;}
 private static String attr(Element e,String key){return e.hasAttribute(key)?clip(e.getAttribute(key),255):null;}
 private static String android(Element e,String key){return e.hasAttributeNS(ANDROID,key)?clip(e.getAttributeNS(ANDROID,key),255):null;}
 private static Element first(Element e,String tag){var nodes=e.getElementsByTagName(tag);return nodes.getLength()==0?null:(Element)nodes.item(0);}
 private static String find(String text,String regex){Matcher matcher=Pattern.compile(regex).matcher(text);return matcher.find()?clip(matcher.group(1).strip(),255):null;}
 private static String prefer(String a,String b){return a==null||a.isBlank()?b:a;}
 public static String clip(String value,int max){if(value==null)return null;String safe=value.replace("\u0000","");return safe.substring(0,Math.min(safe.length(),max));}
}
