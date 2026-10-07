package com.cyberintel.service;
import com.cyberintel.dto.ApkDtos.*;
import org.springframework.stereotype.Service;
import java.util.*;
@Service
public class MockAnalysisFactory {
 public Findings create(String sha256){
  Findings result=new Findings();String suffix=sha256.substring(0,8);
  result.metadata=new Metadata("demo.sample."+suffix,"Demo APK "+suffix,"1.0","1","23","35");
  result.permissions.add(StaticFindingsExtractor.permission("android.permission.INTERNET"));
  result.permissions.add(StaticFindingsExtractor.permission("android.permission.CAMERA"));
  result.components.add(new Component("ACTIVITY","demo.sample.MainActivity",true,null,"MEDIUM"));
  result.apis.add(new Api("demo.sample.MainActivity","onCreate","WebView","WEB","MEDIUM","Synthetic demo reference. This finding was not extracted from the uploaded APK."));
  result.strings.add(new Text("https://api.example.com/demo/"+suffix,"URL","DEMO"));
  result.strings.add(new Text("Demonstration data, not extracted evidence","STRING","DEMO"));
  result.summary.putAll(Map.of("javaFiles",1,"smaliFiles",1,"resourceFiles",1,"assets",0,"nativeLibraries",0,
   "packages",List.of("demo.sample"),"classes",List.of("demo.sample.MainActivity"),"methods",List.of("demo.sample.MainActivity#onCreate")));
  return result;
 }
}
