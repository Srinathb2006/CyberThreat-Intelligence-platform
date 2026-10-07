package com.cyberintel.service;

import com.cyberintel.config.AnalysisProperties;
import com.cyberintel.dto.ApkDtos.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AndroguardAnalyzerServiceTest {
 @TempDir Path directory;
 @Test void mergesDexInventoryAndNewFindingsWithoutDuplicatingExistingEvidence()throws Exception{
  Files.writeString(directory.resolve("result.json"),"""
   {"metadata":{"packageName":"from.androguard","applicationName":"Dex app","versionName":"2"},
    "permissions":["android.permission.INTERNET","android.permission.CAMERA"],
    "apiFindings":[
     {"className":"Ldalvik/system/DexClassLoader;","methodName":"<init>","apiName":"DexClassLoader","category":"DYNAMIC_LOADING","severity":"HIGH"},
     {"className":"Ljavax/crypto/Cipher;","methodName":"getInstance","apiName":"Cipher.getInstance","category":"CRYPTOGRAPHY","severity":"MEDIUM"}],
    "dexFileNames":["classes.dex","classes2.dex"],"dexClassCount":12,"dexMethodCount":87}
   """);
  Findings findings=new Findings();
  findings.metadata=new Metadata("existing.package",null,null,null,null,null);
  findings.permissions.add(StaticFindingsExtractor.permission("android.permission.INTERNET"));
  findings.apis.add(new Api("caller","load","DexClassLoader","DYNAMIC_LOADING","HIGH","Existing source finding"));
  var service=new AndroguardAnalyzerService(new AnalysisProperties(),null,new ObjectMapper());
  service.merge(directory,findings);
  assertThat(findings.metadata.packageName()).isEqualTo("existing.package");
  assertThat(findings.metadata.applicationName()).isEqualTo("Dex app");
  assertThat(findings.permissions).extracting(Permission::permissionName).containsExactly("android.permission.INTERNET","android.permission.CAMERA");
  assertThat(findings.apis).extracting(Api::apiName).containsExactly("DexClassLoader","Cipher.getInstance");
  assertThat(findings.summary).containsEntry("dexFileNames",java.util.List.of("classes.dex","classes2.dex"))
   .containsEntry("dexClassCount",12).containsEntry("dexMethodCount",87);
 }
 @Test void disabledToolIsUnavailable(){
  var service=new AndroguardAnalyzerService(new AnalysisProperties(),new AnalysisProcessRunner(new AnalysisProperties(),new com.cyberintel.config.AnalysisRuntimeProperties(),null),new ObjectMapper());
  assertThat(service.available()).isFalse();
 }
 @Test void rejectsIncompleteToolOutputInsteadOfReportingARealScan()throws Exception{
  Files.writeString(directory.resolve("result.json"),"{}");
  var service=new AndroguardAnalyzerService(new AnalysisProperties(),null,new ObjectMapper());
  assertThatThrownBy(()->service.merge(directory,new Findings()))
   .isInstanceOf(java.io.IOException.class).hasMessageContaining("invalid format");
 }
}
