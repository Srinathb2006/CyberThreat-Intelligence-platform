package com.cyberintel;
import com.cyberintel.service.StaticFindingsExtractor;
import com.cyberintel.dto.ApkDtos.Findings;
import com.cyberintel.util.ApkArchiveValidator;
import com.cyberintel.config.AnalysisRuntimeProperties;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import static org.assertj.core.api.Assertions.*;
class StaticExtractionTest {
 @TempDir Path temp;
 @Test void readsManifestPermissionsComponentsAndAaptFallback()throws Exception{
  Path manifest=temp.resolve("AndroidManifest.xml");Files.writeString(manifest,ApkTestFixtures.MANIFEST);
  var extractor=new StaticFindingsExtractor();var findings=new Findings();extractor.readManifest(manifest,findings);
  assertThat(findings.metadata.packageName()).isEqualTo("org.example.safe");
  assertThat(findings.metadata.applicationName()).isEqualTo("Safe fixture");
  assertThat(findings.components).hasSize(4);assertThat(findings.components.get(0).exported()).isTrue();
  assertThat(findings.permissions.get(0).severity()).isEqualTo("HIGH");
  extractor.readBadging("package: name='org.real' versionCode='9' versionName='2.0'\nsdkVersion:'24'\ntargetSdkVersion:'35'\napplication-label:'Real'\nuses-permission: name='android.permission.INTERNET'",findings);
  assertThat(findings.metadata.packageName()).isEqualTo("org.real");assertThat(findings.metadata.minSdk()).isEqualTo("24");assertThat(findings.permissions).hasSize(2);
  extractor.readBadging("package: name='org.aapt2' versionCode='3' versionName='1.0'\nminSdkVersion:'26'\ntargetSdkVersion:'35'\napplication-label:'AAPT2'\nuses-permission: name='android.permission.READ_EXTERNAL_STORAGE'",findings);
  assertThat(findings.metadata.packageName()).isEqualTo("org.aapt2");
  assertThat(findings.metadata.minSdk()).isEqualTo("26");
  assertThat(findings.permissions).hasSize(3);
 }
 @Test void rejectsArchiveTraversalAndXmlEntities()throws Exception{
  Path apk=temp.resolve("fixture.apk");var validator=new ApkArchiveValidator(new AnalysisRuntimeProperties());
  Files.write(apk,ApkTestFixtures.apk(null));assertThatCode(()->validator.validate(apk)).doesNotThrowAnyException();
  Files.write(apk,ApkTestFixtures.apk("../escape"));assertThatThrownBy(()->validator.validate(apk)).hasMessageContaining("unsafe");
  Path xml=temp.resolve("manifest.xml");Files.writeString(xml,"<!DOCTYPE manifest [<!ENTITY x SYSTEM 'file:///never-read'>]><manifest>&x;</manifest>");
  assertThatThrownBy(()->new StaticFindingsExtractor().readManifest(xml,new Findings())).isInstanceOf(Exception.class);
 }
 @Test void extractsSourceIndicatorsWithoutVerdicts()throws Exception{
  Path jadx=Files.createDirectories(temp.resolve("jadx")),apktool=Files.createDirectories(temp.resolve("apktool"));
  Files.writeString(jadx.resolve("Safe.java"),"package org.example;\npublic class Safe { public void test() { WebView v; String url=\"https://example.com/api\"; String email=\"a@example.com\"; } }");
  var findings=new StaticFindingsExtractor().extract(jadx,apktool,"");
  assertThat(findings.apis).anyMatch(a->a.apiName().equals("WebView"));
  assertThat(findings.strings).anyMatch(s->s.kind().equals("URL")&&s.value().equals("https://example.com/api"));
  assertThat(findings.summary.get("javaFiles")).isEqualTo(1);
  Files.write(jadx.resolve("binary.txt"),new byte[]{(byte)0xc3,0x28});
  var withBinary=new StaticFindingsExtractor().extract(jadx,apktool,"");
  assertThat(withBinary.summary.get("unreadableTextFiles")).isEqualTo(1);
  assertThat(withBinary.apis).isNotEmpty();
 }
 @Test void reservesCapacityForIndicatorsAcrossFiles()throws Exception{
  Path jadx=Files.createDirectories(temp.resolve("jadx")),apktool=Files.createDirectories(temp.resolve("apktool"));
  StringBuilder content=new StringBuilder();for(int i=0;i<1200;i++)content.append("\"ordinary sample text ").append(i).append("\"\n");
  Files.writeString(jadx.resolve("A.java"),content);
  Files.writeString(jadx.resolve("Z.java"),"\"https://example.org/later\" \"user@example.org\" \"999.999.999.999\" \"192.0.2.1\"");
  var findings=new StaticFindingsExtractor().extract(jadx,apktool,"");
  assertThat(findings.strings).anyMatch(s->s.kind().equals("URL")&&s.value().equals("https://example.org/later"));
  assertThat(findings.strings).noneMatch(s->s.kind().equals("IP")&&s.value().equals("999.999.999.999"));
  assertThat(findings.strings.stream().filter(s->s.kind().equals("STRING")).count()).isLessThanOrEqualTo(200);
 }
}
