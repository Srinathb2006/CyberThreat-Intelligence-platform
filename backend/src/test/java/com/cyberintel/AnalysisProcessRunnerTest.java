package com.cyberintel;
import com.cyberintel.config.*;
import com.cyberintel.service.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.assertj.core.api.Assertions.*;
class AnalysisProcessRunnerTest {
 @TempDir Path temp;
 @Test void handlesUnavailableSuccessTimeoutAndCancellation()throws Exception{
  var config=new AnalysisProperties();config.setUploadDirectory(temp.resolve("uploads").toString());
  var limits=new AnalysisRuntimeProperties();limits.setDirectory(temp.toString());limits.setTimeoutSeconds(1);
  var storage=new AnalysisStorage(limits,config);var runner=new AnalysisProcessRunner(config,limits,storage);
  Path apk=storage.upload(UUID.randomUUID().toString());Files.writeString(apk,"not executed");
  assertThat(runner.run("aapt",apk,storage.area(1,"aapt"),List.of(),()->false).status()).isEqualTo("UNAVAILABLE");
  var tool=new AnalysisProperties.Tool();tool.setEnabled(true);
  tool.setPath(Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"java.exe":"java").toString());config.getTools().put("aapt",tool);
  String classpath=Path.of("target/test-classes").toAbsolutePath().toString();
  var success=runner.run("aapt",apk,storage.area(2,"aapt"),List.of("-cp",classpath,"com.cyberintel.ProcessFixture"),()->false);
  assertThat(success.status()).isEqualTo("SUCCESS");assertThat(success.output()).contains("fixture output","fixture stderr");
  assertThat(runner.run("aapt",apk,storage.area(3,"aapt"),List.of("-cp",classpath,"com.cyberintel.ProcessFixture","sleep"),()->false).status()).isEqualTo("TIMEOUT");
  assertThat(runner.run("aapt",apk,storage.area(4,"aapt"),List.of("-cp",classpath,"com.cyberintel.ProcessFixture","sleep"),()->true).status()).isEqualTo("CANCELLED");
 }
}
