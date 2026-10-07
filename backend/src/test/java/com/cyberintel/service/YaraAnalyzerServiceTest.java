package com.cyberintel.service;

import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import static org.assertj.core.api.Assertions.assertThat;

class YaraAnalyzerServiceTest {
 @Test void parsesRuleMetadataAndKeepsOnlyFilesUnderExtractionRoot(){
  Path root=Path.of("analysis/scans/7/apktool/decoded").toAbsolutePath().normalize();
  String file=root.resolve("smali/Example.smali").toString();
  String outside=root.getParent().resolve("other.txt").toString();
  var matches=YaraAnalyzerService.parse("Suspicious_Code [severity=\"HIGH\",description=\"Known byte pattern\"] "+file+"\nIgnored "+outside,root);
  assertThat(matches).hasSize(1);
  assertThat(matches.get(0).ruleName()).isEqualTo("Suspicious_Code");
  assertThat(matches.get(0).severity()).isEqualTo("HIGH");
  assertThat(matches.get(0).description()).isEqualTo("Known byte pattern");
  assertThat(matches.get(0).evidence()).isEqualTo("decoded/smali/Example.smali");
 }
}
