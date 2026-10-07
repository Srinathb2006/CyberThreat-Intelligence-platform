package com.cyberintel.service;
import com.cyberintel.config.AnalysisProperties;
import org.springframework.stereotype.Service;
@Service public class YaraAnalyzerService extends PlannedAnalyzerService {
 public YaraAnalyzerService(AnalysisProperties properties){super("yara",properties);}
}

