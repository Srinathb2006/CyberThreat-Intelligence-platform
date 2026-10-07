package com.cyberintel.service;
import com.cyberintel.config.AnalysisProperties;
import org.springframework.stereotype.Service;
@Service public class AndroguardAnalyzerService extends PlannedAnalyzerService {
 public AndroguardAnalyzerService(AnalysisProperties properties){super("androguard",properties);}
}

