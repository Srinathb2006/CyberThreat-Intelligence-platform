package com.cyberintel.service;

import com.cyberintel.config.RiskScoringProperties;
import com.cyberintel.config.RiskScoringProperties.Weights;
import com.cyberintel.config.RiskScoringProperties.SeverityMultipliers;
import com.cyberintel.config.RiskScoringProperties.ConfidenceMultipliers;

import com.cyberintel.dto.ApkDtos;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.cyberintel.entity.*;
import com.cyberintel.repository.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Transactional
public class RiskCorrelationService {

    private final RiskScoringProperties scoringProperties;
    private final RiskAssessmentRepository riskAssessmentRepository;
    private final RiskIndicatorRepository riskIndicatorRepository;
    private final ApkAnalysisRepository apkAnalysisRepository;
    private final MalwareFindingRepository malwareFindingRepository;
    private final IocRepository iocRepository;
    private final ThreatMatchRepository threatMatchRepository;
    private final ScanRepository scanRepository;
    private final AlertService alertService;
    private final ObjectMapper objectMapper;

    public RiskCorrelationService(
            RiskScoringProperties scoringProperties,
            RiskAssessmentRepository riskAssessmentRepository,
            RiskIndicatorRepository riskIndicatorRepository,
            ApkAnalysisRepository apkAnalysisRepository,
            MalwareFindingRepository malwareFindingRepository,
            IocRepository iocRepository,
            ThreatMatchRepository threatMatchRepository,
            ScanRepository scanRepository,
            AlertService alertService,
            ObjectMapper objectMapper) {
        this.scoringProperties = scoringProperties;
        this.riskAssessmentRepository = riskAssessmentRepository;
        this.riskIndicatorRepository = riskIndicatorRepository;
        this.apkAnalysisRepository = apkAnalysisRepository;
        this.malwareFindingRepository = malwareFindingRepository;
        this.iocRepository = iocRepository;
        this.threatMatchRepository = threatMatchRepository;
        this.scanRepository = scanRepository;
        this.alertService = alertService;
        this.objectMapper = objectMapper;
    }

    public ApkDtos.RiskAssessmentResult calculateRisk(Long scanId) {
        ApkAnalysis analysis = apkAnalysisRepository.findByScanId(scanId)
                .orElseThrow(() -> new IllegalArgumentException("APK analysis not found for scanId: " + scanId));

        riskAssessmentRepository.findByScanIdAndIsLatestTrue(scanId)
                .ifPresent(existing -> {
                    existing.setIsLatest(false);
                    existing.setUpdatedAt(Instant.now());
                    riskAssessmentRepository.save(existing);
                });

        EvidenceCollector collector = new EvidenceCollector(analysis);
        collector.collect();

        CategoryScores scores = calculateCategoryScores(collector);

        List<RiskIndicator> indicators = buildRiskIndicators(collector, scores);

        double totalScore = Math.min(100.0, scores.total());
        totalScore = Math.max(0.0, totalScore);

        String riskLevel = determineRiskLevel(totalScore);
        String confidence = determineOverallConfidence(indicators);

        ApkDtos.RiskBreakdownDto breakdown = new ApkDtos.RiskBreakdownDto(
                round1(scores.staticFindings()),
                round1(scores.threatIntelligence()),
                round1(scores.suspiciousApis()),       // maps to apiCalls
                round1(scores.suspiciousPermissions()), // maps to permissions
                round1(scores.iocIndicators()),        // maps to iocs
                round1(scores.suspiciousUrls()),       // maps to urls
                round1(scores.suspiciousComponents()), // maps to components
                round1(scores.obfuscationNative()),
                round1(totalScore)
        );

        List<ApkDtos.RiskRecommendationDto> recommendations = generateRecommendations(collector, scores);

        String summary = buildSummary(analysis, totalScore, riskLevel, confidence, scores);

        RiskAssessment assessment = new RiskAssessment();
        assessment.setScanId(scanId);
        assessment.setApkAnalysisId(analysis.id);
        assessment.setScore(round2(totalScore));
        assessment.setRiskLevel(riskLevel);
        assessment.setConfidence(confidence);
        assessment.setSummary(summary);
        try {
            assessment.setRecommendations(objectMapper.writeValueAsString(recommendations));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unable to save risk recommendations", e);
        }
        assessment.setIsLatest(true);
        assessment.setCreatedAt(Instant.now());
        assessment.setUpdatedAt(Instant.now());
        assessment.setIndicators(indicators);
        riskAssessmentRepository.save(assessment);

        indicators.forEach(i -> i.setRiskAssessment(assessment));
        riskIndicatorRepository.saveAll(indicators);

        Scan scan = scanRepository.findById(scanId).orElse(null);
        if (scan != null) {
            scan.setRiskScore((int) Math.round(totalScore));
            scan.setRiskLevel(Scan.RiskLevel.valueOf(riskLevel));
            scanRepository.save(scan);
        }

        alertService.generateAlertsFromAssessment(scanId);
        return toResult(assessment, breakdown, indicators, recommendations);
    }

    public ApkDtos.RiskAssessmentResult getLatestRisk(Long scanId) {
        RiskAssessment assessment = riskAssessmentRepository.findByScanIdAndIsLatestTrue(scanId)
                .orElseThrow(() -> new IllegalArgumentException("No risk assessment found for scanId: " + scanId));

        List<RiskIndicator> indicators = riskIndicatorRepository.findByRiskAssessmentIdOrderByContributionDesc(assessment.getId());
        ApkDtos.RiskBreakdownDto breakdown = buildBreakdownFromIndicators(indicators);

        return toResult(assessment, breakdown, indicators, savedRecommendations(assessment, indicators));
    }

    public List<ApkDtos.RiskIndicatorDto> getIndicators(Long scanId) {
        RiskAssessment assessment = riskAssessmentRepository.findByScanIdAndIsLatestTrue(scanId)
                .orElseThrow(() -> new IllegalArgumentException("No risk assessment found for scanId: " + scanId));

        List<RiskIndicator> indicators = riskIndicatorRepository.findByRiskAssessmentIdOrderByContributionDesc(assessment.getId());
        return indicators.stream().map(this::toIndicatorDto).toList();
    }

    public ApkDtos.RiskBreakdownDto getBreakdown(Long scanId) {
        RiskAssessment assessment = riskAssessmentRepository.findByScanIdAndIsLatestTrue(scanId)
                .orElseThrow(() -> new IllegalArgumentException("No risk assessment found for scanId: " + scanId));

        List<RiskIndicator> indicators = riskIndicatorRepository.findByRiskAssessmentId(assessment.getId());
        return buildBreakdownFromIndicators(indicators);
    }

    public List<ApkDtos.RiskRecommendationDto> getRecommendations(Long scanId) {
        RiskAssessment assessment = riskAssessmentRepository.findByScanIdAndIsLatestTrue(scanId)
                .orElseThrow(() -> new IllegalArgumentException("No risk assessment found for scanId: " + scanId));

        List<RiskIndicator> indicators = riskIndicatorRepository.findByRiskAssessmentId(assessment.getId());
        return savedRecommendations(assessment, indicators);
    }

    private List<ApkDtos.RiskRecommendationDto> savedRecommendations(
            RiskAssessment assessment, List<RiskIndicator> indicators) {
        // Assessments created before the snapshot column retain the legacy fallback.
        if (assessment.getRecommendations() == null) {
            return generateRecommendationsFromIndicators(indicators);
        }
        try {
            return objectMapper.readValue(assessment.getRecommendations(), new TypeReference<>() {});
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unable to read risk recommendations", e);
        }
    }

    private CategoryScores calculateCategoryScores(EvidenceCollector collector) {
        Weights w = scoringProperties.getWeights();
        SeverityMultipliers sev = scoringProperties.getSeverity();
        ConfidenceMultipliers conf = scoringProperties.getConfidence();

        double staticFindingsScore = calculateEvidenceScore(
                collector.malwareFindings, w.getStaticFindings(), sev, conf, "static_findings");

        double threatIntelScore = calculateEvidenceScore(
                collector.threatMatches, w.getThreatIntelligence(), sev, conf, "threat_intelligence");

        double apiScore = calculateEvidenceScore(
                collector.suspiciousApis, w.getSuspiciousApis(), sev, conf, "suspicious_apis");

        double permScore = calculateEvidenceScore(
                collector.suspiciousPermissions, w.getSuspiciousPermissions(), sev, conf, "suspicious_permissions");

        double iocScore = calculateEvidenceScore(
                collector.deduplicatedIocs, w.getIocIndicators(), sev, conf, "ioc_indicators");

        double urlScore = calculateEvidenceScore(
                collector.suspiciousUrls, w.getSuspiciousUrls(), sev, conf, "suspicious_urls");

        double compScore = calculateEvidenceScore(
                collector.suspiciousComponents, w.getSuspiciousComponents(), sev, conf, "suspicious_components");

        double obfScore = calculateEvidenceScore(
                collector.obfuscationNative, w.getObfuscationNative(), sev, conf, "obfuscation_native");

        double total = staticFindingsScore + threatIntelScore + apiScore + permScore +
                iocScore + urlScore + compScore + obfScore;

        return new CategoryScores(
                staticFindingsScore, threatIntelScore, apiScore, permScore,
                iocScore, urlScore, compScore, obfScore, total
        );
    }

    private double calculateEvidenceScore(
            List<? extends ScoredEvidence> evidenceList,
            double categoryWeight,
            SeverityMultipliers sev,
            ConfidenceMultipliers conf,
            String category) {

        if (evidenceList == null || evidenceList.isEmpty()) return 0.0;

        double sum = evidenceList.stream()
                .mapToDouble(e -> {
                    double severityFactor = getSeverityFactor(e.getSeverity(), sev);
                    double confidenceFactor = getConfidenceFactor(e.getConfidence(), conf);
                    return categoryWeight * severityFactor * confidenceFactor;
                })
                .sum();

        return Math.min(categoryWeight, sum);
    }

    private double getSeverityFactor(String severity, SeverityMultipliers sev) {
        return switch (severity != null ? severity.toUpperCase() : "LOW") {
            case "CRITICAL" -> sev.getCritical();
            case "HIGH" -> sev.getHigh();
            case "MEDIUM" -> sev.getMedium();
            default -> sev.getLow();
        };
    }

    private double getConfidenceFactor(String confidence, ConfidenceMultipliers conf) {
        return switch (confidence != null ? confidence.toUpperCase() : "LOW") {
            case "HIGH" -> conf.getHigh();
            case "MEDIUM" -> conf.getMedium();
            default -> conf.getLow();
        };
    }

    private String determineRiskLevel(double score) {
        if (score >= 76) return "CRITICAL";
        if (score >= 51) return "HIGH";
        if (score >= 26) return "MEDIUM";
        return "LOW";
    }

    private String determineOverallConfidence(List<RiskIndicator> indicators) {
        if (indicators == null || indicators.isEmpty()) return "LOW";

        long highConf = indicators.stream()
                .filter(i -> "HIGH".equalsIgnoreCase(i.getConfidence()))
                .count();
        long medConf = indicators.stream()
                .filter(i -> "MEDIUM".equalsIgnoreCase(i.getConfidence()))
                .count();

        double highRatio = (double) highConf / indicators.size();
        double medRatio = (double) medConf / indicators.size();

        if (highRatio >= 0.5) return "HIGH";
        if (highRatio + medRatio >= 0.6) return "MEDIUM";
        return "LOW";
    }

    private class EvidenceCollector {
        final ApkAnalysis analysis;
        List<ScoredEvidence> malwareFindings = new ArrayList<>();
        List<ScoredEvidence> threatMatches = new ArrayList<>();
        List<ScoredEvidence> suspiciousApis = new ArrayList<>();
        List<ScoredEvidence> suspiciousPermissions = new ArrayList<>();
        List<ScoredEvidence> deduplicatedIocs = new ArrayList<>();
        List<ScoredEvidence> suspiciousUrls = new ArrayList<>();
        List<ScoredEvidence> suspiciousComponents = new ArrayList<>();
        List<ScoredEvidence> obfuscationNative = new ArrayList<>();

        final Set<String> seenValues = new HashSet<>();

        EvidenceCollector(ApkAnalysis analysis) { this.analysis = analysis; }

        void collect() {
            collectMalwareFindings();
            collectThreatMatches();
            collectSuspiciousApis();
            collectSuspiciousPermissions();
            collectIocs();
            collectSuspiciousUrls();
            collectSuspiciousComponents();
            collectObfuscationNative();
        }

        private void collectMalwareFindings() {
            List<MalwareFinding> findings = malwareFindingRepository.findByApkAnalysisId(analysis.id);
            for (MalwareFinding mf : findings) {
                String key = "malware:" + mf.category + ":" + (mf.evidence != null ? mf.evidence.substring(0, Math.min(100, mf.evidence.length())) : mf.ruleId);
                if (seenValues.add(key)) {
                    malwareFindings.add(new ScoredEvidenceImpl(
                            "malware_finding", mf.id, mf.category,
                            mf.title + ": " + mf.description,
                            mf.severity, mf.confidence, mf.evidence));
                }
            }
        }

        private void collectThreatMatches() {
            List<IOC> iocs = iocRepository.findByApkAnalysisId(analysis.id);
            for (IOC ioc : iocs) {
                List<ThreatMatch> matches = threatMatchRepository.findMatchedByIocId(ioc.id);
                for (ThreatMatch tm : matches) {
                    ThreatIntelligence ti = tm.threatIntelligence;
                    String key = "threat_intel:" + ti.indicator;
                    if (seenValues.add(key)) {
                        threatMatches.add(new ScoredEvidenceImpl(
                                "threat_intelligence", tm.id,
                                ti.category != null ? ti.category : "THREAT_INTEL",
                                "Threat intelligence match: " + ti.threatName + " (" + ti.threatFamily + ") - " + tm.description,
                                tm.severity, tm.confidence, ti.indicator));
                    }
                }
            }
        }

        private void collectSuspiciousApis() {
            for (ApiFinding api : analysis.apiFindings) {
                if (isSuspiciousApi(api)) {
                    String key = "api:" + api.apiName + ":" + api.className;
                    if (seenValues.add(key)) {
                        suspiciousApis.add(new ScoredEvidenceImpl(
                                "api_finding", api.id, "suspicious_api",
                                "Suspicious API: " + api.apiName + " in " + api.className,
                                api.severity != null ? api.severity : "MEDIUM",
                                "MEDIUM", api.apiName + "." + api.methodName));
                    }
                }
            }
        }

        private void collectSuspiciousPermissions() {
            for (PermissionFinding perm : analysis.permissions) {
                if (isSuspiciousPermission(perm)) {
                    String key = "perm:" + perm.permissionName;
                    if (seenValues.add(key)) {
                        suspiciousPermissions.add(new ScoredEvidenceImpl(
                                "permission", perm.id, "suspicious_permission",
                                "Suspicious permission: " + perm.permissionName,
                                perm.severity != null ? perm.severity : "MEDIUM",
                                "MEDIUM", perm.permissionName));
                    }
                }
            }
        }

        private void collectIocs() {
            List<IOC> iocs = iocRepository.findByApkAnalysisId(analysis.id);
            for (IOC ioc : iocs) {
                List<ThreatMatch> matches = threatMatchRepository.findMatchedByIocId(ioc.id);
                if (!matches.isEmpty()) continue;

                String key = "ioc:" + ioc.type + ":" + ioc.value;
                if (seenValues.add(key)) {
                    deduplicatedIocs.add(new ScoredEvidenceImpl(
                            "ioc", ioc.id, ioc.type,
                            "IOC: " + ioc.type + " - " + ioc.value + " (" + (ioc.description != null ? ioc.description : "No description") + ")",
                            ioc.severity, ioc.confidence, ioc.value));
                }
            }
        }

        private void collectSuspiciousUrls() {
            for (ExtractedString str : analysis.strings) {
                if (str.kind != null && (str.kind.equalsIgnoreCase("URL") || str.kind.equalsIgnoreCase("DOMAIN"))) {
                    if (isSuspiciousUrl(str.value)) {
                        String key = "url:" + str.value;
                        if (seenValues.add(key)) {
                            suspiciousUrls.add(new ScoredEvidenceImpl(
                                    "extracted_string", str.id, "suspicious_url",
                                    "Suspicious URL/Domain: " + str.value,
                                    "MEDIUM", "MEDIUM", str.value));
                        }
                    }
                }
            }
        }

        private void collectSuspiciousComponents() {
            for (ComponentFinding comp : analysis.components) {
                if (isSuspiciousComponent(comp)) {
                    String key = "comp:" + comp.componentName + ":" + comp.componentType;
                    if (seenValues.add(key)) {
                        suspiciousComponents.add(new ScoredEvidenceImpl(
                                "component", comp.id, "suspicious_component",
                                "Suspicious component: " + comp.componentName + " (" + comp.componentType + ")",
                                comp.severity != null ? comp.severity : "LOW",
                                "MEDIUM", comp.componentName));
                    }
                }
            }
        }

        private void collectObfuscationNative() {
            String sourceSummary = analysis.sourceSummary;
            if (sourceSummary != null && (sourceSummary.toLowerCase().contains("obfuscat") || sourceSummary.toLowerCase().contains("native"))) {
                String key = "obfuscation:" + analysis.id;
                if (seenValues.add(key)) {
                    obfuscationNative.add(new ScoredEvidenceImpl(
                            "analysis_meta", analysis.id, "obfuscation_native",
                            "Obfuscation or native code detected", "MEDIUM", "LOW",
                            "Source analysis indicates obfuscation/native libraries"));
                }
            }
        }

        private boolean isSuspiciousApi(ApiFinding api) {
            String name = api.apiName != null ? api.apiName.toLowerCase() : "";
            String clazz = api.className != null ? api.className.toLowerCase() : "";
            return name.contains("exec") || name.contains("runtime") || name.contains("shell") ||
                    name.contains("reflection") || name.contains("classloader") ||
                    name.contains("dexclassloader") || name.contains("loadlibrary") ||
                    name.contains("sendtextmessage") || name.contains("sms") ||
                    name.contains("telephony") || name.contains("getdevicid") ||
                    name.contains("getsimserial") || name.contains("getsubscriberid") ||
                    clazz.contains("dalvik") || clazz.contains("xposed") ||
                    clazz.contains("frida") || clazz.contains("substrate");
        }

        private boolean isSuspiciousPermission(PermissionFinding perm) {
            String name = perm.permissionName != null ? perm.permissionName.toLowerCase() : "";
            return name.contains("send_sms") || name.contains("read_sms") || name.contains("receive_sms") ||
                    name.contains("call_phone") || name.contains("read_contacts") || name.contains("write_contacts") ||
                    name.contains("read_call_log") || name.contains("write_call_log") ||
                    name.contains("access_fine_location") || name.contains("access_coarse_location") ||
                    name.contains("record_audio") || name.contains("camera") ||
                    name.contains("read_external_storage") || name.contains("write_external_storage") ||
                    name.contains("install_packages") || name.contains("delete_packages") ||
                    name.contains("system_alert_window") || name.contains("bind_accessibility_service") ||
                    name.contains("device_admin") || name.contains("battery_stats");
        }

        private boolean isSuspiciousUrl(String value) {
            String lower = value.toLowerCase();
            return lower.contains("onion") || lower.contains("pastebin") || lower.contains("github.io") ||
                    lower.contains("raw.githubusercontent") || lower.contains("bit.ly") ||
                    lower.contains("tinyurl") || lower.matches(".*\\.(tk|ml|ga|cf|gq)") ||
                    lower.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*");
        }

        private boolean isSuspiciousComponent(ComponentFinding comp) {
            String name = comp.componentName != null ? comp.componentName.toLowerCase() : "";
            String type = comp.componentType != null ? comp.componentType.toLowerCase() : "";
            boolean exported = comp.exported != null && comp.exported;
            return (type.equals("receiver") && (name.contains("boot") || name.contains("startup") || name.contains("sms"))) ||
                    (type.equals("service") && exported && (name.contains("accessibility") || name.contains("admin"))) ||
                    (type.equals("activity") && exported && (name.contains("main") || name.contains("launcher")));
        }
    }

    private List<RiskIndicator> buildRiskIndicators(EvidenceCollector collector, CategoryScores scores) {
        List<RiskIndicator> indicators = new ArrayList<>();

        addIndicators(indicators, collector.malwareFindings, "MALWARE_FINDING", scores.staticFindings(), scoringProperties.getWeights().getStaticFindings());
        addIndicators(indicators, collector.threatMatches, "THREAT_INTELLIGENCE", scores.threatIntelligence(), scoringProperties.getWeights().getThreatIntelligence());
        addIndicators(indicators, collector.suspiciousApis, "SUSPICIOUS_API", scores.suspiciousApis(), scoringProperties.getWeights().getSuspiciousApis());
        addIndicators(indicators, collector.suspiciousPermissions, "SUSPICIOUS_PERMISSION", scores.suspiciousPermissions(), scoringProperties.getWeights().getSuspiciousPermissions());
        addIndicators(indicators, collector.deduplicatedIocs, "IOC_INDICATOR", scores.iocIndicators(), scoringProperties.getWeights().getIocIndicators());
        addIndicators(indicators, collector.suspiciousUrls, "SUSPICIOUS_URL", scores.suspiciousUrls(), scoringProperties.getWeights().getSuspiciousUrls());
        addIndicators(indicators, collector.suspiciousComponents, "SUSPICIOUS_COMPONENT", scores.suspiciousComponents(), scoringProperties.getWeights().getSuspiciousComponents());
        addIndicators(indicators, collector.obfuscationNative, "OBFUSCATION_NATIVE", scores.obfuscationNative(), scoringProperties.getWeights().getObfuscationNative());

        return indicators;
    }

    private void addIndicators(List<RiskIndicator> indicators, List<ScoredEvidence> evidenceList,
                               String category, double categoryScore, double categoryWeight) {
        if (evidenceList == null || evidenceList.isEmpty()) return;

        double totalEvidenceWeight = evidenceList.stream()
                .mapToDouble(e -> getSeverityFactor(e.getSeverity(), scoringProperties.getSeverity()) *
                        getConfidenceFactor(e.getConfidence(), scoringProperties.getConfidence()))
                .sum();

        if (totalEvidenceWeight == 0) return;

        for (ScoredEvidence e : evidenceList) {
            double severityFactor = getSeverityFactor(e.getSeverity(), scoringProperties.getSeverity());
            double confidenceFactor = getConfidenceFactor(e.getConfidence(), scoringProperties.getConfidence());
            double evidenceWeight = severityFactor * confidenceFactor;
            double contribution = (evidenceWeight / totalEvidenceWeight) * categoryScore;

            RiskIndicator indicator = new RiskIndicator();
            indicator.setSourceType(e.getSourceType());
            indicator.setSourceId(e.getSourceId());
            indicator.setCategory(category);
            indicator.setDescription(e.getDescription());
            indicator.setSeverity(e.getSeverity());
            indicator.setConfidence(e.getConfidence());
            indicator.setContribution(round2(contribution));
            indicator.setEvidence(e.getEvidence());
            indicator.setCreatedAt(Instant.now());
            indicators.add(indicator);
        }
    }

    private List<ApkDtos.RiskRecommendationDto> generateRecommendations(EvidenceCollector collector, CategoryScores scores) {
        List<ApkDtos.RiskRecommendationDto> recommendations = new ArrayList<>();

        if (!collector.threatMatches.isEmpty()) {
            recommendations.add(new ApkDtos.RiskRecommendationDto(
                    "THREAT_INTELLIGENCE", "Quarantine the APK and investigate the associated threat intelligence indicators."));
            for (ScoredEvidence e : collector.threatMatches) {
                if (e.getDescription().toLowerCase().contains("banking") || e.getDescription().toLowerCase().contains("trojan")) {
                    recommendations.add(new ApkDtos.RiskRecommendationDto(
                            "THREAT_INTELLIGENCE", "Banking trojan detected. Immediately revoke any financial credentials entered on this device."));
                    break;
                }
            }
        }

        boolean hasDynamicLoading = collector.malwareFindings.stream()
                .anyMatch(e -> e.getCategory().toLowerCase().contains("dynamic") ||
                        e.getCategory().toLowerCase().contains("classloader") ||
                        e.getCategory().toLowerCase().contains("reflection"));
        if (hasDynamicLoading) {
            recommendations.add(new ApkDtos.RiskRecommendationDto(
                    "DYNAMIC_CODE_LOADING", "Inspect dynamically loaded code and identify the source of the loaded code."));
        }

        boolean hasSms = collector.suspiciousPermissions.stream()
                .anyMatch(e -> e.getEvidence().toLowerCase().contains("sms"));
        hasSms |= collector.malwareFindings.stream()
                .anyMatch(e -> e.getCategory().toLowerCase().contains("sms"));
        if (hasSms) {
            recommendations.add(new ApkDtos.RiskRecommendationDto(
                    "SMS_ABUSE", "Review SMS access and determine whether the behavior is expected."));
        }

        boolean hasBootReceiver = collector.suspiciousComponents.stream()
                .anyMatch(e -> e.getDescription().toLowerCase().contains("boot") || e.getDescription().toLowerCase().contains("startup"));
        if (hasBootReceiver) {
            recommendations.add(new ApkDtos.RiskRecommendationDto(
                    "PERSISTENCE", "Review automatic startup behavior and determine whether it is legitimate."));
        }

        if (!collector.suspiciousUrls.isEmpty()) {
            recommendations.add(new ApkDtos.RiskRecommendationDto(
                    "SUSPICIOUS_INFRASTRUCTURE", "Review extracted URLs and investigate their associated infrastructure using approved threat intelligence sources."));
        }

        boolean hasExfil = collector.malwareFindings.stream()
                .anyMatch(e -> e.getCategory().toLowerCase().contains("exfil") || e.getCategory().toLowerCase().contains("steal"));
        if (hasExfil) {
            recommendations.add(new ApkDtos.RiskRecommendationDto(
                    "DATA_EXFILTRATION", "Investigate potential data exfiltration. Review network traffic and data access patterns."));
        }

        boolean hasRoot = collector.malwareFindings.stream()
                .anyMatch(e -> e.getCategory().toLowerCase().contains("root") || e.getCategory().toLowerCase().contains("su"));
        if (hasRoot) {
            recommendations.add(new ApkDtos.RiskRecommendationDto(
                    "PRIVILEGE_ESCALATION", "Root/jailbreak detection detected. Verify if the app requires elevated privileges."));
        }

        boolean hasCrypto = collector.malwareFindings.stream()
                .anyMatch(e -> e.getCategory().toLowerCase().contains("crypto") || e.getCategory().toLowerCase().contains("ransom"));
        if (hasCrypto) {
            recommendations.add(new ApkDtos.RiskRecommendationDto(
                    "RANSOMWARE", "Cryptographic operations associated with ransomware detected. Isolate the device immediately."));
        }

        if (recommendations.isEmpty()) {
            recommendations.add(new ApkDtos.RiskRecommendationDto(
                    "GENERAL", "No specific high-risk patterns identified. Continue monitoring and apply standard security hygiene."));
        }

        return recommendations;
    }

    private List<ApkDtos.RiskRecommendationDto> generateRecommendationsFromIndicators(List<RiskIndicator> indicators) {
        List<ApkDtos.RiskRecommendationDto> recommendations = new ArrayList<>();
        Set<String> categories = new HashSet<>();

        for (RiskIndicator i : indicators) {
            String cat = i.getCategory();
            if (categories.add(cat)) {
                switch (cat) {
                    case "THREAT_INTELLIGENCE" ->
                            recommendations.add(new ApkDtos.RiskRecommendationDto("THREAT_INTELLIGENCE", "Quarantine the APK and investigate the associated threat intelligence indicators."));
                    case "DYNAMIC_CODE_LOADING" ->
                            recommendations.add(new ApkDtos.RiskRecommendationDto("DYNAMIC_CODE_LOADING", "Inspect dynamically loaded code and identify the source of the loaded code."));
                    case "SMS_ABUSE" ->
                            recommendations.add(new ApkDtos.RiskRecommendationDto("SMS_ABUSE", "Review SMS access and determine whether the behavior is expected."));
                    case "PERSISTENCE" ->
                            recommendations.add(new ApkDtos.RiskRecommendationDto("PERSISTENCE", "Review automatic startup behavior and determine whether it is legitimate."));
                    case "SUSPICIOUS_URL" ->
                            recommendations.add(new ApkDtos.RiskRecommendationDto("SUSPICIOUS_INFRASTRUCTURE", "Review extracted URLs and investigate their associated infrastructure using approved threat intelligence sources."));
                    case "DATA_EXFILTRATION" ->
                            recommendations.add(new ApkDtos.RiskRecommendationDto("DATA_EXFILTRATION", "Investigate potential data exfiltration. Review network traffic and data access patterns."));
                    case "PRIVILEGE_ESCALATION" ->
                            recommendations.add(new ApkDtos.RiskRecommendationDto("PRIVILEGE_ESCALATION", "Root/jailbreak detection detected. Verify if the app requires elevated privileges."));
                    case "RANSOMWARE" ->
                            recommendations.add(new ApkDtos.RiskRecommendationDto("RANSOMWARE", "Cryptographic operations associated with ransomware detected. Isolate the device immediately."));
                }
            }
        }

        if (recommendations.isEmpty()) {
            recommendations.add(new ApkDtos.RiskRecommendationDto("GENERAL", "No specific high-risk patterns identified. Continue monitoring and apply standard security hygiene."));
        }

        return recommendations;
    }

    private String buildSummary(ApkAnalysis analysis, double score, String riskLevel, String confidence, CategoryScores scores) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Risk assessment for %s (scan %d): Score %.1f/100 - %s risk with %s confidence. ",
                analysis.applicationName != null ? analysis.applicationName : "unknown",
                analysis.scan.getId(), score, riskLevel, confidence));

        List<String> topCategories = new ArrayList<>();
        if (scores.threatIntelligence() > 10) topCategories.add("threat intelligence matches");
        if (scores.staticFindings() > 10) topCategories.add("static malware findings");
        if (scores.suspiciousApis() > 5) topCategories.add("suspicious API calls");
        if (scores.suspiciousPermissions() > 5) topCategories.add("suspicious permissions");
        if (scores.iocIndicators() > 5) topCategories.add("IOC indicators");

        if (!topCategories.isEmpty()) {
            sb.append("Primary contributors: ").append(String.join(", ", topCategories)).append(".");
        } else {
            sb.append("No significant risk contributors identified.");
        }

        if ("MOCK".equalsIgnoreCase(analysis.analysisMode)) {
            sb.append(" NOTE: This assessment is based on MOCK analysis data and does not represent a real malware verdict.");
        }

        return sb.toString();
    }

    private ApkDtos.RiskBreakdownDto buildBreakdownFromIndicators(List<RiskIndicator> indicators) {
        Map<String, Double> sums = new HashMap<>();
        for (RiskIndicator i : indicators) {
            String cat = i.getCategory().toLowerCase().replace("_", "");
            sums.merge(cat, i.getContribution() != null ? i.getContribution() : 0.0, Double::sum);
        }

        double total = sums.values().stream().mapToDouble(Double::doubleValue).sum();

        return new ApkDtos.RiskBreakdownDto(
                round1(sums.getOrDefault("malwarefinding", 0.0)),        // staticFindings
                round1(sums.getOrDefault("threatintelligence", 0.0)),    // threatIntelligence
                round1(sums.getOrDefault("suspiciousapi", 0.0)),         // apiCalls
                round1(sums.getOrDefault("suspiciouspermission", 0.0)),  // permissions
                round1(sums.getOrDefault("iocindicator", 0.0)),          // iocs
                round1(sums.getOrDefault("suspiciousurl", 0.0)),         // urls
                round1(sums.getOrDefault("suspiciouscomponent", 0.0)),   // components
                round1(sums.getOrDefault("obfuscationnative", 0.0)),     // obfuscationNative
                round1(total)
        );
    }

    private ApkDtos.RiskAssessmentResult toResult(RiskAssessment assessment,
                                                   ApkDtos.RiskBreakdownDto breakdown,
                                                   List<RiskIndicator> indicators,
                                                   List<ApkDtos.RiskRecommendationDto> recommendations) {
        return new ApkDtos.RiskAssessmentResult(
                assessment.getId(), assessment.getScanId(), assessment.getScore(),
                assessment.getRiskLevel(), assessment.getConfidence(), assessment.getSummary(),
                breakdown, indicators.stream().map(this::toIndicatorDto).toList(),
                recommendations, assessment.getCreatedAt()
        );
    }

    private ApkDtos.RiskIndicatorDto toIndicatorDto(RiskIndicator i) {
        return new ApkDtos.RiskIndicatorDto(
                i.getId(), i.getSourceType(), i.getSourceId(), i.getCategory(),
                i.getDescription(), i.getSeverity(), i.getConfidence(),
                i.getContribution(), i.getEvidence(), i.getCreatedAt()
        );
    }

    private double round1(double v) { return Math.round(v * 10.0) / 10.0; }
    private double round2(double v) { return Math.round(v * 100.0) / 100.0; }

    private record CategoryScores(
            double staticFindings, double threatIntelligence, double suspiciousApis,
            double suspiciousPermissions, double iocIndicators, double suspiciousUrls,
            double suspiciousComponents, double obfuscationNative, double total
    ) {}

    private interface ScoredEvidence {
        String getSourceType(); Long getSourceId(); String getCategory();
        String getDescription(); String getSeverity(); String getConfidence(); String getEvidence();
    }

    private record ScoredEvidenceImpl(
            String sourceType, Long sourceId, String category,
            String description, String severity, String confidence, String evidence
    ) implements ScoredEvidence {
        @Override public String getSourceType() { return sourceType; }
        @Override public Long getSourceId() { return sourceId; }
        @Override public String getCategory() { return category; }
        @Override public String getDescription() { return description; }
        @Override public String getSeverity() { return severity; }
        @Override public String getConfidence() { return confidence; }
        @Override public String getEvidence() { return evidence; }
    }
}
