package com.cyberintel.service;

import com.cyberintel.entity.ApkAnalysis;
import com.cyberintel.entity.IOC;
import com.cyberintel.entity.ThreatIntelligence;
import com.cyberintel.entity.ThreatMatch;
import com.cyberintel.repository.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.*;
import java.util.stream.*;

@Service
public class ThreatIntelligenceMatchingService {
    private final ThreatIntelligenceRepository threatIntelRepo;
    private final ThreatMatchRepository threatMatchRepo;
    private final IocRepository iocRepo;
    private final ApkAnalysisRepository analysisRepo;

    public ThreatIntelligenceMatchingService(ThreatIntelligenceRepository threatIntelRepo,
                                             ThreatMatchRepository threatMatchRepo,
                                             IocRepository iocRepo,
                                             ApkAnalysisRepository analysisRepo) {
        this.threatIntelRepo = threatIntelRepo;
        this.threatMatchRepo = threatMatchRepo;
        this.iocRepo = iocRepo;
        this.analysisRepo = analysisRepo;
    }

    @Transactional
    public CorrelationResult correlate(Long scanId) {
        var analysis = analysisRepo.findByScanId(scanId).orElseThrow();
        List<IOC> iocs = iocRepo.findByApkAnalysisId(analysis.id);

        int total = iocs.size();
        int matched = 0;
        int noMatch = 0;
        int review = 0;
        int critical = 0, high = 0, medium = 0, low = 0;
        Set<String> categories = new HashSet<>();
        Set<String> families = new HashSet<>();
        List<MatchInfo> matches = new ArrayList<>();

        for (IOC ioc : iocs) {
            var matchResult = matchIoc(ioc);
            if (matchResult.matched()) {
                matched++;
                String sev = matchResult.threatIntelligence().severity;
                switch (sev) {
                    case "CRITICAL" -> critical++;
                    case "HIGH" -> high++;
                    case "MEDIUM" -> medium++;
                    default -> low++;
                }
                if (matchResult.threatIntelligence().category != null) {
                    categories.add(matchResult.threatIntelligence().category);
                }
                if (matchResult.threatIntelligence().threatFamily != null) {
                    families.add(matchResult.threatIntelligence().threatFamily);
                }
                matches.add(new MatchInfo(ioc.id, ioc.value, ioc.type,
                    matchResult.threatIntelligence().id,
                    matchResult.threatIntelligence().threatName,
                    matchResult.threatIntelligence().threatFamily,
                    matchResult.threatIntelligence().category,
                    matchResult.threatIntelligence().severity,
                    matchResult.threatIntelligence().confidence,
                    "MATCHED"));
            } else {
                noMatch++;
                matches.add(new MatchInfo(ioc.id, ioc.value, ioc.type,
                    null, null, null, null, null, null, "NO_MATCH"));
            }
        }

        return new CorrelationResult(scanId, total, matched, noMatch, review, critical, high, medium, low,
            categories, families, matches);
    }

    @Transactional(readOnly = true)
    public CorrelationSummary getCorrelationSummary(Long scanId) {
        var analysis = analysisRepo.findByScanId(scanId).orElseThrow();
        List<IOC> iocs = iocRepo.findByApkAnalysisId(analysis.id);

        int total = iocs.size();
        int matched = 0;
        int critical = 0, high = 0, medium = 0, low = 0;
        Set<String> categories = new HashSet<>();
        Set<String> families = new HashSet<>();

        for (IOC ioc : iocs) {
            List<ThreatMatch> matches = threatMatchRepo.findMatchedByIocId(ioc.id);
            if (!matches.isEmpty()) {
                matched++;
                for (ThreatMatch tm : matches) {
                    ThreatIntelligence ti = tm.threatIntelligence;
                    String sev = ti.severity;
                    switch (sev) {
                        case "CRITICAL" -> critical++;
                        case "HIGH" -> high++;
                        case "MEDIUM" -> medium++;
                        default -> low++;
                    }
                    if (ti.category != null) categories.add(ti.category);
                    if (ti.threatFamily != null) families.add(ti.threatFamily);
                }
            }
        }

        int noMatch = total - matched;
        return new CorrelationSummary(scanId, total, matched, noMatch, 0, critical, high, medium, low, categories, families);
    }

    MatchResult matchIoc(IOC ioc) {
        List<ThreatIntelligence> exactMatches = threatIntelRepo.findByIndicatorAndType(ioc.value, ioc.type);
        if (!exactMatches.isEmpty()) {
            ThreatIntelligence ti = exactMatches.get(0);
            createOrUpdateMatch(ioc, ti, "EXACT", "MATCHED", ti.confidence, ti.severity,
                "Exact match found in local threat intelligence database");
            return new MatchResult(true, ti);
        }
        return new MatchResult(false, null);
    }

    private void createOrUpdateMatch(IOC ioc, ThreatIntelligence ti, String matchType, String status,
                                     String confidence, String severity, String description) {
        Optional<ThreatMatch> existing = threatMatchRepo.findByIocId(ioc.id).stream()
            .filter(tm -> tm.threatIntelligence.id.equals(ti.id))
            .findFirst();

        if (existing.isPresent()) {
            ThreatMatch tm = existing.get();
            tm.matchType = matchType;
            tm.status = status;
            tm.confidence = confidence;
            tm.severity = severity;
            tm.description = description;
            tm.matchedAt = Instant.now();
            threatMatchRepo.save(tm);
        } else {
            ThreatMatch tm = new ThreatMatch();
            tm.ioc = ioc;
            tm.threatIntelligence = ti;
            tm.matchType = matchType;
            tm.status = status;
            tm.confidence = confidence;
            tm.severity = severity;
            tm.description = description;
            threatMatchRepo.save(tm);
        }
    }

    @Transactional
    public void clearMatches(Long scanId) {
        var analysis = analysisRepo.findByScanId(scanId).orElseThrow();
        List<IOC> iocs = iocRepo.findByApkAnalysisId(analysis.id);
        for (IOC ioc : iocs) {
            threatMatchRepo.deleteByIocId(ioc.id);
        }
    }

    @Transactional(readOnly = true)
    public List<ThreatIntelligenceSearchResult> search(String indicator) {
        List<ThreatIntelligence> results = threatIntelRepo.findByIndicatorExact(indicator);
        return results.stream().map(ti -> new ThreatIntelligenceSearchResult(
            ti.id, ti.indicator, ti.indicatorType, ti.threatName,
            ti.threatFamily, ti.category, ti.severity, ti.confidence,
            ti.description, ti.source, ti.firstSeen, ti.lastSeen)).toList();
    }

    public record MatchResult(boolean matched, ThreatIntelligence threatIntelligence) {}
    public record MatchInfo(Long iocId, String iocValue, String iocType, Long threatIntelligenceId,
                            String threatName, String threatFamily, String category,
                            String severity, String confidence, String status) {}
    public record CorrelationResult(Long scanId, int totalIocs, int matched, int noMatch, int review,
                                    int critical, int high, int medium, int low,
                                    Set<String> categories, Set<String> families, List<MatchInfo> matches) {}
    public record CorrelationSummary(Long scanId, int totalIocs, int matched, int noMatch, int review,
                                     int critical, int high, int medium, int low,
                                     Set<String> categories, Set<String> families) {}
    public record ThreatIntelligenceSearchResult(Long id, String indicator, String indicatorType,
                                                 String threatName, String threatFamily, String category,
                                                 String severity, String confidence, String description,
                                                 String source, Instant firstSeen, Instant lastSeen) {}
}