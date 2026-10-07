package com.cyberintel.service;

import com.cyberintel.dto.UrlScanDtos.*;
import com.cyberintel.entity.Scan;
import com.cyberintel.entity.UrlScan;
import com.cyberintel.exception.ApiException;
import com.cyberintel.repository.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;
import java.util.List;

@Service
@Transactional
public class UrlScanService {
    private final UrlStaticAnalyzer analyzer;
    private final ScanRepository scans;
    private final UrlScanRepository results;
    private final UserRepository users;
    private final ObjectMapper json;

    public UrlScanService(UrlStaticAnalyzer analyzer, ScanRepository scans, UrlScanRepository results,
                          UserRepository users, ObjectMapper json) {
        this.analyzer = analyzer; this.scans = scans; this.results = results; this.users = users; this.json = json;
    }
    public Result create(String url, String email) {
        Analysis analysis = analyzer.analyze(url);
        var user = users.findByEmail(email).orElseThrow(() -> new ApiException(HttpStatus.UNAUTHORIZED, "Authentication required."));
        Scan scan = new Scan(Scan.ScanType.URL, url, user);
        scan.setStatus(Scan.Status.COMPLETED);
        scan.setCompletedAt(Instant.now());
        scan.setRiskScore(analysis.score());
        scan.setRiskLevel(Scan.RiskLevel.valueOf(analysis.riskLevel()));
        try {
            String snapshot = json.writeValueAsString(analysis);
            scans.save(scan);
            results.save(new UrlScan(scan, snapshot));
            return new Result(scan.getId(), scan.getTarget(), scan.getStatus().name(), scan.getCreatedAt(), analysis);
        } catch (JsonProcessingException e) { throw new IllegalStateException("Unable to save URL analysis", e); }
    }
    @Transactional(readOnly = true)
    public Result get(Long scanId, String email) {
        return toResult(results.findByScanIdAndScanUserEmail(scanId, email)
                .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "URL scan not found.")));
    }
    @Transactional(readOnly = true)
    public List<Result> history(String email) {
        return results.findTop50ByScanUserEmailOrderByScanCreatedAtDescScanIdDesc(email).stream().map(this::toResult).toList();
    }
    private Result toResult(UrlScan result) {
        Scan scan = result.getScan();
        try {
            return new Result(scan.getId(), scan.getTarget(), scan.getStatus().name(), scan.getCreatedAt(),
                    json.readValue(result.getAnalysisJson(), Analysis.class));
        } catch (JsonProcessingException e) { throw new IllegalStateException("Unable to load URL analysis", e); }
    }
}
