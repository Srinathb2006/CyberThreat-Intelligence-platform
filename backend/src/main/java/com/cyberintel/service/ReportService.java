package com.cyberintel.service;

import com.cyberintel.entity.*;
import com.cyberintel.repository.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.lowagie.text.*;
import com.lowagie.text.pdf.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;


@Service
@Transactional(readOnly = true)
public class ReportService {

    private final ScanRepository scanRepository;
    private final ApkAnalysisRepository apkAnalysisRepository;
    private final MalwareFindingRepository malwareFindingRepository;
    private final IocRepository iocRepository;
    private final ThreatMatchRepository threatMatchRepository;
    private final RiskAssessmentRepository riskAssessmentRepository;
    private final RiskIndicatorRepository riskIndicatorRepository;
    private final AlertRepository alertRepository;
    private final ObjectMapper objectMapper;

    public ReportService(
            ScanRepository scanRepository,
            ApkAnalysisRepository apkAnalysisRepository,
            MalwareFindingRepository malwareFindingRepository,
            IocRepository iocRepository,
            ThreatMatchRepository threatMatchRepository,
            RiskAssessmentRepository riskAssessmentRepository,
            RiskIndicatorRepository riskIndicatorRepository,
            AlertRepository alertRepository) {
        this.scanRepository = scanRepository;
        this.apkAnalysisRepository = apkAnalysisRepository;
        this.malwareFindingRepository = malwareFindingRepository;
        this.iocRepository = iocRepository;
        this.threatMatchRepository = threatMatchRepository;
        this.riskAssessmentRepository = riskAssessmentRepository;
        this.riskIndicatorRepository = riskIndicatorRepository;
        this.alertRepository = alertRepository;

        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    // =========================================================================
    // 1. PDF REPORT GENERATION
    // =========================================================================

    public byte[] generatePdfReport(Long scanId) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new NoSuchElementException("Scan not found for id: " + scanId));
        ApkAnalysis analysis = apkAnalysisRepository.findByScanId(scanId).orElse(null);
        RiskAssessment assessment = riskAssessmentRepository.findByScanIdAndIsLatestTrue(scanId).orElse(null);

        List<MalwareFinding> malwareFindings = analysis != null
                ? malwareFindingRepository.findByApkAnalysisId(analysis.id) : Collections.emptyList();
        List<IOC> iocs = analysis != null
                ? iocRepository.findByApkAnalysisId(analysis.id) : Collections.emptyList();

        List<ThreatMatch> threatMatches = new ArrayList<>();
        for (IOC ioc : iocs) {
            threatMatches.addAll(threatMatchRepository.findMatchedByIocId(ioc.id));
        }

        List<RiskIndicator> indicators = assessment != null
                ? riskIndicatorRepository.findByRiskAssessmentIdOrderByContributionDesc(assessment.getId()) : Collections.emptyList();
        List<Alert> alerts = alertRepository.findByScanIdOrderByCreatedAtDesc(scanId);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            Document document = new Document(PageSize.A4, 36, 36, 36, 36);
            PdfWriter.getInstance(document, baos);
            document.open();

            // Colors
            Color primaryColor = new Color(21, 34, 54);
            Color headerBg = new Color(30, 48, 77);
            Color darkText = new Color(20, 20, 20);
            Color grayText = new Color(100, 100, 100);

            // Fonts
            Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 20, primaryColor);
            Font subtitleFont = FontFactory.getFont(FontFactory.HELVETICA, 11, grayText);
            Font h1Font = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 13, primaryColor);
            Font boldFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, darkText);
            Font regularFont = FontFactory.getFont(FontFactory.HELVETICA, 9, darkText);
            Font thFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9, Color.WHITE);

            // Title Banner
            Paragraph title = new Paragraph("CYBERINTEL SECURITY REPORT", titleFont);
            title.setAlignment(Element.ALIGN_LEFT);
            document.add(title);

            String targetName = analysis != null && analysis.applicationName != null
                    ? analysis.applicationName : scan.getTarget();
            Paragraph sub = new Paragraph("APK Threat & Vulnerability Assessment: " + targetName, subtitleFont);
            document.add(sub);
            document.add(new Paragraph("Generated at: " + DATE_FMT.format(java.time.Instant.now()), subtitleFont));
            document.add(Chunk.NEWLINE);

            // Executive Summary Table
            document.add(new Paragraph("1. EXECUTIVE SUMMARY & RISK VERDICT", h1Font));
            document.add(Chunk.NEWLINE);

            PdfPTable summaryTable = new PdfPTable(2);
            summaryTable.setWidthPercentage(100);
            summaryTable.setSpacingBefore(4f);
            summaryTable.setSpacingAfter(10f);

            addTableCell(summaryTable, "Target Application", targetName, boldFont, regularFont);
            addTableCell(summaryTable, "Package Name", analysis != null && analysis.packageName != null ? analysis.packageName : "N/A", boldFont, regularFont);
            addTableCell(summaryTable, "SHA-256 Hash", analysis != null && analysis.sha256 != null ? analysis.sha256 : "N/A", boldFont, regularFont);
            addTableCell(summaryTable, "Risk Score / Level", (scan.getRiskScore() != null ? scan.getRiskScore() + "/100" : "N/A") + " (" + scan.getRiskLevel() + ")", boldFont, regularFont);
            addTableCell(summaryTable, "Total Findings", String.valueOf(malwareFindings.size()), boldFont, regularFont);
            addTableCell(summaryTable, "Extracted IOCs", String.valueOf(iocs.size()), boldFont, regularFont);
            addTableCell(summaryTable, "Threat Intelligence Matches", String.valueOf(threatMatches.size()), boldFont, regularFont);
            addTableCell(summaryTable, "Security Alerts", String.valueOf(alerts.size()), boldFont, regularFont);
            document.add(summaryTable);

            // Assessment Summary
            if (assessment != null && assessment.getSummary() != null) {
                Paragraph p = new Paragraph("Assessment Notes: " + assessment.getSummary(), regularFont);
                p.setSpacingAfter(10f);
                document.add(p);
            }

            // 2. Risk Indicators Table
            if (!indicators.isEmpty()) {
                document.add(new Paragraph("2. TOP RISK INDICATORS", h1Font));
                PdfPTable indTable = new PdfPTable(new float[]{2.5f, 5.0f, 1.5f, 1.5f, 1.5f});
                indTable.setWidthPercentage(100);
                indTable.setSpacingBefore(6f);
                indTable.setSpacingAfter(12f);

                addTableHeader(indTable, headerBg, thFont, "Category", "Description", "Severity", "Confidence", "Contribution");
                for (RiskIndicator ind : indicators) {
                    indTable.addCell(new Phrase(ind.getCategory(), regularFont));
                    indTable.addCell(new Phrase(ind.getDescription() != null ? ind.getDescription() : "", regularFont));
                    indTable.addCell(new Phrase(ind.getSeverity(), regularFont));
                    indTable.addCell(new Phrase(ind.getConfidence(), regularFont));
                    indTable.addCell(new Phrase(String.valueOf(ind.getContribution()), regularFont));
                }
                document.add(indTable);
            }

            // 3. Malware Findings
            if (!malwareFindings.isEmpty()) {
                document.add(new Paragraph("3. MALWARE FINDINGS", h1Font));
                PdfPTable mfTable = new PdfPTable(new float[]{2.0f, 3.5f, 4.5f, 1.5f, 1.5f});
                mfTable.setWidthPercentage(100);
                mfTable.setSpacingBefore(6f);
                mfTable.setSpacingAfter(12f);

                addTableHeader(mfTable, headerBg, thFont, "Category", "Title", "Evidence", "Severity", "Confidence");
                for (MalwareFinding mf : malwareFindings) {
                    mfTable.addCell(new Phrase(mf.category != null ? mf.category : "", regularFont));
                    mfTable.addCell(new Phrase(mf.title != null ? mf.title : "", regularFont));
                    mfTable.addCell(new Phrase(mf.evidence != null ? truncate(mf.evidence, 60) : "", regularFont));
                    mfTable.addCell(new Phrase(mf.severity != null ? mf.severity : "", regularFont));
                    mfTable.addCell(new Phrase(mf.confidence != null ? mf.confidence : "", regularFont));
                }
                document.add(mfTable);
            }

            // 4. Threat Matches & IOCs
            if (!threatMatches.isEmpty()) {
                document.add(new Paragraph("4. THREAT INTELLIGENCE MATCHES", h1Font));
                PdfPTable tmTable = new PdfPTable(new float[]{3.0f, 2.5f, 2.5f, 1.5f, 1.5f});
                tmTable.setWidthPercentage(100);
                tmTable.setSpacingBefore(6f);
                tmTable.setSpacingAfter(12f);

                addTableHeader(tmTable, headerBg, thFont, "Indicator", "Threat Name", "Family", "Severity", "Confidence");
                for (ThreatMatch tm : threatMatches) {
                    String ind = tm.threatIntelligence != null ? tm.threatIntelligence.indicator : "N/A";
                    String name = tm.threatIntelligence != null ? tm.threatIntelligence.threatName : "N/A";
                    String fam = tm.threatIntelligence != null ? tm.threatIntelligence.threatFamily : "N/A";
                    tmTable.addCell(new Phrase(ind, regularFont));
                    tmTable.addCell(new Phrase(name, regularFont));
                    tmTable.addCell(new Phrase(fam, regularFont));
                    tmTable.addCell(new Phrase(tm.severity != null ? tm.severity : "", regularFont));
                    tmTable.addCell(new Phrase(tm.confidence != null ? tm.confidence : "", regularFont));
                }
                document.add(tmTable);
            }

            // 5. Security Alerts
            if (!alerts.isEmpty()) {
                document.add(new Paragraph("5. GENERATED SECURITY ALERTS", h1Font));
                PdfPTable alertTable = new PdfPTable(new float[]{4.0f, 1.5f, 1.5f, 4.0f});
                alertTable.setWidthPercentage(100);
                alertTable.setSpacingBefore(6f);
                alertTable.setSpacingAfter(12f);

                addTableHeader(alertTable, headerBg, thFont, "Alert Title", "Severity", "Status", "Source");
                for (Alert a : alerts) {
                    alertTable.addCell(new Phrase(a.getTitle(), regularFont));
                    alertTable.addCell(new Phrase(a.getSeverity() != null ? a.getSeverity().name() : "", regularFont));
                    alertTable.addCell(new Phrase(a.getStatus() != null ? a.getStatus().name() : "", regularFont));
                    alertTable.addCell(new Phrase(a.getSource() != null ? a.getSource() : "", regularFont));
                }
                document.add(alertTable);
            }

            document.close();
            return baos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate PDF report: " + e.getMessage(), e);
        }
    }

    private void addTableCell(PdfPTable table, String label, String value, Font labelFont, Font valueFont) {
        PdfPCell c1 = new PdfPCell(new Phrase(label, labelFont));
        c1.setBackgroundColor(new Color(245, 247, 250));
        c1.setPadding(5f);
        table.addCell(c1);

        PdfPCell c2 = new PdfPCell(new Phrase(value, valueFont));
        c2.setPadding(5f);
        table.addCell(c2);
    }

    private void addTableHeader(PdfPTable table, Color bg, Font font, String... headers) {
        for (String h : headers) {
            PdfPCell cell = new PdfPCell(new Phrase(h, font));
            cell.setBackgroundColor(bg);
            cell.setPadding(6f);
            table.addCell(cell);
        }
    }

    private String truncate(String text, int max) {
        if (text == null) return "";
        return text.length() <= max ? text : text.substring(0, max) + "...";
    }

    // =========================================================================
    // 2. JSON REPORT GENERATION
    // =========================================================================

    public byte[] generateJsonReport(Long scanId) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new NoSuchElementException("Scan not found for id: " + scanId));
        ApkAnalysis analysis = apkAnalysisRepository.findByScanId(scanId).orElse(null);
        RiskAssessment assessment = riskAssessmentRepository.findByScanIdAndIsLatestTrue(scanId).orElse(null);

        List<MalwareFinding> malwareFindings = analysis != null
                ? malwareFindingRepository.findByApkAnalysisId(analysis.id) : Collections.emptyList();
        List<IOC> iocs = analysis != null
                ? iocRepository.findByApkAnalysisId(analysis.id) : Collections.emptyList();

        List<ThreatMatch> threatMatches = new ArrayList<>();
        for (IOC ioc : iocs) {
            threatMatches.addAll(threatMatchRepository.findMatchedByIocId(ioc.id));
        }

        List<RiskIndicator> indicators = assessment != null
                ? riskIndicatorRepository.findByRiskAssessmentId(assessment.getId()) : Collections.emptyList();
        List<Alert> alerts = alertRepository.findByScanIdOrderByCreatedAtDesc(scanId);

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("reportTitle", "CyberIntel Security Report");
        report.put("generatedAt", Instant.now().toString());

        Map<String, Object> scanInfo = new LinkedHashMap<>();
        scanInfo.put("scanId", scan.getId());
        scanInfo.put("scanType", scan.getScanType() != null ? scan.getScanType().name() : null);
        scanInfo.put("target", scan.getTarget());
        scanInfo.put("status", scan.getStatus() != null ? scan.getStatus().name() : null);
        scanInfo.put("riskScore", scan.getRiskScore());
        scanInfo.put("riskLevel", scan.getRiskLevel() != null ? scan.getRiskLevel().name() : null);
        scanInfo.put("createdAt", scan.getCreatedAt());
        scanInfo.put("completedAt", scan.getCompletedAt());
        report.put("scan", scanInfo);

        if (analysis != null) {
            Map<String, Object> apkInfo = new LinkedHashMap<>();
            apkInfo.put("packageName", analysis.packageName);
            apkInfo.put("applicationName", analysis.applicationName);
            apkInfo.put("versionName", analysis.versionName);
            apkInfo.put("versionCode", analysis.versionCode);
            apkInfo.put("minSdk", analysis.minSdk);
            apkInfo.put("targetSdk", analysis.targetSdk);
            apkInfo.put("sha256", analysis.sha256);
            apkInfo.put("md5", analysis.md5);
            apkInfo.put("fileSize", analysis.fileSize);
            apkInfo.put("permissionsCount", analysis.permissions != null ? analysis.permissions.size() : 0);
            apkInfo.put("componentsCount", analysis.components != null ? analysis.components.size() : 0);
            apkInfo.put("apiFindingsCount", analysis.apiFindings != null ? analysis.apiFindings.size() : 0);
            report.put("apkAnalysis", apkInfo);
        }

        if (assessment != null) {
            Map<String, Object> assessMap = new LinkedHashMap<>();
            assessMap.put("score", assessment.getScore());
            assessMap.put("riskLevel", assessment.getRiskLevel());
            assessMap.put("confidence", assessment.getConfidence());
            assessMap.put("summary", assessment.getSummary());
            assessMap.put("indicators", indicators);
            report.put("riskAssessment", assessMap);
        }

        report.put("malwareFindings", malwareFindings);
        report.put("iocs", iocs);
        report.put("threatMatches", threatMatches);
        report.put("alerts", alerts.stream().map(a -> Map.of(
                "id", a.getId(),
                "title", a.getTitle(),
                "description", a.getDescription(),
                "severity", a.getSeverity() != null ? a.getSeverity().name() : "N/A",
                "status", a.getStatus() != null ? a.getStatus().name() : "N/A",
                "source", a.getSource() != null ? a.getSource() : ""
        )).toList());

        try {
            return objectMapper.writeValueAsBytes(report);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate JSON report: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    // 3. FINDINGS CSV GENERATION
    // =========================================================================

    public byte[] generateFindingsCsv(Long scanId) {
        ApkAnalysis analysis = apkAnalysisRepository.findByScanId(scanId)
                .orElseThrow(() -> new NoSuchElementException("Analysis not found for scanId: " + scanId));

        List<MalwareFinding> findings = malwareFindingRepository.findByApkAnalysisId(analysis.id);

        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        pw.println("Category,Severity,Confidence,Title,Description,Evidence,RuleId,Source");

        for (MalwareFinding f : findings) {
            pw.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n",
                    csv(f.category),
                    csv(f.severity),
                    csv(f.confidence),
                    csv(f.title),
                    csv(f.description),
                    csv(f.evidence),
                    csv(f.ruleId),
                    csv(f.source)
            );
        }
        return sw.toString().getBytes(StandardCharsets.UTF_8);
    }

    // =========================================================================
    // 4. IOC CSV GENERATION
    // =========================================================================

    public byte[] generateIocCsv(Long scanId) {
        ApkAnalysis analysis = apkAnalysisRepository.findByScanId(scanId)
                .orElseThrow(() -> new NoSuchElementException("Analysis not found for scanId: " + scanId));

        List<IOC> iocs = iocRepository.findByApkAnalysisId(analysis.id);

        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        pw.println("Type,Value,Severity,Confidence,Source,Description");

        for (IOC ioc : iocs) {
            pw.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n",
                    csv(ioc.type),
                    csv(ioc.value),
                    csv(ioc.severity),
                    csv(ioc.confidence),
                    csv(ioc.source),
                    csv(ioc.description)
            );
        }
        return sw.toString().getBytes(StandardCharsets.UTF_8);
    }

    // =========================================================================
    // 5. THREAT MATCH CSV GENERATION
    // =========================================================================

    public byte[] generateThreatMatchCsv(Long scanId) {
        ApkAnalysis analysis = apkAnalysisRepository.findByScanId(scanId)
                .orElseThrow(() -> new NoSuchElementException("Analysis not found for scanId: " + scanId));

        List<IOC> iocs = iocRepository.findByApkAnalysisId(analysis.id);
        List<ThreatMatch> matches = new ArrayList<>();
        for (IOC ioc : iocs) {
            matches.addAll(threatMatchRepository.findMatchedByIocId(ioc.id));
        }

        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        pw.println("Indicator,IndicatorType,ThreatName,ThreatFamily,Category,MatchType,Severity,Confidence,MatchedAt,Description");

        for (ThreatMatch tm : matches) {
            ThreatIntelligence ti = tm.threatIntelligence;
            pw.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n",
                    ti != null ? csv(ti.indicator) : "",
                    ti != null ? csv(ti.indicatorType) : "",
                    ti != null ? csv(ti.threatName) : "",
                    ti != null ? csv(ti.threatFamily) : "",
                    ti != null ? csv(ti.category) : "",
                    csv(tm.matchType),
                    csv(tm.severity),
                    csv(tm.confidence),
                    tm.matchedAt != null ? tm.matchedAt.toString() : "",
                    csv(tm.description)
            );
        }
        return sw.toString().getBytes(StandardCharsets.UTF_8);
    }

    // =========================================================================
    // 6. SUMMARY CSV GENERATION
    // =========================================================================

    public byte[] generateSummaryCsv(Long scanId) {
        Scan scan = scanRepository.findById(scanId)
                .orElseThrow(() -> new NoSuchElementException("Scan not found for scanId: " + scanId));
        ApkAnalysis analysis = apkAnalysisRepository.findByScanId(scanId).orElse(null);
        RiskAssessment assessment = riskAssessmentRepository.findByScanIdAndIsLatestTrue(scanId).orElse(null);

        long findingsCount = analysis != null ? malwareFindingRepository.countByApkAnalysisId(analysis.id) : 0;
        long iocCount = analysis != null ? iocRepository.countByApkAnalysisId(analysis.id) : 0;
        long alertCount = alertRepository.findByScanIdOrderByCreatedAtDesc(scanId).size();

        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        pw.println("Metric,Value");
        pw.printf("\"%s\",\"%s\"%n", "Scan ID", scan.getId());
        pw.printf("\"%s\",\"%s\"%n", "Target", csv(scan.getTarget()));
        pw.printf("\"%s\",\"%s\"%n", "Application Name", analysis != null ? csv(analysis.applicationName) : "N/A");
        pw.printf("\"%s\",\"%s\"%n", "Package Name", analysis != null ? csv(analysis.packageName) : "N/A");
        pw.printf("\"%s\",\"%s\"%n", "SHA-256", analysis != null ? csv(analysis.sha256) : "N/A");
        pw.printf("\"%s\",\"%s\"%n", "Risk Score", scan.getRiskScore() != null ? scan.getRiskScore() : "N/A");
        pw.printf("\"%s\",\"%s\"%n", "Risk Level", scan.getRiskLevel() != null ? scan.getRiskLevel().name() : "N/A");
        pw.printf("\"%s\",\"%s\"%n", "Total Findings", findingsCount);
        pw.printf("\"%s\",\"%s\"%n", "Extracted IOCs", iocCount);
        pw.printf("\"%s\",\"%s\"%n", "Generated Alerts", alertCount);
        pw.printf("\"%s\",\"%s\"%n", "Created At", scan.getCreatedAt() != null ? scan.getCreatedAt().toString() : "");

        if (assessment != null && assessment.getSummary() != null) {
            pw.printf("\"%s\",\"%s\"%n", "Assessment Summary", csv(assessment.getSummary()));
        }

        return sw.toString().getBytes(StandardCharsets.UTF_8);
    }

    private String csv(String val) {
        if (val == null) return "";
        return val.replace("\"", "\"\"");
    }
}
