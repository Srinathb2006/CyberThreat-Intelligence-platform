package com.cyberintel.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "url_scans")
public class UrlScan {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "scan_id", nullable = false, unique = true)
    private Scan scan;
    @Column(name = "analysis_json", nullable = false, columnDefinition = "TEXT")
    private String analysisJson;

    protected UrlScan() {}
    public UrlScan(Scan scan, String analysisJson) { this.scan = scan; this.analysisJson = analysisJson; }
    public Scan getScan() { return scan; }
    public String getAnalysisJson() { return analysisJson; }
}
