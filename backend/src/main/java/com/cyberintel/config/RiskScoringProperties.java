package com.cyberintel.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "risk.scoring")
public class RiskScoringProperties {

    private Weights weights = new Weights();
    private SeverityMultipliers severity = new SeverityMultipliers();
    private ConfidenceMultipliers confidence = new ConfidenceMultipliers();

    public Weights getWeights() { return weights; }
    public void setWeights(Weights weights) { this.weights = weights; }

    public SeverityMultipliers getSeverity() { return severity; }
    public void setSeverity(SeverityMultipliers severity) { this.severity = severity; }

    public ConfidenceMultipliers getConfidence() { return confidence; }
    public void setConfidence(ConfidenceMultipliers confidence) { this.confidence = confidence; }

    public static class Weights {
        private Double staticFindings = 25.0;
        private Double threatIntelligence = 30.0;
        private Double suspiciousApis = 15.0;
        private Double suspiciousPermissions = 10.0;
        private Double iocIndicators = 10.0;
        private Double suspiciousUrls = 5.0;
        private Double suspiciousComponents = 3.0;
        private Double obfuscationNative = 2.0;

        public Double getStaticFindings() { return staticFindings; }
        public void setStaticFindings(Double staticFindings) { this.staticFindings = staticFindings; }
        public Double getThreatIntelligence() { return threatIntelligence; }
        public void setThreatIntelligence(Double threatIntelligence) { this.threatIntelligence = threatIntelligence; }
        public Double getSuspiciousApis() { return suspiciousApis; }
        public void setSuspiciousApis(Double suspiciousApis) { this.suspiciousApis = suspiciousApis; }
        public Double getSuspiciousPermissions() { return suspiciousPermissions; }
        public void setSuspiciousPermissions(Double suspiciousPermissions) { this.suspiciousPermissions = suspiciousPermissions; }
        public Double getIocIndicators() { return iocIndicators; }
        public void setIocIndicators(Double iocIndicators) { this.iocIndicators = iocIndicators; }
        public Double getSuspiciousUrls() { return suspiciousUrls; }
        public void setSuspiciousUrls(Double suspiciousUrls) { this.suspiciousUrls = suspiciousUrls; }
        public Double getSuspiciousComponents() { return suspiciousComponents; }
        public void setSuspiciousComponents(Double suspiciousComponents) { this.suspiciousComponents = suspiciousComponents; }
        public Double getObfuscationNative() { return obfuscationNative; }
        public void setObfuscationNative(Double obfuscationNative) { this.obfuscationNative = obfuscationNative; }
    }

    public static class SeverityMultipliers {
        private Double low = 0.25;
        private Double medium = 0.50;
        private Double high = 0.75;
        private Double critical = 1.00;

        public Double getLow() { return low; }
        public void setLow(Double low) { this.low = low; }
        public Double getMedium() { return medium; }
        public void setMedium(Double medium) { this.medium = medium; }
        public Double getHigh() { return high; }
        public void setHigh(Double high) { this.high = high; }
        public Double getCritical() { return critical; }
        public void setCritical(Double critical) { this.critical = critical; }
    }

    public static class ConfidenceMultipliers {
        private Double low = 0.50;
        private Double medium = 0.75;
        private Double high = 1.00;

        public Double getLow() { return low; }
        public void setLow(Double low) { this.low = low; }
        public Double getMedium() { return medium; }
        public void setMedium(Double medium) { this.medium = medium; }
        public Double getHigh() { return high; }
        public void setHigh(Double high) { this.high = high; }
    }
}