package com.cyberintel.service;

import com.cyberintel.dto.UrlScanDtos.Finding;
import com.cyberintel.exception.ApiException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.*;

class UrlStaticAnalyzerTest {
    private final UrlStaticAnalyzer analyzer = new UrlStaticAnalyzer();

    @Test void parsesStructureWithoutResolvingDomains() {
        var result = analyzer.analyze("https://never-resolve.invalid:443/docs?a=1#section");
        assertThat(result.host()).isEqualTo("never-resolve.invalid");
        assertThat(result.domain()).isEqualTo(result.host());
        assertThat(result.ipAddress()).isNull();
        assertThat(result.https()).isTrue();
        assertThat(result.port()).isEqualTo(443);
        assertThat(result.path()).isEqualTo("/docs");
        assertThat(result.queryPresent()).isTrue();
        assertThat(result.fragmentPresent()).isTrue();
        assertThat(result.score()).isZero();
        assertThat(result.findings()).isEmpty();
    }
    @Test void identifiesIndependentHeuristicsAndEncodedKeywords() {
        var result = analyzer.analyze("http://a.b.c.d.example.zip:8080/%2576erify?account=urgent");
        assertThat(result.findings()).extracting(Finding::code).containsExactly(
                "NO_HTTPS", "SUSPICIOUS_TLD", "MANY_SUBDOMAINS", "UNUSUAL_PORT", "NESTED_ENCODING", "SUSPICIOUS_KEYWORDS");
        assertThat(result.score()).isEqualTo(65);
        assertThat(result.riskLevel()).isEqualTo("HIGH");
        assertThat(result.findings().get(5).evidence()).contains("verify", "account", "urgent");
    }
    @ParameterizedTest @ValueSource(strings = {"https://127.0.0.1/", "https://10.0.0.1/", "https://172.16.1.2/", "https://192.168.2.3/", "https://169.254.169.254/", "https://[::1]/", "https://[0:0:0:0:0:0:0:1]/", "https://[fc00::1]/", "https://[fe80::1]/", "https://[::ffff:127.0.0.1]/"})
    void analyzesLocalIpLiteralsAsText(String url) {
        var result = analyzer.analyze(url);
        assertThat(result.domain()).isNull();
        assertThat(result.ipAddress()).isNotBlank();
        assertThat(result.findings()).extracting(Finding::code).contains("IP_BASED_URL", "NON_PUBLIC_IP");
    }
    @ParameterizedTest @ValueSource(strings = {"https://8.8.8.8/", "https://[2606:4700:4700::1111]/"})
    void publicIpDoesNotReceiveLocalFlag(String url) {
        assertThat(analyzer.analyze(url).findings()).extracting(Finding::code)
                .contains("IP_BASED_URL").doesNotContain("NON_PUBLIC_IP");
    }
    @Test void normalizesInternationalDomainWithoutNetworkAccess() {
        var result = analyzer.analyze("HTTPS://bücher.example/");
        assertThat(result.host()).isEqualTo("xn--bcher-kva.example");
        assertThat(result.findings()).extracting(Finding::code).contains("INTERNATIONALIZED_DOMAIN");
        assertThat(analyzer.analyze("https://xn--bcher-kva.example/").findings()).isEqualTo(result.findings());
    }
    @ParameterizedTest @ValueSource(strings = {"", "example.com", "//example.com", "javascript:alert(1)", "file:///etc/passwd", "ftp://example.com", "https:///path", "https://user:pass@example.com", "https://good.example@evil.example", "https://example.com\\@evil.example", "https://example.com/a b", "https://example.com/%0d%0aHeader", "https://example.com/%250a", "https://example.com/%5c", "https://example.com/%zz", "https://example.com:0", "https://example.com:65536", "https://example.com:", "https://example.com:abc", "https://[not-ip]/", "https://[fe80::1%25eth0]/", "https://%65xample.com", "https://a..com", "https://-a.com", "https://127.1", "https://2130706433", "https://0x7f000001", "https://0177.0.0.1", "https://256.0.0.1", "https://example.com/\u202eevil"})
    void rejectsMalformedOrAmbiguousInput(String url) {
        assertThatThrownBy(() -> analyzer.analyze(url)).isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException)e).getStatus().value()).isEqualTo(400));
    }
    @Test void enforcesLengthAndAllowsLegitimateEncoding() {
        assertThatThrownBy(() -> analyzer.analyze(null)).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> analyzer.analyze("https://example.com/" + "a".repeat(2048))).isInstanceOf(ApiException.class);
        assertThat(analyzer.analyze("https://example.com/hello%20world?q=a+b").findings())
                .extracting(Finding::code).containsExactly("PERCENT_ENCODING");
    }
    @ParameterizedTest @ValueSource(strings = {"https://example.123", "https://example.0x7f", "https://example.com/%2525250a", "https://example.com/%25foo%250a", "https://example.com/%c0%af"})
    void rejectsDeeplyEncodedControlsAndNumericDomainSuffixes(String url) {
        assertThatThrownBy(() -> analyzer.analyze(url)).isInstanceOf(ApiException.class);
    }
}
