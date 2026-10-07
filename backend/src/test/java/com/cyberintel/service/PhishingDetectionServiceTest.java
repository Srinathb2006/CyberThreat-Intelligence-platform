package com.cyberintel.service;

import com.cyberintel.dto.PhishingDtos.Reason;
import com.cyberintel.exception.ApiException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.*;

class PhishingDetectionServiceTest {
    private final PhishingDetectionService service = new PhishingDetectionService(new UrlStaticAnalyzer());

    @Test void cleanUnresolvableUrlHasNoHeuristicFindings() {
        var result = service.analyze("https://never-resolve.invalid/docs");
        assertThat(result.host()).isEqualTo("never-resolve.invalid");
        assertThat(result.https()).isTrue();
        assertThat(result.ipBased()).isFalse();
        assertThat(result.score()).isZero();
        assertThat(result.riskLevel()).isEqualTo("LOW");
        assertThat(result.reasons()).isEmpty();
        assertThat(result.redirectIndicators()).isEmpty();
    }
    @Test void explainsDomainPatternsAndCapsTheSum() {
        String url = "http://login-verify-account-urgent123456789012345.zip:8080/%76erify?q=" + "a".repeat(320);
        var result = service.analyze(url);
        assertThat(result.reasons()).extracting(Reason::code).contains("NO_HTTPS", "SUSPICIOUS_TLD", "HYPHENATED_DOMAIN",
                "LONG_DOMAIN_LABEL", "DIGIT_HEAVY_DOMAIN", "CREDENTIAL_DOMAIN_PATTERN", "CREDENTIAL_PRESSURE_LURE", "SUSPICIOUS_KEYWORDS");
        assertThat(result.reasons().stream().mapToInt(Reason::contribution).sum()).isGreaterThan(100);
        assertThat(result.score()).isEqualTo(100);
        assertThat(result.riskLevel()).isEqualTo("CRITICAL");
        assertThat(result).isEqualTo(service.analyze(url));
        assertThat(result.reasons()).allSatisfy(reason -> {
            assertThat(reason.description()).isNotBlank();
            assertThat(reason.evidence()).isNotBlank();
            assertThat(reason.contribution()).isPositive();
        });
    }
    @Test void httpsDoesNotEraseSuspiciousSignals() {
        var result = service.analyze("https://login-verify-account.example/urgent");
        assertThat(result.reasons()).extracting(Reason::code).doesNotContain("NO_HTTPS")
                .contains("CREDENTIAL_DOMAIN_PATTERN", "CREDENTIAL_PRESSURE_LURE");
        assertThat(result.score()).isGreaterThan(25);
    }
    @ParameterizedTest @ValueSource(strings = {"http://127.0.0.1/login", "http://[::1]/login"})
    void ipLiteralIsClassifiedWithoutContact(String url) {
        var result = service.analyze(url);
        assertThat(result.ipBased()).isTrue();
        assertThat(result.reasons()).extracting(Reason::code).contains("IP_BASED_URL", "NO_HTTPS");
    }
    @Test void internationalAndDeepDomainsAreExplained() {
        var result = service.analyze("https://a.b.c.d.bücher.example/login");
        assertThat(result.host()).contains("xn--bcher-kva");
        assertThat(result.reasons()).extracting(Reason::code).contains("INTERNATIONALIZED_DOMAIN", "MANY_SUBDOMAINS");
    }
    @Test void encodedCrossHostHttpRedirectRemainsOnlyAnIndicator() {
        var result = service.analyze("https://example.com/start?redirect_uri=http%253A%252F%252Fother.zip%252Flogin");
        assertThat(result.redirectIndicators()).hasSize(1);
        var redirect = result.redirectIndicators().get(0);
        assertThat(redirect.destination()).isEqualTo("http://other.zip/login");
        assertThat(redirect.host()).isEqualTo("other.zip");
        assertThat(redirect.crossHost()).isTrue();
        assertThat(redirect.https()).isFalse();
        assertThat(redirect.status()).isEqualTo("INSPECTED");
        assertThat(result.reasons()).extracting(Reason::code).contains("REDIRECT_PARAMETER", "CROSS_HOST_REDIRECT",
                "HTTPS_DOWNGRADE_REDIRECT", "REDIRECT_SUSPICIOUS_TLD");
        assertThat(result.score()).isEqualTo(Math.min(100, result.reasons().stream().mapToInt(Reason::contribution).sum()));
    }
    @Test void relativeDestinationsAndRepeatedParametersDoNotInventExternalRedirects() {
        var result = service.analyze("https://example.com/start?next=/docs&next=/help&return_url=https://example.com/end");
        assertThat(result.redirectIndicators()).hasSize(3).allSatisfy(r -> {
            assertThat(r.host()).isEqualTo("example.com");
            assertThat(r.crossHost()).isFalse();
        });
        assertThat(result.reasons()).extracting(Reason::code).containsExactly("REDIRECT_PARAMETER");
        assertThat(result.score()).isEqualTo(5);
    }
    @Test void fragmentAndProtocolRelativeCandidatesAreInspectedLocally() {
        var result = service.analyze("https://example.com/#/signin?next=//192.168.0.1/login");
        assertThat(result.redirectIndicators()).hasSize(1);
        assertThat(result.redirectIndicators().get(0).parameter()).isEqualTo("fragment:next");
        assertThat(result.redirectIndicators().get(0).https()).isTrue();
        assertThat(result.reasons()).extracting(Reason::code).contains("CROSS_HOST_REDIRECT", "REDIRECT_IP_BASED_URL");
    }
    @Test void nonWebMalformedAndEmptyCandidatesAreNotFollowed() {
        var result = service.analyze("https://example.com/?next=javascript:alert(1)&url=http://&return=&target");
        assertThat(result.redirectIndicators()).extracting(r -> r.status())
                .containsExactly("UNSUPPORTED_SCHEME", "INVALID", "EMPTY", "EMPTY");
        assertThat(result.reasons()).extracting(Reason::code).contains("NON_WEB_REDIRECT", "UNINSPECTABLE_REDIRECT");
    }
    @Test void encodedSeparatorsDoNotCreateExtraParametersAndTargetsAreNotRecursed() {
        var result = service.analyze("https://example.com/?next=/docs%3Fnext%3Dhttps%3A%2F%2Fother.example%26url%3Dhttp%3A%2F%2F10.0.0.1");
        assertThat(result.redirectIndicators()).hasSize(1);
        assertThat(result.redirectIndicators().get(0).crossHost()).isFalse();
        assertThat(result.reasons()).extracting(Reason::code).doesNotContain("CROSS_HOST_REDIRECT", "REDIRECT_IP_BASED_URL");
    }
    @Test void repeatedKeywordsOrRedirectsDoNotMultiplyRulePoints() {
        var result = service.analyze("https://example.com/login/login/urgent/urgent?next=https://one.example&next=https://two.example");
        assertThat(result.reasons()).extracting(Reason::code).doesNotHaveDuplicates();
        assertThat(result.reasons().stream().filter(r -> r.code().equals("CROSS_HOST_REDIRECT"))).hasSize(1);
        assertThat(service.analyze("https://example.com/verify").reasons()).extracting(Reason::code)
                .doesNotContain("CREDENTIAL_PRESSURE_LURE");
    }
    @ParameterizedTest @CsvSource({"0,LOW", "25,LOW", "26,MEDIUM", "50,MEDIUM", "51,HIGH", "75,HIGH", "76,CRITICAL", "100,CRITICAL"})
    void riskBoundariesAreStable(int score, String expected) {
        assertThat(PhishingDetectionService.riskLevel(score)).isEqualTo(expected);
    }
    @ParameterizedTest @ValueSource(strings = {"", "javascript:alert(1)", "file:///etc/passwd", "https://127.1", "https://user:password@example.com", "https://example.com/%25250a", "https://example.com/\\foo"})
    void usesSharedSecureValidation(String url) {
        assertThatThrownBy(() -> service.analyze(url)).isInstanceOf(ApiException.class);
    }
}
