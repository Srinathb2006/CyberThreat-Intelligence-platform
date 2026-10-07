package com.cyberintel.service;

import com.cyberintel.dto.PhishingDtos.*;
import com.cyberintel.dto.UrlScanDtos.Analysis;
import com.cyberintel.exception.ApiException;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Deterministic text-only rules. No networking, DNS, ML, or external intelligence. */
@Service
public class PhishingDetectionService {
    private static final Set<String> REDIRECT_KEYS = Set.of("redirect", "redirect_uri", "redirect_url", "redirecturl",
            "url", "next", "return", "returnurl", "return_url", "return_to", "continue", "dest", "destination", "target", "callback");
    private static final Pattern ESCAPES = Pattern.compile("(?:%[0-9a-fA-F]{2})+");
    private static final Pattern CREDENTIAL_TERMS = Pattern.compile("(?i)(?:^|[^a-z])(login|signin|sign-in|password|credential|verify|wallet|account)(?=$|[^a-z])");
    private static final Pattern PRESSURE_TERMS = Pattern.compile("(?i)(?:^|[^a-z])(urgent|suspend|suspended|expire|expired|verify|recover|recovery|unlock|prize|reward)(?=$|[^a-z])");
    private final UrlStaticAnalyzer urlAnalyzer;

    public PhishingDetectionService(UrlStaticAnalyzer urlAnalyzer) { this.urlAnalyzer = urlAnalyzer; }

    public Result analyze(String url) {
        Analysis base = urlAnalyzer.analyze(url);
        Map<String, Reason> reasons = new LinkedHashMap<>();
        for (var finding : base.findings()) {
            reasons.put(finding.code(), new Reason(finding.code(), finding.severity(), finding.description(),
                    finding.evidence(), finding.contribution()));
        }
        if (base.domain() != null) {
            String[] labels = base.domain().split("\\.");
            if (Arrays.stream(labels).filter(l -> !l.startsWith("xn--")).anyMatch(l -> l.chars().filter(c -> c == '-').count() >= 3)) {
                add(reasons, "HYPHENATED_DOMAIN", "LOW", "A hostname label contains at least three hyphens, a pattern that can imitate multi-word trusted names.", base.host(), 10);
            }
            if (Arrays.stream(labels).anyMatch(l -> l.length() >= 30)) {
                add(reasons, "LONG_DOMAIN_LABEL", "LOW", "A hostname label is at least 30 characters long and can obscure the intended destination.", base.host(), 10);
            }
            if (Arrays.stream(labels).anyMatch(l -> {
                long digits = l.chars().filter(Character::isDigit).count();
                return digits >= 5 && digits * 3 >= l.length();
            })) {
                add(reasons, "DIGIT_HEAVY_DOMAIN", "LOW", "A hostname label has at least five digits making up a third or more of its text. Review for generated or lookalike names.", base.host(), 10);
            }
            Set<String> domainTerms = terms(CREDENTIAL_TERMS, base.host());
            if (domainTerms.size() >= 2) {
                add(reasons, "CREDENTIAL_DOMAIN_PATTERN", "MEDIUM", "Multiple credential-related terms appear in the hostname. This may be a credential lure; it does not establish impersonation.", String.join(", ", domainTerms), 15);
            }
        }
        String decoded = decode(url);
        Set<String> credentialTerms = terms(CREDENTIAL_TERMS, decoded);
        Set<String> pressureTerms = terms(PRESSURE_TERMS, decoded);
        // A single shared word such as 'verify' is not independently two signals.
        Set<String> distinctTerms = new TreeSet<>(credentialTerms);
        distinctTerms.addAll(pressureTerms);
        if (!credentialTerms.isEmpty() && !pressureTerms.isEmpty() && distinctTerms.size() >= 2) {
            add(reasons, "CREDENTIAL_PRESSURE_LURE", "MEDIUM", "Credential-related language appears together with urgency, recovery or reward language. Review the request in context.", String.join(", ", distinctTerms), 15);
        }

        URI source = URI.create(url); // Validated by the local URL analyzer.
        List<RedirectIndicator> redirects = new ArrayList<>();
        inspectParameters(source.getRawQuery(), "query", source, base, redirects, reasons);
        String fragment = source.getRawFragment();
        if (fragment != null) {
            int queryStart = fragment.indexOf('?');
            inspectParameters(queryStart >= 0 ? fragment.substring(queryStart + 1) : fragment,
                    "fragment", source, base, redirects, reasons);
        }
        int score = Math.min(100, reasons.values().stream().mapToInt(Reason::contribution).sum());
        return new Result(url, base.host(), base.https(), base.ipAddress() != null, score,
                riskLevel(score), List.copyOf(reasons.values()), List.copyOf(redirects));
    }

    private void inspectParameters(String raw, String location, URI source, Analysis base,
                                   List<RedirectIndicator> redirects, Map<String, Reason> reasons) {
        if (raw == null || raw.isEmpty()) return;
        // Split before decoding: encoded '&' or '=' belongs to a value, not a new parameter.
        for (String pair : raw.split("&")) {
            int equals = pair.indexOf('=');
            String key = decode(equals < 0 ? pair : pair.substring(0, equals)).toLowerCase(Locale.ROOT);
            if (!REDIRECT_KEYS.contains(key)) continue;
            String parameter = location + ":" + key;
            String destination = equals < 0 ? "" : decode(pair.substring(equals + 1));
            add(reasons, "REDIRECT_PARAMETER", "LOW", "A redirect-like parameter is present. Static input cannot confirm whether a redirect occurs.", parameter, 5);
            if (destination.isEmpty()) {
                redirects.add(new RedirectIndicator(parameter, destination, null, false, null, "EMPTY"));
                continue;
            }
            try {
                URI candidate = new URI(destination);
                String scheme = candidate.getScheme();
                if (scheme != null && !scheme.equalsIgnoreCase("https") && !scheme.equalsIgnoreCase("http")) {
                    redirects.add(new RedirectIndicator(parameter, destination, null, false, null, "UNSUPPORTED_SCHEME"));
                    add(reasons, "NON_WEB_REDIRECT", "HIGH", "A redirect-like value specifies a non-HTTP(S) scheme. It is not executed or followed.", parameter + " uses " + scheme, 25);
                    continue;
                }
                // Relative and protocol-relative destinations are resolved lexically, not requested.
                URI resolved = source.resolve(candidate);
                Analysis target = urlAnalyzer.analyze(resolved.toString());
                boolean crossHost = !base.host().equalsIgnoreCase(target.host());
                redirects.add(new RedirectIndicator(parameter, destination, target.host(), crossHost, target.https(), "INSPECTED"));
                if (crossHost) add(reasons, "CROSS_HOST_REDIRECT", "MEDIUM", "A supplied redirect candidate names a different hostname. This can be legitimate; no redirect was observed.", parameter + " → " + target.host(), 20);
                if (base.https() && !target.https()) add(reasons, "HTTPS_DOWNGRADE_REDIRECT", "MEDIUM", "An HTTPS URL contains an HTTP redirect candidate, which would lose HTTPS if followed.", parameter + " → " + target.host(), 10);
                // Preserve destination signals once per rule; do not recursively follow nested candidates.
                for (var finding : target.findings()) {
                    if (Set.of("IP_BASED_URL", "SUSPICIOUS_TLD", "INTERNATIONALIZED_DOMAIN").contains(finding.code())) {
                        add(reasons, "REDIRECT_" + finding.code(), finding.severity(),
                                "Redirect candidate: " + finding.description(), parameter + " → " + finding.evidence(), finding.contribution());
                    }
                }
            } catch (URISyntaxException | ApiException | IllegalArgumentException e) {
                redirects.add(new RedirectIndicator(parameter, destination, null, false, null, "INVALID"));
                add(reasons, "UNINSPECTABLE_REDIRECT", "LOW", "A redirect-like value is malformed or unsupported by URL validation. Its destination could not be inspected locally.", parameter, 5);
            }
        }
    }

    private String decode(String value) {
        String decoded = value;
        for (int i = 0; i < value.length() && ESCAPES.matcher(decoded).find(); i++) {
            decoded = ESCAPES.matcher(decoded).replaceAll(match -> Matcher.quoteReplacement(
                    URLDecoder.decode(match.group(), StandardCharsets.UTF_8)));
        }
        return decoded;
    }
    private Set<String> terms(Pattern pattern, String text) {
        Set<String> result = new TreeSet<>();
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) result.add(matcher.group(1).toLowerCase(Locale.ROOT));
        return result;
    }
    private void add(Map<String, Reason> reasons, String code, String severity, String description, String evidence, int points) {
        // Each rule contributes once, regardless of repeated keywords or parameters.
        reasons.putIfAbsent(code, new Reason(code, severity, description, evidence, points));
    }
    static String riskLevel(int score) {
        return score > 75 ? "CRITICAL" : score > 50 ? "HIGH" : score > 25 ? "MEDIUM" : "LOW";
    }
}
