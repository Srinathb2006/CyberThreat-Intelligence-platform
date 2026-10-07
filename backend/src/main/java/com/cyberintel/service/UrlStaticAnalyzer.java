package com.cyberintel.service;

import com.cyberintel.dto.UrlScanDtos.*;
import com.cyberintel.exception.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/** Pure lexical analysis. Never resolves a hostname or opens a network connection. */
@Component
public class UrlStaticAnalyzer {
    // Local heuristic list, not a reputation feed or a claim that these domains are malicious.
    private static final Set<String> FLAGGED_TLDS = Set.of("zip", "mov", "top", "xyz", "click", "work", "tk", "ml", "ga", "cf", "gq");
    private static final Pattern KEYWORDS = Pattern.compile("(?i)(?:^|[^a-z])(login|verify|password|credential|wallet|banking|urgent|prize|free|account|secure)(?=$|[^a-z])");
    private static final Pattern HEX_ESCAPE = Pattern.compile("(?:%[0-9a-fA-F]{2})+");

    public Analysis analyze(String input) {
        if (input == null || input.isBlank() || input.length() > 2048) {
            throw invalid("Enter an HTTP or HTTPS URL of at most 2048 characters.");
        }
        if (input.codePoints().anyMatch(c -> Character.isWhitespace(c) || Character.isSpaceChar(c)
                || Character.isISOControl(c) || Character.getType(c) == Character.FORMAT) || input.contains("\\")) {
            throw invalid("URLs cannot contain whitespace, control characters or backslashes. Encode spaces as %20.");
        }
        URI uri;
        try { uri = new URI(input); }
        catch (URISyntaxException e) { throw invalid("Malformed URL or percent encoding."); }
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https")) || uri.isOpaque()) {
            throw invalid("Only absolute HTTP and HTTPS URLs are supported.");
        }
        String authority = uri.getRawAuthority();
        if (authority == null || authority.isEmpty()) throw invalid("A hostname or IP address is required.");
        if (authority.contains("@")) throw invalid("URLs with embedded credentials are not supported.");
        if (authority.contains("%")) throw invalid("Encoded hostnames and IPv6 zone identifiers are not supported.");

        String host;
        String portText = null;
        boolean ipv6 = authority.startsWith("[");
        if (ipv6) {
            int close = authority.indexOf(']');
            // URI validates bracketed IPv6 syntax locally, without resolving it.
            if (close < 0 || uri.getHost() == null) throw invalid("Invalid IPv6 address.");
            host = authority.substring(1, close).toLowerCase(Locale.ROOT);
            String tail = authority.substring(close + 1);
            if (!tail.isEmpty()) {
                if (!tail.startsWith(":")) throw invalid("Invalid authority.");
                portText = tail.substring(1);
            }
        } else {
            int colon = authority.indexOf(':');
            host = colon < 0 ? authority : authority.substring(0, colon);
            if (colon >= 0) portText = authority.substring(colon + 1);
            if (host.isEmpty()) throw invalid("A hostname is required.");
        }
        int port = scheme.equalsIgnoreCase("https") ? 443 : 80;
        if (portText != null) {
            if (!portText.matches("[0-9]{1,5}")) throw invalid("Port must be a number from 1 to 65535.");
            port = Integer.parseInt(portText);
            if (port < 1 || port > 65535) throw invalid("Port must be a number from 1 to 65535.");
        }

        boolean unicodeHost = host.chars().anyMatch(c -> c > 127);
        boolean trailingDot = host.endsWith(".");
        if (!ipv6) {
            try { host = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT); }
            catch (IllegalArgumentException e) { throw invalid("Invalid domain name."); }
            if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
            if (host.isEmpty() || host.length() > 253 || Arrays.stream(host.split("\\.", -1))
                    .anyMatch(label -> label.isEmpty() || label.length() > 63)) throw invalid("Invalid domain name.");
        }
        boolean ipv4 = !ipv6 && host.matches("[0-9]+(?:\\.[0-9]+){3}");
        if (ipv4) {
            for (String octet : host.split("\\.")) {
                if (octet.length() > 3 || (octet.length() > 1 && octet.startsWith("0")) || Integer.parseInt(octet) > 255) {
                    throw invalid("Use canonical IPv4 notation with four decimal octets from 0 to 255.");
                }
            }
        } else if (!ipv6 && host.matches("(?i)(?:0x[0-9a-f]+|[0-9]+)(?:\\.(?:0x[0-9a-f]+|[0-9]+))*")) {
            throw invalid("Ambiguous numeric hosts are not supported. Use canonical IPv4 notation.");
        }
        if (!ipv4 && !ipv6 && host.substring(host.lastIndexOf('.') + 1).matches("(?i)(?:[0-9]+|0x[0-9a-f]+)")) {
            throw invalid("A domain cannot end with an ambiguous numeric label.");
        }

        List<Finding> findings = new ArrayList<>();
        boolean https = scheme.equalsIgnoreCase("https");
        if (!https) add(findings, "NO_HTTPS", "MEDIUM", "The URL specifies unencrypted HTTP.", scheme, 15);
        if (ipv4 || ipv6) {
            add(findings, "IP_BASED_URL", "MEDIUM", "The URL uses an IP literal instead of a domain; review its intended destination.", host, 20);
            if (nonPublicIp(host, ipv4)) add(findings, "NON_PUBLIC_IP", "MEDIUM", "The literal is in a local, private or special-use address range.", host, 10);
        } else {
            String[] labels = host.split("\\.");
            String tld = labels[labels.length - 1];
            if (FLAGGED_TLDS.contains(tld)) add(findings, "SUSPICIOUS_TLD", "LOW", "The suffix appears on the scanner's local heuristic list; this is not a reputation verdict.", "." + tld, 10);
            if (labels.length == 1 || host.endsWith(".localhost") || host.endsWith(".local")) add(findings, "LOCAL_HOSTNAME", "LOW", "This is a single-label or local-use hostname. No DNS lookup was performed.", host, 5);
            if (labels.length > 5) add(findings, "MANY_SUBDOMAINS", "LOW", "Many hostname labels can obscure the destination.", host, 10);
            if (unicodeHost || Arrays.stream(labels).anyMatch(l -> l.startsWith("xn--"))) add(findings, "INTERNATIONALIZED_DOMAIN", "LOW", "Internationalized domain: inspect the ASCII spelling for possible lookalikes.", host, 10);
        }
        if (trailingDot) add(findings, "TRAILING_DOT", "LOW", "A trailing root dot can disguise a familiar hostname spelling.", host, 5);
        if (port != (https ? 443 : 80)) add(findings, "UNUSUAL_PORT", "LOW", "The explicit port differs from the scheme's default.", Integer.toString(port), 5);
        if (input.length() > 300) add(findings, "LONG_URL", "LOW", "A long URL can make the destination and parameters difficult to inspect.", Integer.toString(input.length()) + " characters", 5);

        String decoded = input;
        int layers = 0;
        // Each successful decoding shrinks the bounded input. Inspect every layer for controls.
        while (layers < input.length() && HEX_ESCAPE.matcher(decoded).find()) {
            // Decode escape runs independently: a newly decoded literal '%' must not
            // prevent inspection of other encoded content in the same layer.
            decoded = HEX_ESCAPE.matcher(decoded).replaceAll(match -> Matcher.quoteReplacement(
                    URLDecoder.decode(match.group(), StandardCharsets.UTF_8)));
            layers++;
            if (decoded.codePoints().anyMatch(c -> c == 0xfffd || Character.isISOControl(c) || Character.getType(c) == Character.FORMAT)
                    || decoded.contains("\\")) throw invalid("Encoded control characters or backslashes are not supported.");
        }
        if (layers > 0) add(findings, layers > 1 ? "NESTED_ENCODING" : "PERCENT_ENCODING", "LOW",
                layers > 1 ? "Repeated percent encoding can hide URL content." : "Percent-encoded content is present; encoding also has legitimate uses.",
                layers + " decoding layer(s)", layers > 1 ? 15 : 5);
        Set<String> keywords = new TreeSet<>();
        var matcher = KEYWORDS.matcher(decoded);
        while (matcher.find()) keywords.add(matcher.group(1).toLowerCase(Locale.ROOT));
        if (!keywords.isEmpty()) add(findings, "SUSPICIOUS_KEYWORDS", "LOW", "Review these attention or credential-related terms in context; legitimate URLs also use them.", String.join(", ", keywords), 10);
        int score = Math.min(100, findings.stream().mapToInt(Finding::contribution).sum());
        String risk = score > 75 ? "CRITICAL" : score > 50 ? "HIGH" : score > 25 ? "MEDIUM" : "LOW";
        return new Analysis(host, ipv4 || ipv6 ? null : host, ipv4 || ipv6 ? host : null, https, port,
                uri.getRawPath().isEmpty() ? "/" : uri.getRawPath(), uri.getRawQuery() != null,
                uri.getRawFragment() != null, score, risk, List.copyOf(findings));
    }

    private boolean nonPublicIp(String host, boolean ipv4) {
        if (ipv4) {
            String[] parts = host.split("\\.");
            int a = Integer.parseInt(parts[0]), b = Integer.parseInt(parts[1]);
            return a == 0 || a == 10 || a == 127 || a >= 224 || (a == 169 && b == 254)
                    || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 100 && b >= 64 && b <= 127);
        }
        // Expand locally, including IPv4-mapped literals, rather than using InetAddress/DNS.
        String value = host;
        if (value.contains(".")) {
            int lastColon = value.lastIndexOf(':');
            String[] p = value.substring(lastColon + 1).split("\\.");
            value = value.substring(0, lastColon + 1) + Integer.toHexString(Integer.parseInt(p[0]) * 256 + Integer.parseInt(p[1]))
                    + ":" + Integer.toHexString(Integer.parseInt(p[2]) * 256 + Integer.parseInt(p[3]));
        }
        String[] halves = value.split("::", -1);
        List<Integer> words = new ArrayList<>();
        if (!halves[0].isEmpty()) for (String word : halves[0].split(":")) words.add(Integer.parseInt(word, 16));
        if (halves.length == 2) {
            String[] right = halves[1].isEmpty() ? new String[0] : halves[1].split(":");
            while (words.size() < 8 - right.length) words.add(0);
            for (String word : right) words.add(Integer.parseInt(word, 16));
        }
        int first = words.get(0);
        if (words.subList(0, 5).stream().allMatch(w -> w == 0) && (words.get(5) == 0 || words.get(5) == 65535)) {
            int hi = words.get(6), lo = words.get(7);
            return nonPublicIp((hi >> 8) + "." + (hi & 255) + "." + (lo >> 8) + "." + (lo & 255), true);
        }
        return (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 || (first & 0xff00) == 0xff00;
    }

    private void add(List<Finding> findings, String code, String severity, String description, String evidence, int points) {
        findings.add(new Finding(code, severity, description, evidence, points));
    }
    private ApiException invalid(String message) { return new ApiException(HttpStatus.BAD_REQUEST, message); }
}
