# Static phishing detection

Open **Phishing Detection** in the workspace (`/phishing`). Submit an absolute HTTP or HTTPS URL (maximum 2048 characters) using a real authenticated account.

`POST /api/phishing/analyze` accepts `{"url":"https://example.com"}` and returns:

- `url`, normalized `host`, `https`, and `ipBased`.
- `score` (0–100), `riskLevel`, and `reasons` with stable rule codes, severity, description, evidence, and individual point contributions.
- `redirectIndicators`: parameter location/name, decoded candidate, locally parsed host/HTTPS, cross-host flag, and inspection status.

This endpoint is stateless: no new scan records or database migration. Invalid input returns 400 and unauthenticated requests return 401. Validation uses the URL Scanner's local parser, including rejection of credentials, control characters, malformed hosts/ports, unsupported schemes, and ambiguous numeric hosts.

## Rules

The existing URL rules cover structure, HTTPS scheme, IP literals, local addresses, domain labels, internationalized domains, unusual ports, suspicious suffixes, percent encoding, and keywords. Additional phishing rules identify:

- Three or more hyphens in a non-punycode hostname label: +10.
- A hostname label of 30 or more characters: +10.
- At least five digits comprising a third of a hostname label: +10.
- Multiple credential terms in a hostname: +15.
- Credential terms together with distinct urgency, recovery, or reward terms: +15.
- Redirect-like query/fragment parameters: +5.
- A different hostname in a redirect candidate: +20.
- HTTPS-to-HTTP redirect candidates: +10.
- Non-HTTP(S) redirect candidate schemes: +25.
- Malformed/unsupported redirect candidates: +5.
- IP literals, heuristic suffixes, and internationalized domains in redirect candidates retain their corresponding URL-rule contributions under separate redirect rule codes.

Each rule scores once per assessment, even with repeated keywords/parameters. The score is the sum of contributions capped at 100. Risk levels are LOW (0–25), MEDIUM (26–50), HIGH (51–75), and CRITICAL (76–100). Scores are review priorities, not probabilities or verified phishing verdicts; benign authentication and redirect URLs can trigger rules. HTTPS is not treated as proof of legitimacy.

## Redirect limitations and network behavior

Only parameters supplied in the URL are inspected, including common names such as `next`, `redirect_uri`, `return_url`, `url`, `destination`, and `callback`. Parameters are separated before percent decoding so encoded separators do not create extra fields. Relative candidates resolve locally against the source URL. Nested candidate chains are not recursively traversed. Cross-host comparison uses normalized full hostnames, not registrable-domain ownership. Empty, malformed, and non-web candidates are labeled explicitly.

No URL is visited or requested. There are no DNS lookups, HTTP clients, observed redirect responses, certificate checks, external APIs, or ML. An absent redirect indicator does not establish that a server would not redirect. All supplied URL content is displayed as escaped text rather than clickable links or embedded resources.

Validation: `mvn test` in `backend`; `npm test` and `npm run build` in `frontend`.
