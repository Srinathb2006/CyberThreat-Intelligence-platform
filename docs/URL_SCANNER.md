# URL Scanner

The authenticated `/url-scanner` page performs **static text analysis only**. The backend uses URI/IDN parsing and local rules. It does not perform DNS lookups, HTTP requests, redirects, certificate checks, reputation lookups, or page downloads. Submitted URLs are rendered as text rather than links.

## API

- `POST /api/url-scans` with JSON `{"url":"https://example.com/path"}` creates a saved analysis (201).
- `GET /api/url-scans` lists the current user's most recent 50 results.
- `GET /api/url-scans/{scanId}` reloads a saved result; missing and other users' scans return 404.

All endpoints require the existing bearer authentication. Input is limited to 2048 characters. Only absolute HTTP/HTTPS URLs are accepted. Malformed domains, ports, percent escapes, credentials, whitespace, controls, backslashes, encoded hostnames, IPv6 zone IDs, and ambiguous numeric IP formats are rejected with 400. IPv4 literals use four decimal octets; IPv6 literals must be bracketed. Unicode domain names are converted locally to ASCII using Java IDN. The `domain` field is the full normalized hostname, not a registrable-domain or ownership assertion. Domain IP addresses are not resolved; `ipAddress` is populated only for literal IPs.

## Findings and scoring

Results expose URL components and explainable findings for HTTP, IP literals, local/private address ranges, local names, unusual ports, long URLs, excessive hostname labels, internationalized domains, trailing dots, percent/nested encoding, a small local suffix list, and credential/attention keywords. Finding contributions sum to a score capped at 100 (0–25 LOW, 26–50 MEDIUM, 51–75 HIGH, 76–100 CRITICAL). These are heuristic review priorities, not proof of malware or a safety verdict. HTTPS presence describes the scheme only; no TLS connection is made. The local suffix list is not a live reputation feed. IP range checks are limited lexical heuristics, not an exhaustive routability database.

Migration V12 creates `url_scans`, linked to the existing `scans` table. The analysis is saved as a JSON snapshot so reload does not rerun changing rules. History/detail access is scoped to the authenticated owner. Existing scan summaries can recognize these records as type URL. A URL scan does not automatically create an alert.

Run backend validation with `mvn test` in `backend`, and frontend checks with `npm test` and `npm run build` in `frontend`.
