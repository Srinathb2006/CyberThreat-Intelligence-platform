# Risk correlation, alerts, and reports

These features operate on stored APK scan records. They are separate actions after the initial APK extraction; the frontend offers buttons for static malware analysis, local threat-intelligence correlation, and risk calculation. The backend does not automatically run those three actions at upload time.

## Risk calculation

`POST /api/risk-correlation/{scanId}/calculate` gathers stored malware-rule findings, local threat-intelligence matches, suspicious API/permission/URL/component indicators, IOCs, and obfuscation/native indicators. The scoring configuration is defined in `RiskScoringProperties` (there are no environment overrides in the current `application.yml`). For each category, the service sums `category weight × severity multiplier × confidence multiplier` across eligible evidence and caps that category at its weight. The combined score is clamped to 0–100.

| Category | Cap |
| --- | ---: |
| Static malware findings | 25 |
| Threat-intelligence matches | 30 |
| Suspicious APIs | 15 |
| Suspicious permissions | 10 |
| IOC indicators | 10 |
| Suspicious URLs | 5 |
| Suspicious components | 3 |
| Obfuscation/native indicators | 2 |

Severity multipliers are LOW 0.25, MEDIUM 0.50, HIGH 0.75, CRITICAL 1.00. Confidence multipliers are LOW 0.50, MEDIUM 0.75, HIGH 1.00. Levels use the unrounded score: CRITICAL at 76 or above, HIGH at 51 or above, MEDIUM at 26 or above, and LOW below 26. The score is a review priority, not a probability of malware. The latest assessment, indicators, breakdown, confidence, summary, and recommendation snapshot are saved. Recalculating creates a new latest assessment. `GET /api/risk-correlation/{scanId}` and its `/indicators`, `/breakdown`, and `/recommendations` routes reload those records.

The current risk service does not consume the separate YARA match table. Standalone URL Scanner, Phishing Detection, and Endpoint Monitoring scores are independent of this APK score. Real and mock APK modes are labeled in the UI; a score based on mock findings remains demonstration output.

## Alerts

After a successful risk calculation, the same transaction calls `AlertService.generateAlertsFromAssessment`. It can create alerts for an overall HIGH/CRITICAL assessment, threat-intelligence indicators, and selected HIGH/CRITICAL indicator categories such as dynamic loading or potential data exfiltration. An existing alert with the same scan ID and title is not recreated. A separate `POST /api/alerts/generate/{scanId}` route can invoke generation again.

`GET /api/alerts` supports status, severity, and search filters; `GET /api/alerts/{id}` returns a detail; `PATCH /api/alerts/{id}/status` and `POST /api/alerts/{id}/resolve` update workflow state; `GET /api/alerts/stats` returns aggregate counts. Alerts are stored records, not push notifications, emails, or endpoint telemetry.

## Reports

The reports API generates exports on request from current database records. It does not save immutable report snapshots:

| Route suffix under `/api/reports/{scanId}` | Content |
| --- | --- |
| `/pdf` | PDF summary, risk indicators, malware findings, matches, IOCs, and alerts when present. |
| `/json` | Structured scan/APK/risk/finding/IOC/match/alert data. |
| `/findings.csv` | Malware findings. |
| `/iocs.csv` | Extracted IOCs. |
| `/threat-matches.csv` | Local intelligence matches. |
| `/summary.csv` | Key scan, risk, finding, IOC, and alert counts. |

Reports currently do not include the separate YARA match table or standalone URL, phishing, and endpoint results. A PDF field labeled “risk verdict” is the heuristic risk level; it is not a verified malware verdict.

## Access limitation

All these routes require a bearer JWT through Spring Security. Their current controllers/services use global scan or alert IDs and do **not** check that the caller owns the referenced scan or alert. The list and aggregate routes are likewise not per-user views. Treat this as an application security limitation and do not deploy it for mutually untrusted users until ownership checks are added. APK upload/history, URL scans, IOC Explorer, endpoint records, and YARA result routes have their own ownership checks; those checks do not automatically protect these legacy routes.
