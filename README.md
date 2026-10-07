# CyberIntel

CyberIntel is a local cyber threat investigation workspace built around static Android APK inspection. It also includes rule-based URL and phishing checks, a database-backed threat-intelligence catalog, IOC exploration, risk correlation, alerts, reports, and a lightweight endpoint demo. It does not execute APKs or visit submitted URLs.

## Architecture

```text
React / Vite (JavaScript) → REST API with bearer JWT → Spring Boot (Java 17 target)
                                                    ├─ Spring Security, services, JPA
                                                    ├─ PostgreSQL + Flyway (V1–V17)
                                                    └─ private APK/analysis storage
                                                         └─ bounded local tool processes
                                                            JADX, Apktool, aapt, Androguard
```

The backend validates and stores uploads, runs up to two APK jobs with eight queued, and persists findings. Configured tools receive fixed arguments and server-controlled paths. YARA runs separately against retained extraction output. The frontend polls APK progress and calls the other analysis APIs on demand. H2 is used in automated backend tests; that test profile disables Flyway and lets Hibernate create the test schema.

## Modules and current data sources

| Module | Implemented behavior |
| --- | --- |
| APK Analysis | Owned upload/history, hashes, asynchronous static extraction, metadata, permissions, components, APIs, strings, URLs, tool status, and on-demand YARA results. |
| Static Malware Analysis | Rule-based findings and IOC extraction from a stored APK analysis, started separately after APK analysis. |
| Threat Intelligence | Local database catalog with seeded demo records, CRUD/import/export endpoints, and IOC matching. No live provider or external reputation API is connected. |
| IOC Explorer | Searches the existing IOC tables with type, severity, confidence, and scan filters, details, and local intelligence-match information. |
| Risk Correlation | On-demand, weighted assessment of stored APK findings, IOCs, and matches. Persists indicators, breakdown, confidence, recommendations, and the latest assessment. |
| Alerts | Automatically generated after successful risk calculation when configured conditions are met; list, filter, status update, resolve, and stats APIs. |
| Reports | On-demand PDF and JSON reports plus findings, IOCs, threat matches, and summary CSV exports for a scan. |
| Scan History | Search and filter stored scan records and linked analysis counts. |
| URL Scanner | Validates HTTP(S) input, scores local lexical/structural indicators, and saves per-user results. It makes no network request to the URL. |
| Phishing Detection | Stateless, explainable static URL and redirect-parameter checks. No page fetch, ML, or external API. |
| Endpoint Monitoring | Owned device records, status fields, and explicitly labeled simulated security events and risk summaries. No device agent or telemetry collection. |
| Dashboard | API-backed aggregate counts when available; trends and distribution charts remain sample data. The recent-event list and counts can fall back to samples when the API fails or has no alerts. |

The development demo login is a frontend-only mock session and cannot call authenticated analysis APIs. Use a registered backend account for live modules. Some older authenticated endpoints are not owner-scoped; see [Security limitations](#security-limitations) before deploying for multiple users.

## Setup

Use JDK 17 or newer, Maven, Node.js/npm, and PostgreSQL. The Maven compiler targets Java 17. Create a PostgreSQL database and a login with permission to run Flyway migrations on that database. No database user is seeded by the application.

From `backend`, copy `.env.example` to `.env`, then set `DB_URL`, `DB_USERNAME`, `DB_PASSWORD`, and a strong `JWT_SECRET` of at least 32 UTF-8 bytes. The backend loads `.env` from the `backend` or project-root launch directory. Environment variables override file values. Start it with:

```powershell
cd backend
mvn spring-boot:run
```

The API defaults to `http://localhost:7070/api`. Flyway applies migrations V1–V17 on normal startup; Hibernate validates the resulting schema. From `frontend`, copy `.env.example` to `.env.local`, check `VITE_API_BASE_URL`, install dependencies, and start Vite:

```powershell
cd frontend
npm ci
npm run dev
```

Open the URL printed by Vite (normally `http://127.0.0.1:5173`). The backend's default CORS origins include both `127.0.0.1:5173` and `localhost:5173`. Register a user in the login screen, then sign in. Frontend `VITE_*` values are public; do not put secrets in them.

To opt into the local demonstration login during Vite development only, set `VITE_ENABLE_DEMO=true` and restart Vite. The demonstration account (`admin@cyberintel.local` / `Admin@123`) is not a database user or valid backend token. Production builds do not enable that login.

## Configuration

See [backend/.env.example](backend/.env.example), [application.yml](backend/src/main/resources/application.yml), and [frontend/.env.example](frontend/.env.example) for the exact properties and defaults.

| Variables | Purpose |
| --- | --- |
| `DB_URL`, `DB_USERNAME`, `DB_PASSWORD` | PostgreSQL connection; URL defaults to `jdbc:postgresql://localhost:5432/cyberintel`. |
| `JWT_SECRET`, `JWT_EXPIRATION_SECONDS` | Signing secret (required) and token lifetime (default 3600 seconds). |
| `PORT`, `CORS_ALLOWED_ORIGINS` | API port (7070) and explicit allowed browser origins. |
| `UPLOAD_DIRECTORY`, `ANALYSIS_DIRECTORY`, `MAX_APK_SIZE` | Private upload/output roots and compressed APK limit (50 MB). |
| `MAX_APK_EXPANDED_BYTES`, `MAX_APK_ENTRIES`, `MAX_ANALYSIS_OUTPUT_BYTES` | Archive and tool-output limits (256 MiB, 20,000 entries, 512 MiB). |
| `ANALYSIS_TIMEOUT_SECONDS`, `ANALYSIS_RETENTION_DAYS` | Per-tool timeout (120 seconds) and artifact retention (7 days). |
| `JADX_ENABLED/PATH`, `APKTOOL_ENABLED/PATH`, `AAPT_ENABLED/PATH` | Optional trusted local static tools; all disabled by default. |
| `ANDROGUARD_ENABLED/PATH` | Optional Androguard integration; path points to a local Python executable with Androguard installed. |
| `YARA_ENABLED/PATH`, `YARA_RULES_DIRECTORY` | Optional local YARA executable and `.yar`/`.yara` rule directory. |
| `VITE_API_BASE_URL`, `VITE_ENABLE_DEMO` | Frontend API base and development-only mock login switch. |

Use absolute paths for tool executables. The server does not accept tool paths from API requests. [APK analysis](docs/APK_ANALYSIS.md), [Androguard](docs/ANDROGUARD_ANALYSIS.md), and [YARA](docs/YARA_ANALYSIS.md) give the tool-specific details.

## APK investigation workflow

1. Upload an `.apk`. The server validates the ZIP structure and manifest, applies size and entry limits, and records real SHA-256/MD5 hashes and file size.
2. Select **Start scan**. The worker uses available configured JADX, Apktool, aapt, and Androguard tools. If none is enabled and available, it stores deterministic findings labeled **MOCK**. A failed real run does not silently become a mock success.
3. Review metadata, extracted code/manifest indicators, and each tool's status. A partial real scan can complete with warnings. No APK is installed or executed.
4. Select **Run Static Analysis** to generate rule-based malware findings and IOCs from the stored extraction. Run threat-intelligence correlation separately to compare those IOCs with the local catalog.
5. Select **Calculate Risk** to persist a risk assessment and trigger alert generation. Reports can then be downloaded. The separate **Run YARA** action scans retained extraction files with local rules, or returns an explicitly labeled synthetic result when YARA is unavailable. YARA results are not currently fed into risk scoring or reports.

The APK upload/history endpoint is scoped to its owner. Original uploaded filenames are display data; stored files use generated names. Temporary output is cleaned after a job, and the retention task removes old upload/output artifacts while keeping database findings. Detailed endpoints and limits are in [APK_ANALYSIS.md](docs/APK_ANALYSIS.md).

## Risk, alerts, and reports

The APK risk score is an on-demand heuristic, not a malware verdict or probability. Each evidence category has a cap: static findings 25, threat-intelligence matches 30, suspicious APIs 15, permissions 10, IOCs 10, URLs 5, components 3, and obfuscation/native indicators 2. Severity and confidence multipliers adjust contributions; the total is clamped to 0–100. The level is CRITICAL at 76 or above, HIGH at 51 or above, MEDIUM at 26 or above, and LOW below 26. The latest assessment and its recommendations survive reloads.

Risk calculation calls alert generation automatically. High/critical assessments, threat-intelligence indicators, and selected high/critical indicator categories can produce alerts; an existing scan/title pair is not recreated. Analysts can update or resolve alerts. Reports are generated from the current stored scan, finding, IOC, match, risk, and alert records when requested; they are not immutable historical snapshots. See [Risk, alerts, and reports](docs/RISK_ALERTS_REPORTS.md) for the API and limits.

## Security limitations

- Static indicators, YARA rule hits, and numeric scores require human review. Obfuscation, reflection, encrypted strings, native code, incomplete tools, and missing rule coverage can hide behavior. A low score does not establish safety.
- URL and phishing modules parse supplied text only. They do not resolve hosts, connect to sites, observe redirects, inspect certificates, or verify live reputation. Endpoint events and their risk summaries are simulated.
- **Authenticated does not mean owner-scoped across the whole API.** APK upload/history, URL scans, IOC Explorer, endpoint records, and YARA results check ownership. Several older scan-history, static-analysis, threat-correlation, risk, alert, and report routes query records by global ID or list without checking the caller's ownership. Do not treat this as a secure multi-tenant deployment without adding those checks.
- Configured external parsers process untrusted APK bytes and are not an OS sandbox. Run the backend and tools under a low-privilege account with filesystem and network restrictions. Keep configured executables and rule files writable only by trusted operators.
- Use HTTPS in deployments. JWTs are stored in browser session storage or, when "remember me" is selected, local storage; browser script compromise can expose them. Put rate limiting and access controls in front of any public deployment.
- Dashboard charts and some fallback values are illustrative. The YARA demo result is synthetic, Androguard's mock fallback is part of the overall APK mock mode, and local seeded threat-intelligence records are demonstration content. Reports currently omit standalone URL/phishing/endpoint and YARA results.

## Validation

Run `mvn clean test` and `mvn clean package` from `backend`, and `npm run build` from `frontend`. The backend test profile uses H2 with Flyway disabled, so those commands do not prove migration behavior on a PostgreSQL server. The separate Python helper test can be run from `backend` with `python -B -m unittest discover -s src/test/python`. Results from the final cleanup run are reported in the accompanying task response, rather than embedded here as a stale claim.
