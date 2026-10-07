# Reverse Engineering Based Cyber Threat Intelligence Platform

A final-year cybersecurity platform for static Android APK investigation. Step 1 supplies the SOC interface, authentication, and database foundation. Step 2 adds authenticated APK upload, hashing, asynchronous reverse engineering, extracted findings, and scan history.

**APK files are analyzed statically and are never executed, installed, rebuilt, or launched.** The backend runs only configured JADX, Apktool, and aapt/aapt2 tools for static inspection. See [APK analysis setup and API](docs/APK_ANALYSIS.md) for Step 2 configuration and limitations.

## Architecture

```text
React / Vite interface
        │ HTTPS REST + Bearer JWT (HTTP for localhost development)
Spring Boot controllers → DTO validation → services
        │                                 │
Spring Security                      AnalysisToolService
        │                                 │
Spring Data JPA / Hibernate           JADX, Apktool, aapt/aapt2
        │                            Androguard / YARA remain planned
PostgreSQL + Flyway migrations
```

The implemented pipeline is upload → bounded archive validation → SHA-256/MD5 → queued static tools → metadata, permissions, components, API references, strings, URLs → persisted results. Threat intelligence, malware verdicts, YARA scoring, correlation, and risk scoring remain future work. Executable paths come from trusted operator configuration, never a request.

## Technology

- Frontend: JavaScript and JSX, React, Vite, Tailwind CSS, React Router, Axios, Recharts, Lucide React. No TypeScript source.
- Backend: **Java 17**, matching the installed system JDK as requested, Spring Boot 3.5.16, Maven, Spring Security, BCrypt, JJWT.
- Database: PostgreSQL, Spring Data JPA, Hibernate, Flyway SQL migrations. H2 is test-only.

## Layout

```text
frontend/src/
  api/          HTTP client and replaceable service adapters
  components/   Reusable interface elements
  layouts/      Sidebar and application shell
  pages/        Login, dashboard, and investigation modules
  routes/       Protected application navigation
  hooks/        Shared state and behavior
  utils/        Session and presentation helpers
backend/src/main/java/com/cyberintel/
  config/       CORS, security, and analysis properties
  controller/   REST endpoints
  dto/          Validated requests and safe user responses
  entity/       User, Scan, Alert, Role
  repository/   Parameterized JPA persistence
  service/      Authentication and planned static tool adapters
  security/     JWT generation/validation and user loading
  exception/    Consistent API errors
  util/         Email normalization and preliminary APK checks
backend/src/main/resources/db/migration/
  V1__foundation.sql
```

## Frontend setup

Install Node.js and npm. In `frontend`:

```powershell
npm install
Copy-Item .env.example .env.local
npm run dev
```

Open the local URL printed by Vite (normally http://localhost:5173).

`VITE_API_BASE_URL` configures the REST base URL; use `http://localhost:7070/api` for the backend below. Frontend environment variables are public and must never contain secrets.

For the development-only demo, set `VITE_ENABLE_DEMO=true` in `.env.local` and restart Vite. Log in with `admin@cyberintel.local` / `Admin@123`. This is a mock session, not a database account or usable backend JWT. Demo authentication is guarded by Vite development mode and is unavailable in production builds. Disable the flag to use real authentication.

Dashboard and other investigation modules retain labeled samples. APK Analysis now uses the live backend: create a real account on the login page, upload an APK, and start analysis. The frontend demo account cannot upload. When no configured tool is available, the backend returns prominently labeled deterministic MOCK findings; it never silently substitutes mock findings for failed real tools.

```powershell
npm run lint
npm run build
npm run preview
```

For production hosting, serve `frontend/dist`, configure an SPA fallback to `index.html` for React routes, and use HTTPS for both the site and API.

## PostgreSQL setup

Create a dedicated database and login using your PostgreSQL administrator account:

```sql
CREATE ROLE cyberintel LOGIN;
-- In psql, set its password interactively: \password cyberintel
CREATE DATABASE cyberintel OWNER cyberintel;
```

Use a strong unique password. The application needs schema migration permissions on its own database. For a production deployment, separate the migration account from the runtime account.

Flyway creates the tables and indexes on first startup. Hibernate validates the schema rather than silently changing it. User emails are normalized and unique. Each scan belongs to a user; an alert can reference a scan. No default database users or plaintext passwords are seeded.

## Backend setup

Install/use JDK **17 or newer** and Maven 3.6.3 or newer. The Maven compiler targets Java 17.

Copy `backend/.env.example` to `backend/.env` and fill in your database credentials and JWT secret. The backend loads this file when launched from the project root or `backend` directory. Use unquoted Java properties values (escape Windows path backslashes or use forward slashes). Environment variables override file values. Alternatively, export the values in the terminal running Maven or set them in the IDE run configuration:

```powershell
$env:DB_URL = 'jdbc:postgresql://localhost:5432/cyberintel'
$env:DB_USERNAME = 'cyberintel'
$env:DB_PASSWORD = Read-Host 'Database password' -MaskInput
$env:JWT_SECRET = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
$env:CORS_ALLOWED_ORIGINS = 'http://localhost:5173,http://127.0.0.1:5173'
cd backend
mvn spring-boot:run
```

The password prompt example requires PowerShell 7. Persist the JWT secret in a secret manager for deployed environments; generating a new secret invalidates existing tokens. Never commit it. API port defaults to 7070.

Build and test:

```powershell
mvn verify
java -jar target/cyberintel-0.1.0.jar
```

Tests use an isolated H2 database and a test-only key. A production startup requires the PostgreSQL credentials and JWT secret.

## Configuration reference

| Variable | Purpose / default |
| --- | --- |
| `DB_URL` | `jdbc:postgresql://localhost:5432/cyberintel` |
| `DB_USERNAME`, `DB_PASSWORD` | Required PostgreSQL credentials |
| `JWT_SECRET` | Required random secret of at least 32 UTF-8 bytes |
| `JWT_EXPIRATION_SECONDS` | 3600; allowed range 60–86400 |
| `CORS_ALLOWED_ORIGINS` | Comma-separated exact origins; defaults to `http://localhost:5173,http://127.0.0.1:5173`; wildcard rejected |
| `PORT` | 7070 |
| `UPLOAD_DIRECTORY` | `./analysis/uploads`; server-controlled APK storage |
| `MAX_APK_SIZE` | `50MB`; multipart and preliminary validator limit |
| `JADX_PATH`, `APKTOOL_PATH`, `AAPT_PATH`, `ANDROGUARD_PATH`, `YARA_PATH` | Trusted operator paths, empty by default |
| `JADX_ENABLED`, `APKTOOL_ENABLED`, `AAPT_ENABLED` | `false`; enable only with a trusted tool path |
| `ANDROGUARD_ENABLED`, `YARA_ENABLED` | `false`; integration remains planned |
| `ANALYSIS_DIRECTORY` | `./analysis`; private scan output root |
| `ANALYSIS_TIMEOUT_SECONDS` | 120 per tool |
| `ANALYSIS_RETENTION_DAYS` | 7; hourly artifact cleanup, database results retained |
| `VITE_API_BASE_URL` | Frontend REST base URL |
| `VITE_ENABLE_DEMO` | Opt-in development-only demo authentication |

## Authentication API

| Method / route | Access | Result |
| --- | --- | --- |
| `POST /api/auth/register` | Public | 201, token and safe user DTO; role is always USER |
| `POST /api/auth/login` | Public | 200, token and safe user DTO |
| `GET /api/auth/me` | Bearer token | Current user DTO |
| `GET /api/platform/status` | Bearer token | Platform readiness status |
| `GET /api/admin/tools` | ADMIN only | Configured availability; Androguard/YARA remain NOT_IMPLEMENTED |

Registration body:

```json
{"name":"Analyst","email":"analyst@example.com","password":"choose-a-unique-password"}
```

Login body contains `email` and `password`. A successful login/registration returns:

```json
{"token":"<signed JWT>","user":{"id":1,"name":"Analyst","email":"analyst@example.com","role":"USER"}}
```

Send `Authorization: Bearer <token>` to protected endpoints. Password hashes never appear in responses. Registration passwords require 10–72 characters and at most 72 UTF-8 bytes; the byte restriction avoids BCrypt truncation. Input DTOs reject unknown fields, including client-supplied roles.

An administrator may provision roles directly through a trusted database administration workflow, for example `UPDATE app_users SET role='ANALYST' WHERE email='analyst@example.com';`. There is no public role escalation endpoint. Roles are reloaded from the database for each authenticated request.

Errors consistently contain `success`, `message`, `timestamp`, and HTTP `status`. Validation, unauthorized requests, forbidden access, record conflicts, database failures, upload errors, and unexpected exceptions have dedicated handling.

## Implementation status and security boundaries

- Authentication, BCrypt, JWT signature/expiry checks, CORS, role protection, JPA entities, and migration are implemented.
- APK upload, progress polling, cancellation, history, and eight result tabs are implemented. Other investigation modules retain their sample views.
- `ApkAnalysisOrchestrator` coordinates configured JADX, Apktool, and aapt adapters. Androguard and YARA remain nonexecuting placeholders.
- Upload validation checks extension, MIME hints, size, ZIP integrity, bounded expansion, entry paths, and manifest structure. It does not certify signatures, installability, or safety. UUID storage names, controlled output directories, bounded worker queues, tool timeouts, output limits, and retention cleanup are implemented.
- Stateless bearer authentication does not use ambient cookies; CSRF is disabled for this API. Frontend token storage is subject to browser XSS risk; apply a restrictive CSP when deploying. Add rate limiting at the API gateway before public exposure.
- Serve deployed traffic over HTTPS with a trusted TLS reverse proxy. Local HTTP is only for development.
- No malware execution, sandbox detonation, arbitrary shell endpoint, final verdict, or risk scoring is included. Run external parsers under an unprivileged OS account in an isolated environment for untrusted samples.

## Verification

The backend builds on the installed Java 17.0.1. All 13 automated tests pass, including upload validation, SHA-256, ownership, mock fallback, cancellation, extraction, and process timeout. A separate PostgreSQL 18.2 database successfully ran migrations V1/V2 and Hibernate validation. H2 tests use a generated schema; migration verification runs against PostgreSQL.

Frontend dependencies are installed with a committed lockfile. ESLint passes without errors or warnings, and the Vite production build passes. The production bundle was checked to exclude the development demo credentials and mock authentication token.

Browser verification passed for login and all 12 sidebar pages at 1440, 768, and 375 pixels, with no runtime errors or page overflow. Navigation, filtering, dialogs, sample downloads, file checks, settings, and sign-out were exercised. Desktop and phone captures are saved in `frontend/screenshots`.

The Spring Boot-managed Flyway version logs that PostgreSQL 18 is newer than its tested support range (through PostgreSQL 17). Migration and authentication passed on the installed PostgreSQL 18.2; use PostgreSQL 17 for that tested support range or validate an updated Flyway version before deployment.
