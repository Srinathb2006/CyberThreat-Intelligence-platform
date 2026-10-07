# Step 2: Static APK reverse engineering

The existing Java 25 / Spring Boot and JavaScript React stack is retained. APK bytes are only read, hashed, decoded, and inspected. No emulator, installer, APK launcher, rebuild command, or user-supplied executable is supported.

## Using the workflow

1. Start PostgreSQL and the backend using the environment variables in `backend/.env.example`.
2. Set the frontend `VITE_API_BASE_URL` to that server's `/api` URL. Restart Vite after changing its environment.
3. Create an account on the login page or sign in with a registered account. The development demo login is intentionally barred from uploading to the live API.
4. Open APK Analysis and choose/drop an `.apk`. Upload validates and stores it, computes SHA-256 and MD5, and creates an owned scan.
5. Review the hash and select **Scan**. Progress is polled; cancellation stops the managed process. Previous scans reload from PostgreSQL.
6. Inspect Overview, APK Information, Permissions, Components, API Calls, Strings, URLs, and Tool Status. Extracted URLs are displayed as text and never visited.

## REAL versus MOCK

- With no enabled and available tool, the backend creates **MOCK** findings determined by the uploaded SHA-256. Hashes and file size describe the actual upload; metadata, permissions, components, source counts, and findings are explicitly synthetic.
- With at least one available tool, the scan is **REAL**. Missing tools are marked `UNAVAILABLE`. Successful tools can produce a partial real result, with unavailable/failed/timed-out tools shown individually. No mock findings are added.
- If every attempted real tool fails, the scan fails. It does not turn into a mock success. Missing aapt does not prevent Apktool manifest/metadata extraction.
- Tool availability checks configuration, a regular file, and executable support. A damaged tool or missing runtime dependency may still fail at execution, which is reported as `FAILED`.

Permissions and API references are indicators, not proof of malware. There is no final malware verdict, IOC matching, correlation, YARA scoring, phishing analysis, or risk score in this step.

## Configuring real tools

Download tools from their official projects: [JADX releases](https://github.com/skylot/jadx/releases), [Apktool releases](https://github.com/iBotPeaches/Apktool/releases), and [Android Build Tools / aapt2](https://developer.android.com/tools/aapt2). Keep the tool directory writable only by the operator.

Set `JADX_ENABLED=true`, `APKTOOL_ENABLED=true`, and optionally `AAPT_ENABLED=true`, with absolute paths in `JADX_PATH`, `APKTOOL_PATH`, and `AAPT_PATH`. Flags default to false so deployment never unexpectedly launches a tool merely because it is on PATH.

On Windows, configure the JADX distribution's `lib/jadx-<version>-all.jar`, the Apktool JAR, and `aapt.exe` or `aapt2.exe`. The runner invokes the server JDK directly for JARs. JADX uses the JAR directory as its classpath and `jadx.cli.JadxCLI`; Apktool uses `java -jar`. `.bat`, `.cmd`, and `.ps1` launchers are deliberately unsupported to avoid shell interpretation. On Unix, a trusted executable CLI launcher is also supported. Tool paths never come from requests.

Fixed argument lists:

```text
JADX:    --no-res -j 1 -d <generated output>/sources <generated upload>.apk
Apktool: d -f -p <generated output>/framework -o <generated output>/decoded <generated upload>.apk
aapt:    dump badging <generated upload>.apk
```

The API does not reveal storage locations or raw tool logs. stdout/stderr are merged and drained into a capped private `tool.log` (256 KiB). Each process has a timeout, cancellation checks, tracked child-process termination, and output size/file-count checks. Java tools receive a 512 MiB heap limit. These application controls are not an OS security sandbox: deploy the backend/tools under a low-privilege account with filesystem/network restrictions when accepting untrusted uploads. Do not deploy this single-process worker queue across multiple backend instances without a shared job coordinator.

## Storage and limits

```text
analysis/
  uploads/<random UUID>.apk
  scans/<numeric database scan id>/
    jadx/
    apktool/
    aapt/
    extracted/
    temporary/
```

`UPLOAD_DIRECTORY` and `ANALYSIS_DIRECTORY` are trusted server configuration. The original filename is display-only. Storage paths reject symlink ancestors. Archive checks reject traversal, absolute/drive paths, duplicate case-folded entries, CRC errors, missing/malformed manifests, excessive compression, and over-limit expansion. XML external entities and DTDs are disabled. A binary manifest header or well-formed textual manifest is accepted for static inspection; this is not Android signature or installability validation.

| Setting | Default |
| --- | --- |
| `MAX_APK_SIZE` | 50MB compressed upload |
| `MAX_APK_EXPANDED_BYTES` | 268435456 (256 MiB) |
| `MAX_APK_ENTRIES` | 20000 |
| `MAX_ANALYSIS_OUTPUT_BYTES` | 536870912 (512 MiB per tool output) |
| `ANALYSIS_TIMEOUT_SECONDS` | 120 per tool |
| `ANALYSIS_RETENTION_DAYS` | 7 |

The worker pool permits two running jobs and eight queued jobs. A full queue returns 429 and leaves the upload retryable. Running/queued jobs interrupted by a server restart become FAILED, rather than remaining stuck. Re-upload to retry a terminal scan. Cancellation is terminal and subsequent worker updates cannot overwrite it.

Temporary output is cleaned after a job. An hourly retention task removes expired upload/output files while retaining database findings; it skips active jobs and gives cancelled jobs a termination grace period. An unstarted expired upload becomes FAILED. Storage errors produce safe API errors without exposing filesystem paths.

## API contract

Every endpoint requires a bearer JWT. A scan is visible and controllable only by its owner; foreign scan IDs return 404.

| Endpoint | Behavior |
| --- | --- |
| `GET /api/apk/config` | Upload size limit and tool availability, no executable paths |
| `POST /api/apk/upload` | multipart field `file`; 201 with scan ID, original display name, size, SHA-256, UPLOADED |
| `POST /api/apk-analysis/{scanId}/start` | 202 with current state; starts only a new UPLOADED scan |
| `POST /api/apk-analysis/{scanId}/cancel` | Cancels queued/running/unstarted work; terminal scans are unchanged |
| `GET /api/apk-analysis/{scanId}` | Metadata, hashes, mode, tool states, stage/progress, findings, timestamps |
| `GET /api/apk-analysis` | Latest 50 owned scans and their results |

Upload validation and hashes complete before the upload response. The UI shows that server-processing period without inventing individual upload-stage percentages. Analysis stages are persisted and polled after start. State updates are separate from HTTP handlers so SSE or a persistent job queue can replace polling later.

## Extraction scope

- Apktool XML supplies package metadata, permissions, activity/alias/service/receiver/provider components, exported flags, and permission guards. Resource labels and `apktool.yml` supply fallbacks; successful aapt badging enriches metadata.
- JADX Java and Apktool smali/text outputs supply bounded heuristic API references, packages, classes, methods, quoted strings, URLs, domains, IPv4 candidates, emails, file paths, and command-like keywords.
- Component defaults follow manifest/SDK rules where determinable; an ambiguous exported flag is null rather than an invented certainty.
- API method attribution is null where not reliably determined. Counts represent extracted/retained references, not a full semantic call graph. Obfuscation, reflection, native code, and encrypted strings limit static extraction.
- Extraction reads at most 16 MiB of eligible text and 2 MiB per file, retaining up to 1,000 strings/components/permissions and 500 API references. Files/counts and caps appear in `sourceSummary`. Native-library and asset counts are inventory only; native binaries are not executed or disassembled.

## Verification

Run `mvn verify` in `backend` and `npm run lint`, `npm test`, `npm run build` in `frontend`. Backend fixtures are harmless synthetic archives/source text, not malware. Process tests launch only a dedicated Java test helper to verify stdout/stderr, timeout, and cancellation.

Downloaded tools and the benign Appium ApiDemos APK used for live verification are kept under the ignored `.verification` folder; they are not repository fixtures or production configuration. Official download sources are recorded there. No APK is executed during verification.
