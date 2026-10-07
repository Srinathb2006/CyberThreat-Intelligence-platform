# Static APK analysis

APK Analysis is the upload and reverse-engineering pipeline. The backend reads APK bytes as an archive, hashes them, and runs only configured local static tools. It never installs, launches, or executes the APK. A successful static scan supplies evidence for later, separate malware-rule, IOC, threat-intelligence, and risk actions.

## Workflow and API

Use a registered backend account; the frontend's development demo login cannot call the authenticated API.

| Action | Endpoint | Result |
| --- | --- | --- |
| Read limits and tool availability | `GET /api/apk/config` | Maximum APK size and enabled/available states for JADX, Apktool, aapt, Androguard, and YARA. |
| Upload | `POST /api/apk/upload` (`file` multipart field) | 201, scan ID, original display name, size, SHA-256, `UPLOADED`. |
| Start / cancel | `POST /api/apk-analysis/{id}/start` or `/cancel` | Queued job or terminal cancellation. |
| Poll / history | `GET /api/apk-analysis/{id}` or `GET /api/apk-analysis` | Stored status, tool states, metadata, findings, and latest 50 owned scans. |
| Derive malware findings and IOCs | `POST /api/static-analysis/{scanId}` | Rule-based findings from stored APK results. This is a separate action. |
| Match IOCs | `POST /api/threat-intelligence/correlate/{scanId}` | Compares extracted IOCs with the local database catalog. |
| Calculate risk | `POST /api/risk-correlation/{scanId}/calculate` | Persists an assessment and invokes alert generation. |
| Run / reload YARA | `POST` or `GET /api/apk-analysis/{scanId}/yara` | Separate local rule scan of retained extracted files, or labeled demo fallback. |

The frontend polls while the APK job is active and shows stages, partial failures, hashes, manifest data, permissions, components, APIs, strings, URLs, source inventory, and tool status. Extracted addresses are shown as text; they are not visited. Risk and report endpoints are described in [RISK_ALERTS_REPORTS.md](RISK_ALERTS_REPORTS.md).

## Real and mock modes

The core APK scan is `REAL` when at least one enabled static analyzer is available: JADX, Apktool, aapt, or Androguard. Tool outcomes are recorded individually (`SUCCESS`, `UNAVAILABLE`, `FAILED`, `TIMEOUT`, `CANCELLED`, or similar). A partial real scan may finish with warnings, but synthetic findings are not mixed into it. If every attempted real tool fails, the scan fails.

If none is enabled and available, `MockAnalysisFactory` generates deterministic example metadata and findings from the real uploaded SHA-256. The mode and all four core tool statuses are `MOCK`. The hash and file size still describe the uploaded bytes; the metadata and findings do not. Androguard unavailability therefore uses this existing mock fallback only when the whole core scan is mock. YARA has its own separately labeled `DEMO` result when its executable or rules are unavailable.

Dashboard trend/distribution charts and some dashboard fallback counts/events are also examples; they are not APK scan output. Local threat-intelligence seed records are demonstration content, even when a database match is real against that catalog.

## Tool behavior and configuration

All tools are disabled by default. Configure trusted executables through `backend/.env` or environment variables; request bodies cannot choose commands or paths.

| Tool | Configuration | Fixed static operation |
| --- | --- | --- |
| JADX | `JADX_ENABLED`, `JADX_PATH` | Decompile code into a controlled `jadx/sources` directory with one worker. |
| Apktool | `APKTOOL_ENABLED`, `APKTOOL_PATH` | Decode manifest/resources/smali into a controlled `apktool/decoded` directory. |
| aapt | `AAPT_ENABLED`, `AAPT_PATH` | `dump badging` for package metadata. |
| Androguard | `ANDROGUARD_ENABLED`, `ANDROGUARD_PATH` | Local Python executable imports Androguard and parses APK/DEX through a bundled helper. |
| YARA | `YARA_ENABLED`, `YARA_PATH`, `YARA_RULES_DIRECTORY` | Separate on-demand scan of extracted files with local `.yar`/`.yara` rules. |

The managed runner uses a process timeout, bounded output and entry limits, child-process termination on cancellation, and private logs. It does not provide an OS-level sandbox. The Androguard helper uses the existing runner; [ANDROGUARD_ANALYSIS.md](ANDROGUARD_ANALYSIS.md) describes its metadata and merge behavior. [YARA_ANALYSIS.md](YARA_ANALYSIS.md) describes rule format, saved matches, and demo behavior.

## Storage, extraction, and limits

Uploads receive UUID storage names beneath `UPLOAD_DIRECTORY`. Per-scan artifacts live beneath `ANALYSIS_DIRECTORY/scans/{id}`. The original filename is used only for display. Retained database results survive hourly cleanup of expired upload and tool-output files. The default retention period is seven days. An unstarted expired upload cannot later be scanned.

Upload validation checks extension, MIME hint, ZIP integrity and entry names, bounded expansion, and manifest structure. These checks are not Android signature verification or proof of installability. The extractor reads bounded text from JADX and Apktool output, then merges Androguard metadata, permissions, DEX inventory, and selected method references without duplicating permission or API names. The resulting references are heuristics; a DEX method reference does not prove invocation. Native libraries are counted but not executed or disassembled.

| Limit | Default |
| --- | --- |
| Compressed APK | `MAX_APK_SIZE=50MB` |
| Expanded archive | `MAX_APK_EXPANDED_BYTES=268435456` (256 MiB) |
| Archive/output entries | `MAX_APK_ENTRIES=20000` |
| Tool output | `MAX_ANALYSIS_OUTPUT_BYTES=536870912` (512 MiB) |
| Per-tool timeout | `ANALYSIS_TIMEOUT_SECONDS=120` |
| Active/queued jobs | 2 active, 8 queued |

The text extractor additionally reads at most 16 MiB total and 2 MiB per file, retaining bounded lists of strings, components, permissions, and API references. A full worker queue returns 429. Interrupted jobs are marked failed after restart; a terminal scan must be re-uploaded to retry. Cancellation is terminal.

## Security boundary

The upload and core APK result routes enforce scan ownership. Several later legacy routes for static findings, threat matching, risk, reports, and scan history currently require authentication but do not enforce that the requested scan belongs to the caller. See the README's security limitations before using multiple untrusted accounts. External parsers still process untrusted input; isolate them with OS permissions and network restrictions for deployment. No result is a malware verdict.
