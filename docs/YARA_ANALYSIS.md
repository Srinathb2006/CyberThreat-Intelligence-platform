# Local YARA analysis

After an APK scan completes, open its **YARA Analysis** tab and select **Run YARA**. The backend applies configured local `.yar` and `.yara` files to the retained JADX and Apktool extraction directories. It never installs or executes the APK, and it makes no external malware API calls.

Set `YARA_ENABLED=true`, `YARA_PATH` to an installed YARA command line executable, and `YARA_RULES_DIRECTORY` to a local directory containing rule files. Rules may include `severity` (`LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`) and `description` string metadata. Missing metadata defaults to `MEDIUM` and a generic description. The API returns the matched rule, severity, description, and relative extracted file path as evidence. A match is an indicator for review, not a malware verdict.

`POST /api/apk-analysis/{scanId}/yara` runs analysis; `GET /api/apk-analysis/{scanId}/yara` returns the saved result. Both endpoints require the scan owner. Results are stored by migration V14 and survive reloads. Scanning is limited to 50 rule files (1 MiB each), the configured extracted file count and size limits, 500 matches, 1 MiB of tool output, and the analysis timeout. Symbolic links in extraction output are rejected.

If YARA or its rule directory is unavailable, the existing deterministic demo analyzer supplies a synthetic sample result. The response has `mode: DEMO` and states that it is not evidence from the uploaded APK. Tool failures and missing extraction artifacts are reported as incomplete local analysis rather than as clean scans.
