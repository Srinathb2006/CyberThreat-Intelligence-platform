# Androguard static analysis

Set `ANDROGUARD_ENABLED=true` and `ANDROGUARD_PATH` to the absolute path of a local Python executable with Androguard installed. The backend checks that Python can import `androguard.misc`, then runs a bundled helper through the existing bounded static tool runner. The helper calls Androguard's `AnalyzeAPK` to parse the APK and DEX files as data. It does not install or execute the APK.

Results join the existing APK analysis: missing manifest metadata, declared permissions, DEX file names and counts, and selected DEX method references. Permission and API findings already present from JADX, Apktool, or aapt are not duplicated. Method references indicate a capability to review; they do not establish that code executed. Tool status appears beside the other APK analyzers.

When Androguard is disabled or unavailable, the existing deterministic mock APK analyzer remains the fallback if no real static analyzer is available. Its output and tool status are labeled `MOCK`. If another real analyzer succeeds, unavailable Androguard contributes no synthetic findings and is marked `UNAVAILABLE`.
