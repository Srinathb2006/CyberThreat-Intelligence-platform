# Step 2 UI implementation
Continue frontend only; read user requirements C:/Users/padma/.codex/attachments/c981ddd4-934f-4737-811f-112ee27d27d5/Pasted text.txt. Existing midnight/teal SOC visual language, system sans/mono metadata, responsive and accessible. No images necessary beyond Lucide. Keep JavaScript/JSX only, retain stack. Read frontend-design implementation.md as before. All shell commands prefix rtk.

Implement real APK workflow in standalone pages/ApkAnalysis.jsx replacing the /apk-analysis placeholder, leaving other modules intact. API contracts below. Add real registration UI at login or link/inline register mode so users can obtain backend USER account (demo sessions cannot upload to real authenticated backend). Do not put credentials in production. For demo session clearly request sign-out and real account for APK module; do NOT build a second frontend mock-analysis engine. Backend handles deterministic MOCK results. Make upload, start scan, cancel, polling, selectable previous scans, hash metadata, errors, and eight result tabs functional. Results are indicators, not verdicts. Source snippets/URLs plain escaped text, never HTML or clickable malicious URLs. Avoid displaying server paths.

API base uses existing Axios:
GET /apk/config -> {maxApkSize:52428800,tools:{jadx:{available:false,enabled:false},apktool:{...},aapt:{...}}}
POST /apk/upload multipart field file -> {success:true,scanId:1,fileName:'sample.apk',fileSize:123,sha256:'...',status:'UPLOADED'}
POST /apk-analysis/{scanId}/start -> result DTO below, 202
POST /apk-analysis/{scanId}/cancel -> result DTO
GET /apk-analysis -> array of result DTO (latest 50 owned scans)
GET /apk-analysis/{scanId} -> result DTO
Result: {scanId,fileName,fileSize,sha256,md5,status:'UPLOADED'|'QUEUED'|'RUNNING'|'COMPLETED'|'FAILED'|'CANCELLED',stage,progress:0..100,analysisMode:null|'MOCK'|'REAL',message,metadata:{packageName,applicationName,versionName,versionCode,minSdk,targetSdk},toolStatus:{jadx,apktool,aapt},permissions:[{permissionName,category,severity,description}],components:[{componentType,componentName,exported:null|boolean,permission,severity}],apiFindings:[{className,methodName,apiName,category,severity,description}],strings:[{value,kind,source}],urls:['...'],sourceSummary:{javaFiles:0,smaliFiles:0,resourceFiles:0,assets:0,nativeLibraries:0,packages:[],classes:[],methods:[]},startedAt,completedAt,createdAt}.
Tool statuses strings NOT_RUN/UNAVAILABLE/SUCCESS/FAILED/TIMEOUT/MOCK/CANCELLED. Result arrays initially empty, metadata fields null; no riskScore/verdict. Poll ~1.5s until terminal, stop on unmount or auth expiry, no overlapping requests. Mark MOCK prominently and never mix with REAL, show tool failures even COMPLETED partial. Cancel aborts upload or calls cancellation endpoint for stored job. Max size comes from backend config. API errors {success:false,message,timestamp,status}.

Own frontend only. Install already done. Run lint/build, retain browser preview port5173. Add UI tests/smoke where possible; report. Root owns backend and docs.
