import { useEffect, useRef, useState } from 'react';
import { UploadCloud, ShieldCheck, PackageSearch, Play, X, RefreshCw, FileCode2, ArrowRight, AlertTriangle, LoaderCircle, Bug, Search, Network, Hash, Zap, Shield, Target, Link2, Gauge } from 'lucide-react';
import { Card, Badge, Button, EmptyState } from '../components/ui';
import { useAuth } from '../hooks/useAuth';
import { validateApk, getApkConfig, uploadApk, listApkScans, getApkScan, startApkScan, cancelApkScan, runStaticAnalysis, getStaticSummary, getMalwareFindings, getIocs, runThreatIntelCorrelation, getThreatIntelCorrelationSummary, calculateRisk } from '../api/scanApi';
import ResultContent from '../components/ApkResults';
import { StatusBadge } from '../components/apkStatus';
import { formatBytes, formatDate, activeStatuses } from '../utils/apk';
const tabs = ['Overview', 'APK Information', 'Permissions', 'Components', 'API Calls', 'Strings', 'URLs', 'Tool Status', 'YARA Analysis', 'Static Malware Analysis', 'IOC Explorer', 'Threat Intelligence', 'Risk Correlation'];
const apiError = (error, fallback) => error.response?.data?.message || fallback;
const isAbort = error => error.code === 'ERR_CANCELED' || error.name === 'AbortError';
export default function ApkAnalysis() {
  const { session, logout } = useAuth();
  return <><div className="page-heading"><div><div className="eyebrow">REVERSE ENGINEERING WORKSPACE</div><h1>APK analysis<span className="title-dot">.</span></h1><p>Look inside an Android package. Follow the evidence, from file to findings.</p></div><span className="page-icon"><PackageSearch size={27} /></span></div>
    {session.demo ? <Card className="padded"><div className="state"><ShieldCheck size={38} /><h3>Connect a real account to investigate APKs</h3><p>The local demo session cannot access the authenticated analysis API. Sign out, then sign in or create an account to upload a package.</p><Button onClick={logout}>Sign out and connect<ArrowRight size={16} /></Button></div><div className="info-note">When analysis tools are unavailable, the backend can return explicitly labeled MOCK results. Uploaded APKs are never executed.</div></Card> : <AnalysisWorkspace />}</>;
}
function AnalysisWorkspace() {
  const [config, setConfig] = useState(null); const [history, setHistory] = useState([]); const [initializing, setInitializing] = useState(true); const [initError, setInitError] = useState('');
  const [file, setFile] = useState(null); const [selectedId, setSelectedId] = useState(null); const [result, setResult] = useState(null); const [loadingResult, setLoadingResult] = useState(false); const [tab, setTab] = useState('Overview');
  const [error, setError] = useState(''); const [notice, setNotice] = useState(''); const [busy, setBusy] = useState(''); const [uploadProgress, setUploadProgress] = useState(0); const [pollError, setPollError] = useState(''); const [refresh, setRefresh] = useState(0); const [initAttempt, setInitAttempt] = useState(0);
  const [staticBusy, setStaticBusy] = useState(false); const [staticProgress, setStaticProgress] = useState(0); const [staticStage, setStaticStage] = useState(''); const [staticError, setStaticError] = useState('');
  const [threatIntelBusy, setThreatIntelBusy] = useState(false); const [threatIntelError, setThreatIntelError] = useState('');
  const [riskBusy, setRiskBusy] = useState(false); const [riskError, setRiskError] = useState('');
  const uploadController = useRef(null); const mounted = useRef(true); const fileInput = useRef(null); const staticController = useRef(null); const threatIntelController = useRef(null); const riskController = useRef(null);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; uploadController.current?.abort(); staticController.current?.abort(); threatIntelController.current?.abort(); riskController.current?.abort(); }; }, []);
  useEffect(() => {
    const controller = new AbortController(); setInitializing(true); setInitError('');
    Promise.all([getApkConfig(controller.signal), listApkScans(controller.signal)]).then(([settings, scans]) => {
      if (controller.signal.aborted) return;
      setConfig(settings); setHistory(scans); setSelectedId(id => id ?? scans[0]?.scanId ?? null);
    }).catch(e => { if (!isAbort(e)) setInitError(apiError(e, 'Unable to connect to the APK service. Check that the backend is running.')); }).finally(() => { if (!controller.signal.aborted) setInitializing(false); });
    return () => controller.abort();
  }, [initAttempt]);
  useEffect(() => {
    if (!selectedId) return;
    const controller = new AbortController(); let timer; setPollError(''); setLoadingResult(true);
    async function poll() {
      try {
        const current = await getApkScan(selectedId, controller.signal);
        if (controller.signal.aborted) return;
        setResult(current); setLoadingResult(false); setHistory(rows => [current, ...rows.filter(row => row.scanId !== current.scanId)].sort((a, b) => b.scanId - a.scanId));
        if (activeStatuses.includes(current.status)) timer = setTimeout(poll, 1500);
      } catch (e) { if (!isAbort(e)) { setPollError(apiError(e, 'Progress updates are unavailable. Retry to reconnect to this scan.')); setLoadingResult(false); } }
    }
    poll(); return () => { controller.abort(); clearTimeout(timer); };
  }, [selectedId, refresh]);
  function choose(candidate) {
    if (busy || !candidate) return;
    setError(''); setNotice(''); const validation = validateApk(candidate, config?.maxApkSize);
    if (validation) { setError(validation); setFile(null); return; } setFile(candidate);
  }
  async function upload() {
    const validation = validateApk(file, config?.maxApkSize); if (validation) { setError(validation); return; }
    setBusy('upload'); setError(''); setNotice(''); setUploadProgress(0); uploadController.current = new AbortController();
    try {
      const response = await uploadApk(file, { signal: uploadController.current.signal, onProgress: setUploadProgress });
      if (!mounted.current) return;
      setResult(response); setSelectedId(response.scanId); setTab('Overview'); setFile(null); if (fileInput.current) fileInput.current.value = '';
      setNotice('APK uploaded and fingerprinted. Review its hash, then start the static analysis.'); setRefresh(v => v + 1);
    } catch (e) {
      if (!mounted.current) return;
      if (isAbort(e)) setNotice('Upload request cancelled. If the server received the complete file, it may appear in previous scans when you refresh.');
      else setError(apiError(e, 'The upload could not be completed. Check your connection and try again.'));
    } finally { if (mounted.current) setBusy(''); uploadController.current = null; }
  }
  async function act(action) {
    if (!result) return; setBusy(action); setError(''); setNotice('');
    try { const updated = await (action === 'start' ? startApkScan(result.scanId) : cancelApkScan(result.scanId)); if (mounted.current) { setResult(updated); setRefresh(v => v + 1); } }
    catch (e) { if (mounted.current) setError(apiError(e, action === 'start' ? 'Could not start the scan. Please retry.' : 'Could not cancel the scan. Refresh to check its current status.')); }
    finally { if (mounted.current) setBusy(''); }
  }

  async function runStatic() {
    if (!currentResult || staticBusy) return;
    setStaticBusy(true); setStaticError(''); setStaticProgress(0); setStaticStage('Starting…');
    staticController.current = new AbortController();

    try {
      const summary = await runStaticAnalysis(currentResult.scanId, false, staticController.current.signal);
      if (staticController.current.signal.aborted) return;
      setStaticStage('Analysis complete'); setStaticProgress(100);
      setNotice('Static malware analysis completed. Check the Static Malware Analysis and IOC Explorer tabs.');
      setRefresh(v => v + 1);
    } catch (e) {
      if (staticController.current.signal.aborted) return;
      setStaticError(apiError(e, 'Static analysis could not be completed. Check your connection and try again.'));
    } finally {
      if (mounted.current) setStaticBusy(false);
    }
  }

  async function runThreatIntelCorrelation() {
    if (!currentResult || threatIntelBusy) return;
    setThreatIntelBusy(true); setThreatIntelError('');
    threatIntelController.current = new AbortController();

    try {
      const correlationResult = await runThreatIntelCorrelation(currentResult.scanId, threatIntelController.current.signal);
      if (threatIntelController.current.signal.aborted) return;
      setNotice(`Threat intelligence correlation completed. ${correlationResult.matched} of ${correlationResult.totalIocs} IOCs matched.`);
      setRefresh(v => v + 1);
    } catch (e) {
      if (threatIntelController.current.signal.aborted) return;
      setThreatIntelError(apiError(e, 'Threat intelligence correlation could not be completed. Check your connection and try again.'));
    } finally {
      if (mounted.current) setThreatIntelBusy(false);
    }
  }

  async function runRiskCorrelation() {
    if (!currentResult || riskBusy) return;
    setRiskBusy(true); setRiskError('');
    riskController.current = new AbortController();

    try {
      const riskResult = await calculateRisk(currentResult.scanId, riskController.current.signal);
      if (riskController.current.signal.aborted) return;
      setNotice(`Risk correlation completed. Risk score: ${riskResult.score?.toFixed(1) || 0} (${riskResult.riskLevel}).`);
      setRefresh(v => v + 1);
    } catch (e) {
      if (riskController.current.signal.aborted) return;
      setRiskError(apiError(e, 'Risk correlation could not be completed. Check your connection and try again.'));
    } finally {
      if (mounted.current) setRiskBusy(false);
    }
  }

  const currentResult = result?.scanId === selectedId ? result : null; const isActive = activeStatuses.includes(currentResult?.status);
  return <>
    <div className="analysis-safety"><ShieldCheck size={17} /><span><strong>Static inspection only.</strong> Packages are decoded and inspected, never installed or executed.</span><span className="analysis-step">STEP 02</span></div>
    {initError && <div className="form-error" role="alert">{initError}<Button variant="secondary" onClick={() => setInitAttempt(v => v + 1)}><RefreshCw size={14} />Retry connection</Button></div>}
    <div className="apk-workspace-grid"><Card className="padded upload-card"><div className="section-heading"><div><span className="eyebrow">01 / INTAKE</span><h2>Upload a package</h2></div><span className="subtle-icon"><UploadCloud size={21} /></span></div>
      <label className={`upload-zone ${!config || busy ? 'unavailable' : ''}`} onDragOver={e => e.preventDefault()} onDrop={e => { e.preventDefault(); if (config) choose(e.dataTransfer.files[0]); }}><UploadCloud size={30} /><strong>{file ? file.name : 'Drop an APK to begin'}</strong><span>{file ? formatBytes(file.size) : 'or browse files on your device'}</span><small>{config ? `.apk only · Up to ${formatBytes(config.maxApkSize)}` : 'Connecting to upload service…'}</small><input ref={fileInput} type="file" accept=".apk" aria-label="Browse APK file" disabled={!config || !!busy} onChange={e => choose(e.target.files[0])} /></label>
      {busy === 'upload' && <div className="upload-progress" role="status"><div><span>{uploadProgress === 100 ? 'Validating file & generating hash…' : 'Uploading APK…'}</span><strong>{uploadProgress}%</strong></div><progress aria-label="Upload progress" max="100" value={uploadProgress} /></div>}
      <div className="apk-actions"><Button disabled={!file || !config || !!busy} onClick={upload}><UploadCloud size={16} />Upload APK</Button>{busy === 'upload' ? <Button variant="secondary" onClick={() => uploadController.current?.abort()}><X size={15} />Cancel upload</Button> : file && <Button variant="secondary" onClick={() => { setFile(null); if (fileInput.current) fileInput.current.value = ''; }}>Clear</Button>}</div><p className="upload-caption">The server validates the archive and calculates its SHA-256 fingerprint before analysis.</p>
      <div className="tool-availability"><span>SERVER TOOL AVAILABILITY</span>{['jadx', 'apktool', 'aapt', 'androguard', 'yara'].map(tool => <div key={tool}><strong>{tool === 'jadx' ? 'JADX' : tool === 'apktool' ? 'Apktool' : tool === 'androguard' ? 'Androguard' : tool === 'yara' ? 'YARA' : 'aapt'}</strong><span className={config?.tools?.[tool]?.available ? 'tool-ready' : ''}>{initializing ? 'Checking…' : config?.tools?.[tool]?.available ? 'Available' : 'Unavailable'}</span></div>)}</div>
    </Card><Card className="previous-scans"><div className="panel-heading"><div><span className="eyebrow">YOUR WORKSPACE</span><h2>Previous APK scans <span className="count-label">{history.length}</span></h2></div><button className="icon-button" aria-label="Refresh scan history" title="Refresh scan history" disabled={!!busy || initializing} onClick={() => { setInitAttempt(v => v + 1); if (selectedId) setRefresh(v => v + 1); }}><RefreshCw size={16} className={initializing ? 'spin' : ''} /></button></div><div className="scan-history-list">{initializing && !history.length ? <div className="state"><LoaderCircle className="spin" size={24} /><p>Loading your scans…</p></div> : history.length ? history.map(scan => <button key={scan.scanId} className={`scan-history-item ${selectedId === scan.scanId ? 'selected' : ''}`} disabled={!!busy} onClick={() => { setSelectedId(scan.scanId); setError(''); setNotice(''); setTab('Overview'); }}><span className="scan-file-icon"><FileCode2 size={19} /></span><span className="scan-history-details"><strong>{scan.fileName}</strong><small>#{scan.scanId} · {formatBytes(scan.fileSize)} · {formatDate(scan.createdAt)}</small></span><span className="scan-history-badges"><StatusBadge status={scan.status} />{scan.analysisMode && <span className={`mode-small ${scan.analysisMode.toLowerCase()}`}>{scan.analysisMode}</span>}</span></button>) : <EmptyState title="Your first investigation starts here" message="Upload an APK to create a scan. Your most recent 50 scans will appear here." />}</div></Card></div>
    {error && <div className="form-error" role="alert">{error}</div>}{notice && <div className="info-note" role="status">{notice}</div>}
    {selectedId && <Card className="analysis-results"><div className="analysis-result-header"><div><span className="eyebrow">02 / INVESTIGATION #{selectedId}</span><h2>{currentResult?.fileName || 'Loading investigation…'}</h2><p>{currentResult ? `${formatBytes(currentResult.fileSize)} · ${currentResult.metadata?.packageName || 'Package details pending'}` : 'Retrieving your stored analysis'}</p></div><div className="apk-actions">{currentResult && <StatusBadge status={currentResult.status} />}{currentResult?.status === 'UPLOADED' && <Button disabled={!!busy || loadingResult} onClick={() => act('start')}><Play size={15} />{busy === 'start' ? 'Starting…' : 'Start scan'}</Button>}{currentResult && (isActive || currentResult.status === 'UPLOADED') && <Button variant="secondary" disabled={!!busy || loadingResult} onClick={() => act('cancel')}><X size={15} />{busy === 'cancel' ? 'Cancelling…' : 'Cancel scan'}</Button>}{currentResult && currentResult.status === 'COMPLETED' && !staticBusy && <Button onClick={runStatic}><Zap size={15} />Run Static Analysis</Button>}{currentResult && currentResult.status === 'COMPLETED' && staticBusy && <Button variant="secondary" disabled><LoaderCircle size={15} className="spin" />Analyzing…</Button>}{currentResult && currentResult.status === 'COMPLETED' && !threatIntelBusy && <Button onClick={runThreatIntelCorrelation} variant="outline"><Shield size={15} />Run Threat Intel Correlation</Button>}{currentResult && currentResult.status === 'COMPLETED' && threatIntelBusy && <Button variant="secondary" disabled><LoaderCircle size={15} className="spin" />Correlating…</Button>}{currentResult && currentResult.status === 'COMPLETED' && !riskBusy && <Button onClick={runRiskCorrelation} variant="outline"><Gauge size={15} />Calculate Risk</Button>}{currentResult && currentResult.status === 'COMPLETED' && riskBusy && <Button variant="secondary" disabled><LoaderCircle size={15} className="spin" />Calculating…</Button>}</div></div>
      {pollError && <div className="form-error poll-error" role="alert">{pollError}<Button variant="secondary" onClick={() => setRefresh(v => v + 1)}><RefreshCw size={14} />Retry updates</Button></div>}
      {staticError && <div className="form-error poll-error" role="alert">{staticError}<Button variant="secondary" onClick={runStatic}><RefreshCw size={14} />Retry static analysis</Button></div>}
      {threatIntelError && <div className="form-error poll-error" role="alert">{threatIntelError}<Button variant="secondary" onClick={runThreatIntelCorrelation}><RefreshCw size={14} />Retry threat intel correlation</Button></div>}
      {riskError && <div className="form-error poll-error" role="alert">{riskError}<Button variant="secondary" onClick={runRiskCorrelation}><RefreshCw size={14} />Retry risk correlation</Button></div>}
      {staticBusy && <div className="static-analysis-progress"><div><span className="stage-label"><LoaderCircle size={14} className="spin" />{staticStage || 'Running static malware analysis…'}</span><span>{staticProgress}%</span></div><progress aria-label="Static analysis progress" value={staticProgress} max="100" /></div>}
      {threatIntelBusy && <div className="static-analysis-progress"><div><span className="stage-label"><LoaderCircle size={14} className="spin" />Correlating IOCs with threat intelligence…</span></div><progress aria-label="Threat intelligence correlation progress" max="100" /></div>}
      {currentResult?.analysisMode && <div className={`analysis-mode-banner ${currentResult.analysisMode.toLowerCase()}`}><span><strong>Analysis Mode: {currentResult.analysisMode}</strong>{currentResult.analysisMode === 'MOCK' ? 'DEMO / MOCK ANALYSIS — Deterministic sample findings, not evidence from this APK.' : 'Findings extracted by available static analysis tools. Review tool status for coverage.'}</span><Badge tone={currentResult.analysisMode === 'MOCK' ? 'amber' : 'teal'}>{currentResult.analysisMode === 'MOCK' ? 'SAMPLE FINDINGS' : 'STATIC ANALYSIS'}</Badge></div>}
      {currentResult && <><div className="analysis-progress"><div><span className="stage-label">{isActive && <LoaderCircle size={14} className="spin" />}{currentResult.stage || (currentResult.status === 'UPLOADED' ? 'Ready to analyze' : currentResult.status)}</span><span>{Math.max(0, Math.min(100, currentResult.progress || 0))}%</span></div><progress aria-label="Analysis progress" value={currentResult.progress || 0} max="100" />{currentResult.message && <p className={currentResult.status === 'FAILED' ? 'analysis-message failure' : 'analysis-message'}>{currentResult.message}</p>}</div>
        {Object.values(currentResult.toolStatus || {}).some(status => ['FAILED', 'TIMEOUT', 'UNAVAILABLE'].includes(status)) && <div className="partial-warning"><AlertTriangle size={16} /><span>Some tools were unavailable or did not complete. Findings may be partial; review the Tool Status tab.</span></div>}
        <div className="result-tabs" role="tablist" aria-label="APK analysis results">{tabs.map((name, index) => <button key={name} id={`tab-${index}`} role="tab" aria-selected={tab === name} aria-controls="analysis-tab-panel" tabIndex={tab === name ? 0 : -1} onClick={() => setTab(name)} onKeyDown={e => { let next; if (e.key === 'ArrowRight') next = (index + 1) % tabs.length; if (e.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length; if (e.key === 'Home') next = 0; if (e.key === 'End') next = tabs.length - 1; if (next != null) { e.preventDefault(); setTab(tabs[next]); document.getElementById(`tab-${next}`)?.focus(); } }}>{name}</button>)}</div><div id="analysis-tab-panel" role="tabpanel" aria-labelledby={`tab-${tabs.indexOf(tab)}`} tabIndex={0}><ResultContent key={`${selectedId}-${tab}`} tab={tab} result={currentResult} /></div></>}
      {loadingResult && !currentResult && <div className="state" role="status"><LoaderCircle className="spin" /><p>Loading scan details…</p></div>}
    </Card>}
    <div className="analysis-footer-note"><ShieldCheck size={15} />Permissions and API patterns are indicators for review, not a malware verdict. Risk scoring uses deterministic, rule-based correlation.</div>
  </>;
}

