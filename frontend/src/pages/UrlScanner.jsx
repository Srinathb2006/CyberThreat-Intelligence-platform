import { useEffect, useRef, useState } from 'react';
import { ArrowRight, Link2, LoaderCircle, RefreshCw, Search, ShieldCheck } from 'lucide-react';
import { Badge, Button, Card, EmptyState } from '../components/ui';
import { useAuth } from '../hooks/useAuth';
import { createUrlScan, getUrlScan, listUrlScans } from '../api/urlScanApi';
import { formatDate } from '../utils/apk';
import { mergeUrlHistory, URL_MAX_LENGTH, validateScanUrl } from '../utils/urlScanner';

const message = (error, fallback) => error.response?.data?.message || fallback;
const isAbort = error => error.code === 'ERR_CANCELED' || error.name === 'AbortError';

export default function UrlScanner() {
  const { session, logout } = useAuth();
  return <>
    <div className="page-heading"><div><div className="eyebrow">STATIC URL INSPECTION</div><h1>URL scanner<span className="title-dot">.</span></h1><p>Inspect the address. Understand its structure and the signals that need review.</p></div><span className="page-icon"><Link2 size={27} /></span></div>
    {session.demo ? <Card className="padded"><div className="state"><ShieldCheck size={38} /><h3>Connect a real account to inspect URLs</h3><p>The local demo session cannot access saved URL scans. Sign out, then sign in or create an account.</p><Button onClick={logout}>Sign out and connect<ArrowRight size={16} /></Button></div></Card> : <UrlWorkspace />}
  </>;
}

function UrlWorkspace() {
  const [url, setUrl] = useState('');
  const [history, setHistory] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(true);
  const [loadingResult, setLoadingResult] = useState(false);
  const [error, setError] = useState('');
  const [historyError, setHistoryError] = useState('');
  const [detailError, setDetailError] = useState('');
  const [historyRevision, setHistoryRevision] = useState(0);
  const [detailRevision, setDetailRevision] = useState(0);
  const submission = useRef(null);

  useEffect(() => () => submission.current?.abort(), []);
  useEffect(() => {
    const controller = new AbortController();
    setLoadingHistory(true); setHistoryError('');
    listUrlScans(controller.signal).then(rows => {
      if (controller.signal.aborted) return;
      setHistory(rows.slice(0, 50));
      setSelectedId(current => current ?? rows[0]?.scanId ?? null);
    }).catch(e => { if (!isAbort(e)) setHistoryError(message(e, 'Unable to load saved URL scans.')); })
      .finally(() => { if (!controller.signal.aborted) setLoadingHistory(false); });
    return () => controller.abort();
  }, [historyRevision]);

  useEffect(() => {
    if (selectedId == null) return;
    const controller = new AbortController();
    setLoadingResult(true); setDetailError('');
    getUrlScan(selectedId, controller.signal).then(scan => {
      if (!controller.signal.aborted) setResult(scan);
    }).catch(e => { if (!isAbort(e)) setDetailError(message(e, 'Unable to retrieve this saved analysis. Retry to reload it.')); })
      .finally(() => { if (!controller.signal.aborted) setLoadingResult(false); });
    return () => controller.abort();
  }, [selectedId, detailRevision]);

  async function submit(event) {
    event.preventDefault();
    if (busy) return;
    const validation = validateScanUrl(url);
    setError(validation || '');
    if (validation) return;
    setBusy(true);
    const controller = new AbortController();
    submission.current = controller;
    try {
      const scan = await createUrlScan(url, controller.signal);
      if (controller.signal.aborted) return;
      setResult(scan); setSelectedId(scan.scanId);
      setHistory(rows => mergeUrlHistory(rows, scan));
    } catch (e) { if (!isAbort(e)) setError(message(e, 'URL analysis could not be saved. Please try again.')); }
    finally { if (!controller.signal.aborted) setBusy(false); }
  }

  const current = result?.scanId === selectedId ? result : null;
  return <>
    <div className="analysis-safety"><ShieldCheck size={17} /><span><strong>Static inspection only.</strong> URLs are never visited or requested. No DNS lookup, redirects, or page downloads.</span></div>
    <div className="apk-workspace-grid url-workspace-grid">
      <Card className="padded"><div className="section-heading"><div><span className="eyebrow">01 / ADDRESS INTAKE</span><h2>Analyze a URL</h2></div><Search size={21} className="subtle-icon" /></div>
        <form onSubmit={submit} noValidate className="url-scan-form">
          <label htmlFor="scan-url">URL to inspect</label>
          <input id="scan-url" type="text" inputMode="url" autoComplete="off" autoCapitalize="none" spellCheck={false} maxLength={URL_MAX_LENGTH} placeholder="https://example.com/path" value={url} onChange={e => setUrl(e.target.value)} disabled={busy} aria-describedby="url-input-help url-privacy-note" aria-invalid={!!error} />
          <p id="url-input-help">Use a complete HTTP or HTTPS address. Up to {URL_MAX_LENGTH.toLocaleString()} characters.</p>
          <p id="url-privacy-note">The full address is saved to your account. Remove any private tokens before submitting.</p>
          {error && <div className="form-error" role="alert">{error}</div>}
          <Button type="submit" disabled={busy || loadingHistory}>{busy ? <LoaderCircle size={16} className="spin" /> : <Search size={16} />}{busy ? 'Analyzing address…' : 'Analyze URL'}</Button>
          {busy && <span className="url-submit-status" role="status">Inspecting URL text and saving the result…</span>}
        </form>
        <p className="url-scope-note">Structure · Domain · IP address · HTTPS · TLDs · Obfuscation · Keywords</p>
      </Card>
      <Card className="previous-scans"><div className="panel-heading"><div><span className="eyebrow">YOUR WORKSPACE / LATEST 50</span><h2>Saved URL scans <span className="count-label">{history.length}</span></h2></div><button className="icon-button" aria-label="Refresh URL scan history" disabled={busy || loadingHistory} onClick={() => setHistoryRevision(v => v + 1)}><RefreshCw size={16} className={loadingHistory ? 'spin' : ''} /></button></div>
        {historyError && <div className="form-error url-history-error" role="alert">{historyError}<Button variant="secondary" disabled={busy || loadingHistory} onClick={() => setHistoryRevision(v => v + 1)}>Retry history</Button></div>}
        <div className="scan-history-list">{loadingHistory && !history.length ? <div className="state" role="status"><LoaderCircle className="spin" /><p>Loading saved scans…</p></div> : history.length ? history.map(scan => <button key={scan.scanId} className={`scan-history-item ${scan.scanId === selectedId ? 'selected' : ''}`} aria-pressed={scan.scanId === selectedId} disabled={busy} onClick={() => setSelectedId(scan.scanId)}><span className="scan-file-icon"><Link2 size={19} /></span><span className="scan-history-details"><strong>{scan.url}</strong><small>#{scan.scanId} · {formatDate(scan.createdAt)}</small></span><Badge>{scan.analysis?.riskLevel || scan.status}</Badge></button>) : !historyError && <EmptyState title="No URLs inspected yet" message="Analyze an address to save its static findings here." />}</div>
      </Card>
    </div>
    {selectedId != null && <Card className="analysis-results">
      <div className="analysis-result-header"><div><span className="eyebrow">02 / SAVED ANALYSIS #{selectedId}</span><h2>Address evidence</h2><p>{current?.url || 'Retrieving your stored analysis'}</p></div><Button variant="secondary" disabled={busy || loadingResult} onClick={() => setDetailRevision(v => v + 1)}><RefreshCw size={14} />Reload analysis</Button></div>
      {detailError && <div className="form-error poll-error" role="alert">{detailError}</div>}
      {loadingResult ? <div className="state" role="status"><LoaderCircle className="spin" /><p>Loading analysis…</p></div> : !detailError && current?.analysis && <UrlEvidence result={current} />}
    </Card>}
  </>;
}

function UrlEvidence({ result }) {
  const analysis = result.analysis;
  const fields = [['Host', analysis.host], ['Domain (normalized host)', analysis.domain || 'Not applicable — IP-based URL'], ['IP address', analysis.ipAddress || 'Not an IP-based URL'], ['HTTPS', analysis.https ? 'Yes — HTTPS scheme' : 'No — HTTP scheme'], ['Effective port', analysis.port], ['Path', analysis.path || '/'], ['Query present', analysis.queryPresent ? 'Yes' : 'No'], ['Fragment present', analysis.fragmentPresent ? 'Yes' : 'No']];
  return <div className="url-evidence">
    <div className="url-score"><div><span className="eyebrow">HEURISTIC SCORE</span><strong>{analysis.score}<small>/100</small></strong><Badge>{analysis.riskLevel}</Badge></div><p>Indicators for review, not a malware verdict. A low score does not establish safety. HTTPS describes the URL scheme; no certificate or website was checked.</p></div>
    <dl className="url-facts">{fields.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
    <div className="section-heading"><h3>Static findings</h3><span className="muted small">{analysis.findings.length} indicators</span></div>
    {analysis.findings.length ? <ul className="url-findings">{analysis.findings.map((finding, index) => <li key={`${finding.code}-${index}`}><div className="url-finding-heading"><Badge>{finding.severity}</Badge><strong>{finding.code.replaceAll('_', ' ')}</strong><span className="muted small">+{finding.contribution} points</span></div><p>{finding.description}</p>{finding.evidence && <code>{finding.evidence}</code>}</li>)}</ul> : <p className="url-no-findings">No configured suspicious patterns were detected in the URL text.</p>}
  </div>;
}
