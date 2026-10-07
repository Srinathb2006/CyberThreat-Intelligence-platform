import { useEffect, useRef, useState } from 'react';
import { ArrowRight, LoaderCircle, Search, ShieldCheck } from 'lucide-react';
import { Button, Card, EmptyState } from '../components/ui';
import PhishingResults from '../components/PhishingResults';
import { useAuth } from '../hooks/useAuth';
import { analyzePhishing } from '../api/phishingApi';
import { URL_MAX_LENGTH, validateScanUrl } from '../utils/urlScanner';

export default function PhishingDetection() {
  const { session, logout } = useAuth();
  return <>
    <div className="page-heading"><div><div className="eyebrow">STATIC PHISHING ASSESSMENT</div><h1>Phishing detection<span className="title-dot">.</span></h1><p>Review URL signals with an explainable, rule-based assessment.</p></div><span className="page-icon"><ShieldCheck size={27} /></span></div>
    {session.demo ? <Card className="padded"><div className="state"><ShieldCheck size={38} /><h3>Connect a real account to assess URLs</h3><p>The local demo session cannot access the authenticated phishing assessment API. Sign out, then sign in or create an account.</p><Button onClick={logout}>Sign out and connect<ArrowRight size={16} /></Button></div></Card> : <PhishingWorkspace />}
  </>;
}

function PhishingWorkspace() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const request = useRef(null);
  useEffect(() => () => request.current?.abort(), []);

  async function submit(event) {
    event.preventDefault();
    if (busy) return;
    const validation = validateScanUrl(url);
    setError(validation || '');
    if (validation) return;
    setBusy(true); setResult(null);
    const controller = new AbortController();
    request.current = controller;
    try {
      const response = await analyzePhishing(url, controller.signal);
      if (!controller.signal.aborted) setResult(response);
    } catch (e) {
      if (!controller.signal.aborted) setError(e.response?.data?.message || 'Unable to assess this URL. Please try again.');
    } finally { if (!controller.signal.aborted) setBusy(false); }
  }

  return <>
    <div className="analysis-safety"><ShieldCheck size={17} /><span><strong>URL text only.</strong> No target HTTP requests, DNS lookups, machine learning, or external intelligence APIs. Results are not saved.</span></div>
    <Card className="padded"><div className="section-heading"><div><span className="eyebrow">01 / ADDRESS INTAKE</span><h2>Assess phishing indicators</h2></div><Search size={21} className="subtle-icon" /></div>
      <form onSubmit={submit} noValidate className="url-scan-form phishing-form"><label htmlFor="phishing-url">URL to assess</label><input id="phishing-url" type="text" inputMode="url" autoComplete="off" autoCapitalize="none" spellCheck={false} maxLength={URL_MAX_LENGTH} value={url} onChange={e => { setUrl(e.target.value); setError(''); }} disabled={busy} placeholder="https://example.com/sign-in" aria-describedby="phishing-input-help" aria-invalid={!!error} /><p id="phishing-input-help">Enter a complete HTTP or HTTPS address, up to {URL_MAX_LENGTH.toLocaleString()} characters. The address and any redirect values are inspected as text only.</p>{error && <div className="form-error" role="alert">{error}</div>}<Button type="submit" disabled={busy}>{busy ? <LoaderCircle className="spin" size={16} /> : <Search size={16} />}{busy ? 'Assessing URL…' : 'Assess URL'}</Button></form>
    </Card>
    {busy ? <Card className="analysis-results"><div className="state" role="status"><LoaderCircle className="spin" /><h3>Checking static phishing indicators</h3><p>Applying rules to the URL text…</p></div></Card> : result ? <Card className="analysis-results"><div className="analysis-result-header"><div><span className="eyebrow">02 / ANALYZED ADDRESS</span><h2>Phishing assessment</h2><p>{result.url}</p></div></div>{url !== result.url && <div className="info-note phishing-edited-note" role="status">The input has changed. These results apply to the analyzed address above. Select Assess URL to update them.</div>}<PhishingResults result={result} /></Card> : <Card className="analysis-results"><EmptyState title="Inspect an address to begin" message="The assessment will show rule points, supporting reasons, and possible redirect parameters." /></Card>}
  </>;
}
