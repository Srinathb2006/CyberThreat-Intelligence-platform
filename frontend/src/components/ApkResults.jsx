import { useState, useMemo, useEffect } from 'react';
import { Fingerprint, PackageSearch, ShieldCheck, FileCode2, Bug, Search, AlertTriangle, Network, Hash, Shield, AlertCircle, Target, Link2, Gauge, TrendingUp, Download, LoaderCircle } from 'lucide-react';
import { Table, Badge, Button, EmptyState } from './ui';
import { StatusBadge } from './apkStatus';
import { formatBytes, formatDate, activeStatuses } from '../utils/apk';
import { calculateRisk, getRiskAssessment, getRiskBreakdown, getRiskRecommendations } from '../api/scanApi';
import { downloadReport } from '../api/reportApi';
export default function ResultContent({ tab, result }) {
  const [query, setQuery] = useState(''); const [page, setPage] = useState(0); const meta = result.metadata || {}; const source = result.sourceSummary || {};
  const present = value => value == null || value === '' ? 'Not available' : String(value);
  const metadataRows = [['Application', meta.applicationName], ['Package', meta.packageName], ['Version name', meta.versionName], ['Version code', meta.versionCode], ['Minimum SDK', meta.minSdk], ['Target SDK', meta.targetSdk], ['File size', formatBytes(result.fileSize)], ['Analysis mode', result.analysisMode], ['Created', formatDate(result.createdAt)], ['Started', formatDate(result.startedAt)], ['Completed', formatDate(result.completedAt)]];
  const hashBlock = <div className="hash-block"><div><Fingerprint size={15} /><strong>SHA-256</strong></div><code>{result.sha256 || 'Calculated after upload'}</code>{result.md5 && <><div><Fingerprint size={15} /><strong>MD5 · identification only</strong></div><code>{result.md5}</code></>}</div>;
  if (tab === 'Overview') return <div className="result-overview"><div className="result-summary"><span className="summary-app-icon"><PackageSearch size={31} /></span><div><h3>{meta.applicationName || result.fileName}</h3><p className="mono">{meta.packageName || 'Package details are not yet available'}</p><small>{meta.versionName ? `Version ${meta.versionName}` : 'Version not available'} · {formatBytes(result.fileSize)}</small></div></div><div className="finding-counts">{[['Permissions', result.permissions?.length || 0], ['Relevant API patterns', result.apiFindings?.length || 0], ['URLs', result.urls?.length || 0], ['Components', result.components?.length || 0]].map(([label, count]) => <div key={label}><strong>{count}</strong><span>{label}</span></div>)}</div>{hashBlock}<div style={{ display: 'flex', gap: '8px', margin: '14px 0' }}><Button variant="secondary" onClick={() => downloadReport(result.id, 'pdf')}><Download size={14} /> Download PDF Report</Button><Button variant="secondary" onClick={() => downloadReport(result.id, 'json')}>Export JSON</Button><Button variant="secondary" onClick={() => downloadReport(result.id, 'summary')}>Summary CSV</Button></div><div className="info-note"><ShieldCheck size={18} />{result.status === 'UPLOADED' ? 'The file is stored and fingerprinted. Start the scan to inspect its contents.' : 'These results describe static indicators. Sensitive permissions and APIs can also be used by legitimate applications.'}</div></div>;

  if (tab === 'APK Information') return <div className="result-information"><div className="metadata-grid">{metadataRows.map(([label, value]) => <div key={label}><span>{label}</span><strong>{present(value)}</strong></div>)}</div>{hashBlock}<h3 className="source-summary-title">Extracted source inventory</h3><div className="source-counts">{[['Java files', source.javaFiles], ['Smali files', source.smaliFiles], ['Resources', source.resourceFiles], ['Assets', source.assets], ['Native libraries', source.nativeLibraries]].map(([label, value]) => <span key={label}><strong>{value || 0}</strong>{label}</span>)}</div>{[['Packages', source.packages], ['Classes', source.classes], ['Methods', source.methods]].map(([label, values]) => <details className="source-details" key={label}><summary>{label} <span>{values?.length || 0}</span></summary>{values?.length ? <pre>{values.join('\n')}</pre> : <p>No entries extracted.</p>}</details>)}</div>;
  if (tab === 'Tool Status') return <div className="tool-results"><div className="tool-status-intro"><h3>Analysis coverage</h3><p>Each tool reports its own outcome. A completed scan can contain partial results.</p></div>{['jadx', 'apktool', 'aapt'].map(name => <div className="tool-status-row" key={name}><span className="scan-file-icon"><FileCode2 size={22} /></span><div><h3>{name === 'jadx' ? 'JADX' : name === 'apktool' ? 'Apktool' : 'aapt'}</h3><p>{name === 'jadx' ? 'Java source, classes, methods, and API patterns' : name === 'apktool' ? 'Manifest, resources, smali, and Android components' : 'Application metadata and package properties'}</p></div><StatusBadge status={result.toolStatus?.[name] || 'NOT_RUN'} /></div>)}<div className="info-note">{result.analysisMode === 'MOCK' ? 'MOCK means the backend generated deterministic sample output because required tools were not available. It is not evidence from the uploaded APK.' : 'UNAVAILABLE means a tool is disabled or missing. FAILED and TIMEOUT indicate incomplete coverage. No mock findings are added to real analyses.'}</div></div>;
  const severity = { key: 'severity', label: 'SEVERITY', render: row => <Badge>{row.severity || 'UNKNOWN'}</Badge> };
  const definitions = {
    'Permissions': { rows: result.permissions || [], columns: [{ key: 'permissionName', label: 'PERMISSION', render: row => <span className="mono wrap-value">{row.permissionName}</span> }, { key: 'category', label: 'CATEGORY' }, severity, { key: 'description', label: 'CONTEXT', render: row => <span className="wrap-description">{row.description}</span> }] },
    'Components': { rows: result.components || [], columns: [{ key: 'componentName', label: 'COMPONENT', render: row => <span className="mono wrap-value">{row.componentName}</span> }, { key: 'componentType', label: 'TYPE' }, { key: 'exported', label: 'EXPORTED', render: row => row.exported == null ? 'Unspecified' : row.exported ? 'Yes' : 'No' }, { key: 'permission', label: 'GUARD PERMISSION', render: row => <span className="mono wrap-value">{row.permission || 'None declared'}</span> }, severity] },
    'API Calls': { rows: result.apiFindings || [], columns: [{ key: 'apiName', label: 'API PATTERN', render: row => <span className="mono wrap-value">{row.apiName}</span> }, { key: 'className', label: 'CLASS / METHOD', render: row => <span className="mono wrap-value">{row.className}<small>{row.methodName || 'Method not resolved'}</small></span> }, { key: 'category', label: 'CATEGORY' }, severity, { key: 'description', label: 'CONTEXT', render: row => <span className="wrap-description">{row.description}</span> }] },
    'Strings': { rows: result.strings || [], columns: [{ key: 'value', label: 'EXTRACTED VALUE', render: row => <code className="wrap-value extracted-text">{row.value}</code> }, { key: 'kind', label: 'KIND' }, { key: 'source', label: 'SOURCE', render: row => <span className="mono wrap-value">{row.source || 'Not available'}</span> }] },
    'URLs': { rows: (result.urls || []).map((value, id) => ({ value, id })), columns: [{ key: 'value', label: 'EXTRACTED URL · PLAIN TEXT ONLY', render: row => <code className="wrap-value extracted-text">{row.value}</code> }] },
  };
  if (tab === 'Static Malware Analysis') return <StaticMalwareAnalysisTab result={result} />;
  if (tab === 'IOC Explorer') return <IOCExplorerTab result={result} />;
  if (tab === 'Threat Intelligence') return <ThreatIntelligenceTab result={result} />;
  if (tab === 'Risk Correlation') return <RiskCorrelationTab result={result} />;

  const definition = definitions[tab]; const filtered = definition.rows.filter(row => Object.values(row).some(value => String(value ?? '').toLowerCase().includes(query.toLowerCase())));
  const pageSize = 50; const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize)); const currentPage = Math.min(page, pageCount - 1);
  return <div className="result-data"><div className="result-filter"><span>{filtered.length} of {definition.rows.length} {tab.toLowerCase()}</span><input aria-label={`Filter ${tab.toLowerCase()}`} placeholder={`Filter ${tab.toLowerCase()}…`} value={query} onChange={e => { setQuery(e.target.value); setPage(0); }} /></div>{definition.rows.length ? <Table columns={definition.columns} rows={filtered.slice(currentPage * pageSize, (currentPage + 1) * pageSize)} /> : <EmptyState title={`No ${tab.toLowerCase()} available`} message={result.status === 'UPLOADED' ? 'Start the static analysis to extract findings.' : activeStatuses.includes(result.status) ? 'The analysis is still in progress. Findings will appear when processing finishes.' : 'No entries were extracted. Check Tool Status to understand analysis coverage.'} />}{pageCount > 1 && <nav className="result-pagination" aria-label={`${tab} pagination`}><span>Page {currentPage + 1} of {pageCount} · {pageSize} per page</span><div className="apk-actions"><Button variant="secondary" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</Button><Button variant="secondary" disabled={currentPage + 1 === pageCount} onClick={() => setPage(currentPage + 1)}>Next</Button></div></nav>}{['Strings', 'URLs'].includes(tab) && <p className="extracted-note">Extracted content is displayed as untrusted plain text. Addresses are not opened or visited.</p>}</div>;
}

function StaticMalwareAnalysisTab({ result }) {
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [page, setPage] = useState(0);

  const findings = result.malwareFindings || [];
  const summary = result.staticSummary || {};

  const severityCounts = useMemo(() => ({
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
    HIGH: findings.filter(f => f.severity === 'HIGH').length,
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
    LOW: findings.filter(f => f.severity === 'LOW').length,
  }), [findings]);

  const categories = useMemo(() => [...new Set(findings.map(f => f.category))], [findings]);

  const filtered = findings.filter(row => {
    const matchesQuery = Object.values(row).some(v => String(v ?? '').toLowerCase().includes(query.toLowerCase()));
    const matchesSeverity = !severityFilter || row.severity === severityFilter;
    const matchesCategory = !categoryFilter || row.category === categoryFilter;
    return matchesQuery && matchesSeverity && matchesCategory;
  });

  const pageSize = 50;
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);

  const columns = [
    { key: 'category', label: 'CATEGORY', render: row => <Badge variant="outline">{row.category}</Badge> },
    { key: 'title', label: 'TITLE', render: row => <strong>{row.title}</strong> },
    { key: 'description', label: 'DESCRIPTION', render: row => <span className="wrap-description">{row.description}</span> },
    { key: 'evidence', label: 'EVIDENCE', render: row => <code className="wrap-value extracted-text">{row.evidence}</code> },
    { key: 'severity', label: 'SEVERITY', render: row => <Badge variant={severityVariant(row.severity)}>{row.severity}</Badge> },
    { key: 'confidence', label: 'CONFIDENCE', render: row => <Badge variant="secondary">{row.confidence}</Badge> },
    { key: 'source', label: 'SOURCE', render: row => <span className="mono">{row.source}</span> },
    { key: 'ruleId', label: 'RULE ID', render: row => <code className="mono">{row.ruleId}</code> },
  ];

  const severityVariant = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'destructive';
      case 'HIGH': return 'destructive';
      case 'MEDIUM': return 'warning';
      case 'LOW': return 'secondary';
      default: return 'outline';
    }
  };

  return (
    <div className="result-data">
      <div className="malware-summary">
        <div className="summary-cards">
          <div className="summary-card"><span className="count">{summary.totalFindings || findings.length}</span><span className="label">Total Findings</span></div>
          <div className="summary-card critical"><span className="count">{severityCounts.CRITICAL}</span><span className="label">Critical</span></div>
          <div className="summary-card high"><span className="count">{severityCounts.HIGH}</span><span className="label">High</span></div>
          <div className="summary-card medium"><span className="count">{severityCounts.MEDIUM}</span><span className="label">Medium</span></div>
          <div className="summary-card low"><span className="count">{severityCounts.LOW}</span><span className="label">Low</span></div>
          <div className="summary-card"><span className="count">{summary.suspiciousUrls || 0}</span><span className="label">Suspicious URLs</span></div>
          <div className="summary-card"><span className="count">{summary.suspiciousApis || 0}</span><span className="label">Suspicious APIs</span></div>
        </div>
      </div>

      <div className="result-filter">
        <input aria-label="Filter findings" placeholder="Filter findings…" value={query} onChange={e => { setQuery(e.target.value); setPage(0); }} />
        <select value={severityFilter} onChange={e => { setSeverityFilter(e.target.value); setPage(0); }} aria-label="Filter by severity">
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select value={categoryFilter} onChange={e => { setCategoryFilter(e.target.value); setPage(0); }} aria-label="Filter by category">
          <option value="">All Categories</option>
          {categories.map(cat => <option key={cat} value={cat}>{cat.replace(/_/g, ' ')}</option>)}
        </select>
      </div>

      {findings.length ? (
        <Table columns={columns} rows={filtered.slice(currentPage * pageSize, (currentPage + 1) * pageSize)} />
      ) : (
        <EmptyState title="No malware findings" message="Run static malware analysis to detect suspicious patterns." />
      )}

      {pageCount > 1 && (
        <nav className="result-pagination" aria-label="Findings pagination">
          <span>Page {currentPage + 1} of {pageCount} · {pageSize} per page</span>
          <div className="apk-actions">
            <Button variant="secondary" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</Button>
            <Button variant="secondary" disabled={currentPage + 1 === pageCount} onClick={() => setPage(currentPage + 1)}>Next</Button>
          </div>
        </nav>
      )}

      <p className="extracted-note">Findings are based on static rule-based analysis. No dynamic execution was performed.</p>
    </div>
  );
}

function IOCExplorerTab({ result }) {
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [page, setPage] = useState(0);

  const iocs = result.iocs || [];
  const summary = result.staticSummary || {};

  const typeCounts = useMemo(() => {
    const counts = {};
    iocs.forEach(ioc => { counts[ioc.type] = (counts[ioc.type] || 0) + 1; });
    return counts;
  }, [iocs]);

  const types = useMemo(() => [...new Set(iocs.map(i => i.type))], [iocs]);

  const filtered = iocs.filter(row => {
    const matchesQuery = Object.values(row).some(v => String(v ?? '').toLowerCase().includes(query.toLowerCase()));
    const matchesType = !typeFilter || row.type === typeFilter;
    const matchesSeverity = !severityFilter || row.severity === severityFilter;
    return matchesQuery && matchesType && matchesSeverity;
  });

  const pageSize = 50;
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);

  const columns = [
    { key: 'type', label: 'TYPE', render: row => <Badge variant="outline">{row.type}</Badge> },
    { key: 'value', label: 'VALUE', render: row => <code className="wrap-value extracted-text">{row.value}</code> },
    { key: 'source', label: 'SOURCE', render: row => <span className="mono">{row.source}</span> },
    { key: 'severity', label: 'SEVERITY', render: row => <Badge variant={severityVariant(row.severity)}>{row.severity}</Badge> },
    { key: 'confidence', label: 'CONFIDENCE', render: row => <Badge variant="secondary">{row.confidence}</Badge> },
    { key: 'description', label: 'DESCRIPTION', render: row => <span className="wrap-description">{row.description}</span> },
    { key: 'firstSeen', label: 'FIRST SEEN', render: row => <span className="mono">{formatDate(row.firstSeen)}</span> },
  ];

  const severityVariant = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'destructive';
      case 'HIGH': return 'destructive';
      case 'MEDIUM': return 'warning';
      case 'LOW': return 'secondary';
      default: return 'outline';
    }
  };

  return (
    <div className="result-data">
      <div className="ioc-summary">
        <div className="summary-cards">
          <div className="summary-card"><span className="count">{summary.iocCount || iocs.length}</span><span className="label">Total IOCs</span></div>
          {Object.entries(typeCounts).map(([type, count]) => (
            <div key={type} className="summary-card"><span className="count">{count}</span><span className="label">{type}</span></div>
          ))}
        </div>
      </div>

      <div className="result-filter">
        <input aria-label="Filter IOCs" placeholder="Filter IOCs…" value={query} onChange={e => { setQuery(e.target.value); setPage(0); }} />
        <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(0); }} aria-label="Filter by type">
          <option value="">All Types</option>
          {types.map(type => <option key={type} value={type}>{type}</option>)}
        </select>
        <select value={severityFilter} onChange={e => { setSeverityFilter(e.target.value); setPage(0); }} aria-label="Filter by severity">
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </div>

      {iocs.length ? (
        <Table columns={columns} rows={filtered.slice(currentPage * pageSize, (currentPage + 1) * pageSize)} />
      ) : (
        <EmptyState title="No IOCs found" message="Run static analysis to extract indicators of compromise." />
      )}

      {pageCount > 1 && (
        <nav className="result-pagination" aria-label="IOC pagination">
          <span>Page {currentPage + 1} of {pageCount} · {pageSize} per page</span>
          <div className="apk-actions">
            <Button variant="secondary" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</Button>
            <Button variant="secondary" disabled={currentPage + 1 === pageCount} onClick={() => setPage(currentPage + 1)}>Next</Button>
          </div>
        </nav>
      )}

      <p className="extracted-note">IOCs are extracted from static analysis. Verify independently before use.</p>
    </div>
  );
}

function ThreatIntelligenceTab({ result }) {
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [page, setPage] = useState(0);
  const [runningCorrelation, setRunningCorrelation] = useState(false);
  const [correlationResult, setCorrelationResult] = useState(null);

  const threatMatches = result.threatMatches || [];
  const iocs = result.iocs || [];

  const typeCounts = useMemo(() => {
    const counts = {};
    threatMatches.forEach(m => { counts[m.threatIntelligence?.indicatorType || 'UNKNOWN'] = (counts[m.threatIntelligence?.indicatorType || 'UNKNOWN'] || 0) + 1; });
    return counts;
  }, [threatMatches]);

  const severityCounts = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    threatMatches.forEach(m => {
      const sev = m.threatIntelligence?.severity;
      if (sev && counts.hasOwnProperty(sev)) counts[sev]++;
    });
    return counts;
  }, [threatMatches]);

  const categories = useMemo(() => [...new Set(threatMatches.map(m => m.threatIntelligence?.category).filter(Boolean))], [threatMatches]);
  const types = useMemo(() => [...new Set(threatMatches.map(m => m.threatIntelligence?.indicatorType).filter(Boolean))], [threatMatches]);

  const filtered = threatMatches.filter(row => {
    const matchesQuery = Object.values(row.threatIntelligence || {}).some(v => String(v ?? '').toLowerCase().includes(query.toLowerCase()));
    const matchesType = !typeFilter || row.threatIntelligence?.indicatorType === typeFilter;
    const matchesSeverity = !severityFilter || row.threatIntelligence?.severity === severityFilter;
    const matchesCategory = !categoryFilter || row.threatIntelligence?.category === categoryFilter;
    return matchesQuery && matchesType && matchesSeverity && matchesCategory;
  });

  const pageSize = 50;
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);

  const columns = [
    { key: 'iocValue', label: 'IOC VALUE', render: row => <code className="wrap-value extracted-text">{row.ioc?.value || 'N/A'}</code> },
    { key: 'iocType', label: 'IOC TYPE', render: row => <Badge variant="outline">{row.ioc?.type || 'N/A'}</Badge> },
    { key: 'threatName', label: 'THREAT NAME', render: row => <strong>{row.threatIntelligence?.threatName || 'Unknown'}</strong> },
    { key: 'threatFamily', label: 'THREAT FAMILY', render: row => <span className="mono">{row.threatIntelligence?.threatFamily || 'N/A'}</span> },
    { key: 'category', label: 'CATEGORY', render: row => <Badge variant="secondary">{row.threatIntelligence?.category || 'N/A'}</Badge> },
    { key: 'severity', label: 'SEVERITY', render: row => <Badge variant={severityVariant(row.threatIntelligence?.severity)}>{row.threatIntelligence?.severity || 'N/A'}</Badge> },
    { key: 'confidence', label: 'CONFIDENCE', render: row => <Badge variant="outline">{row.threatIntelligence?.confidence || 'N/A'}</Badge> },
    { key: 'description', label: 'DESCRIPTION', render: row => <span className="wrap-description">{row.threatIntelligence?.description || 'No description'}</span> },
    { key: 'source', label: 'SOURCE', render: row => <span className="mono">{row.threatIntelligence?.source || 'N/A'}</span> },
    { key: 'matchedAt', label: 'MATCHED AT', render: row => <span className="mono">{row.matchedAt ? new Date(row.matchedAt).toLocaleString() : 'N/A'}</span> },
  ];

  const severityVariant = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'destructive';
      case 'HIGH': return 'destructive';
      case 'MEDIUM': return 'warning';
      case 'LOW': return 'secondary';
      default: return 'outline';
    }
  };

  const handleRunCorrelation = async () => {
    setRunningCorrelation(true);
    try {
      const response = await fetch(`/api/v1/threat-intelligence/correlate/${result.scanId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include'
      });
      if (response.ok) {
        const data = await response.json();
        setCorrelationResult(data);
      }
    } catch (e) {
      console.error('Correlation failed:', e);
    } finally {
      setRunningCorrelation(false);
    }
  };

  return (
    <div className="result-data">
      <div className="malware-summary">
        <div className="summary-cards">
          <div className="summary-card"><span className="count">{threatMatches.length}</span><span className="label">Total Matches</span></div>
          <div className="summary-card critical"><span className="count">{severityCounts.CRITICAL}</span><span className="label">Critical</span></div>
          <div className="summary-card high"><span className="count">{severityCounts.HIGH}</span><span className="label">High</span></div>
          <div className="summary-card medium"><span className="count">{severityCounts.MEDIUM}</span><span className="label">Medium</span></div>
          <div className="summary-card low"><span className="count">{severityCounts.LOW}</span><span className="label">Low</span></div>
          <div className="summary-card"><span className="count">{iocs.length}</span><span className="label">Total IOCs</span></div>
        </div>
      </div>

      <div className="result-filter">
        <input aria-label="Filter threat matches" placeholder="Filter threat matches…" value={query} onChange={e => { setQuery(e.target.value); setPage(0); }} />
        <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(0); }} aria-label="Filter by type">
          <option value="">All Types</option>
          {types.map(type => <option key={type} value={type}>{type}</option>)}
        </select>
        <select value={severityFilter} onChange={e => { setSeverityFilter(e.target.value); setPage(0); }} aria-label="Filter by severity">
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select value={categoryFilter} onChange={e => { setCategoryFilter(e.target.value); setPage(0); }} aria-label="Filter by category">
          <option value="">All Categories</option>
          {categories.map(cat => <option key={cat} value={cat}>{cat}</option>)}
        </select>
        {threatMatches.length === 0 && iocs.length > 0 && !runningCorrelation && (
          <Button onClick={handleRunCorrelation} className="correlate-button">
            <Shield size={14} />Run Threat Intelligence Correlation
          </Button>
        )}
        {runningCorrelation && <Button variant="secondary" disabled><LoaderCircle size={14} className="spin" />Correlating…</Button>}
      </div>

      {correlationResult && (
        <div className="correlation-summary-banner">
          <div className="correlation-stats">
            <span><strong>{correlationResult.matched}</strong> of <strong>{correlationResult.totalIocs}</strong> IOCs matched</span>
            <span>Critical: <strong>{correlationResult.critical}</strong></span>
            <span>High: <strong>{correlationResult.high}</strong></span>
            <span>Medium: <strong>{correlationResult.medium}</strong></span>
            <span>Low: <strong>{correlationResult.low}</strong></span>
            <span>Categories: <strong>{correlationResult.categories?.size || 0}</strong></span>
            <span>Families: <strong>{correlationResult.families?.size || 0}</strong></span>
          </div>
        </div>
      )}

      {threatMatches.length ? (
        <Table columns={columns} rows={filtered.slice(currentPage * pageSize, (currentPage + 1) * pageSize)} />
      ) : iocs.length > 0 ? (
        <EmptyState title="No threat intelligence matches" message="Run Threat Intelligence Correlation to match IOCs against the local threat database." />
      ) : (
        <EmptyState title="No IOCs available" message="Run static analysis to extract indicators of compromise first." />
      )}

      {pageCount > 1 && (
        <nav className="result-pagination" aria-label="Threat matches pagination">
          <span>Page {currentPage + 1} of {pageCount} · {pageSize} per page</span>
          <div className="apk-actions">
            <Button variant="secondary" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</Button>
            <Button variant="secondary" disabled={currentPage + 1 === pageCount} onClick={() => setPage(currentPage + 1)}>Next</Button>
          </div>
        </nav>
      )}

      <p className="extracted-note">Matches are based on exact indicator matching against the local threat intelligence database.</p>
    </div>
  );
}

function RiskCorrelationTab({ result }) {
  const [assessment, setAssessment] = useState(null);
  const [indicators, setIndicators] = useState([]);
  const [breakdown, setBreakdown] = useState(null);
  const [recommendations, setRecommendations] = useState([]);
  const [loading, setLoading] = useState(false);
  const [calculating, setCalculating] = useState(false);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');

  const severityVariant = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'destructive';
      case 'HIGH': return 'destructive';
      case 'MEDIUM': return 'warning';
      case 'LOW': return 'success';
      default: return 'outline';
    }
  };

  const confidenceVariant = (conf) => {
    switch (conf) {
      case 'HIGH': return 'success';
      case 'MEDIUM': return 'warning';
      case 'LOW': return 'secondary';
      default: return 'outline';
    }
  };

  const riskLevelVariant = (level) => {
    switch (level) {
      case 'CRITICAL': return 'destructive';
      case 'HIGH': return 'destructive';
      case 'MEDIUM': return 'warning';
      case 'LOW': return 'success';
      default: return 'outline';
    }
  };

  async function loadAssessment() {
    setLoading(true);
    setError('');
    try {
      const result = await getRiskAssessment(result.scanId);
      setAssessment(result);
      setIndicators(result.indicators || []);
      setBreakdown(result.breakdown);
      setRecommendations(result.recommendations || []);
    } catch (e) {
      if (e.status !== 404) setError(e.message || 'Failed to load risk assessment');
    } finally {
      setLoading(false);
    }
  }

  async function handleCalculate() {
    setCalculating(true);
    setError('');
    try {
      const result = await calculateRisk(result.scanId);
      setAssessment(result);
      setIndicators(result.indicators || []);
      setBreakdown(result.breakdown);
      setRecommendations(result.recommendations || []);
    } catch (e) {
      setError(e.message || 'Failed to calculate risk');
    } finally {
      setCalculating(false);
    }
  }

  useEffect(() => {
    if (result.scanId) {
      loadAssessment();
    }
  }, [result.scanId]);

  const score = assessment?.score ?? 0;
  const riskLevel = assessment?.riskLevel ?? 'LOW';
  const confidence = assessment?.confidence ?? 'LOW';

  const gaugeValue = Math.min(100, Math.max(0, score));

  const breakdownData = useMemo(() => {
    if (!breakdown) return [];
    return [
      { category: 'Threat Intelligence', value: breakdown.threatIntelligence, color: '#fc6a7e' },
      { category: 'Static Findings', value: breakdown.staticFindings, color: '#f2b45c' },
      { category: 'API Calls', value: breakdown.apiCalls, color: '#5d9bf5' },
      { category: 'Permissions', value: breakdown.permissions, color: '#b397ee' },
      { category: 'IOCs', value: breakdown.iocs, color: '#39d0b7' },
      { category: 'URLs', value: breakdown.urls, color: '#f7c94d' },
      { category: 'Components', value: breakdown.components, color: '#7dd3fc' },
      { category: 'Obfuscation/Native', value: breakdown.obfuscationNative, color: '#c4b5fd' },
    ].filter(d => d.value > 0);
  }, [breakdown]);

  const indicatorColumns = [
    { key: 'category', label: 'CATEGORY', render: r => <Badge variant="outline">{r.category}</Badge> },
    { key: 'description', label: 'DESCRIPTION', render: r => <span className="wrap-description">{r.description}</span> },
    { key: 'severity', label: 'SEVERITY', render: r => <Badge variant={severityVariant(r.severity)}>{r.severity}</Badge> },
    { key: 'confidence', label: 'CONFIDENCE', render: r => <Badge variant={confidenceVariant(r.confidence)}>{r.confidence}</Badge> },
    { key: 'contribution', label: 'CONTRIBUTION', render: r => <strong>+{r.contribution.toFixed(1)}</strong> },
    { key: 'evidence', label: 'EVIDENCE', render: r => <code className="wrap-value extracted-text">{r.evidence}</code> },
  ];

  const filteredIndicators = indicators.filter(row =>
    Object.values(row).some(v => String(v ?? '').toLowerCase().includes(query.toLowerCase()))
  );

  if (!result.scanId) {
    return (
      <div className="result-data">
        <EmptyState title="No scan selected" message="Select an APK scan to analyze its risk profile." />
      </div>
    );
  }

  return (
    <div className="result-data">
      {assessment?.analysisMode === 'MOCK' && (
        <div className="sample-banner">
          <ShieldCheck size={15} />
          <strong>Mock Analysis Mode</strong>
          <span>Risk score is based on deterministic sample findings, not real malware intelligence.</span>
          <Badge tone="amber">DEMO DATA</Badge>
        </div>
      )}

      {error && assessment && <div className="form-error" role="alert">{error}</div>}

      <div className="module-grid">
        <div className="padded-card">
          <div className="panel-heading">
            <h2>Risk Score</h2>
          </div>
          <div className="risk-gauge-container">
            <div className="risk-gauge">
              <svg viewBox="0 0 200 200" className="gauge-svg">
                <circle className="gauge-bg" cx="100" cy="100" r="80" />
                <circle
                  className="gauge-progress"
                  cx="100"
                  cy="100"
                  r="80"
                  strokeDasharray="502.65"
                  strokeDashoffset={502.65 - (gaugeValue / 100) * 502.65}
                  style={{ stroke: getRiskColor(riskLevel) }}
                />
                <circle className="gauge-center" cx="100" cy="100" r="55" fill="#0a101c" />
              </svg>
              <div className="gauge-value">
                <span className="score">{gaugeValue.toFixed(1)}</span>
                <span className="max">/ 100</span>
              </div>
            </div>
            <div className="gauge-meta">
              <div className="meta-item">
                <span className="meta-label">Risk Level</span>
                <Badge variant={riskLevelVariant(riskLevel)} className="risk-level-badge">{riskLevel}</Badge>
              </div>
              <div className="meta-item">
                <span className="meta-label">Confidence</span>
                <Badge variant={confidenceVariant(confidence)}>{confidence}</Badge>
              </div>
              <div className="meta-item">
                <span className="meta-label">Assessed</span>
                <span>{assessment.createdAt ? new Date(assessment.createdAt).toLocaleString() : 'N/A'}</span>
              </div>
            </div>
          </div>
          <div className="gauge-actions">
            <Button onClick={handleCalculate} disabled={calculating}>
              {calculating ? <LoaderCircle className="spin" size={16} /> : <Gauge size={16} />}
              {calculating ? 'Calculating...' : 'Calculate Risk'}
            </Button>
          </div>
        </div>

        <div className="padded-card">
          <div className="panel-heading"><h2>Risk Summary</h2></div>
          <div className="risk-summary">
            <p>{assessment?.summary || 'No risk assessment available. Click "Calculate Risk" to generate an assessment.'}</p>
          </div>
        </div>
      </div>

      <div className="module-grid">
        <div className="padded-card">
          <div className="panel-heading"><h2>Risk Breakdown</h2><p>Contribution by evidence category</p></div>
          <div className="breakdown-chart">
            {breakdownData.length ? (
              <div className="breakdown-bars">
                {breakdownData.map((item, i) => (
                  <div key={item.category} className="breakdown-bar">
                    <div className="bar-header">
                      <span className="bar-label">{item.category}</span>
                      <span className="bar-value">+{item.value.toFixed(1)}</span>
                    </div>
                    <div className="bar-track">
                      <div
                        className="bar-fill"
                        style={{
                          width: `${(item.value / (breakdown?.total || 100)) * 100}%`,
                          backgroundColor: item.color
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState title="No breakdown available" message="Calculate risk to see category contributions." />
            )}
          </div>
        </div>

        <div className="padded-card">
          <div className="panel-heading"><h2>Recommendations</h2><p>Actionable guidance based on findings</p></div>
          {recommendations.length ? (
            <ul className="recommendations-list">
              {recommendations.map((rec, i) => (
                <li key={i} className="recommendation-item">
                  <Badge variant="outline">{rec.category}</Badge>
                  <p>{rec.recommendation}</p>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="No recommendations" message="Calculate risk to generate security recommendations." />
          )}
        </div>
      </div>

      <div className="padded-card">
        <div className="panel-heading">
          <h2>Contributing Indicators</h2>
          <p>{indicators.length} evidence items contributing to the risk score</p>
        </div>
        <div className="result-filter">
          <input aria-label="Filter indicators" placeholder="Filter indicators…" value={query} onChange={e => setQuery(e.target.value)} />
        </div>
        {indicators.length ? (
          <Table columns={indicatorColumns} rows={filteredIndicators} />
        ) : (
          <EmptyState title="No indicators" message="Calculate risk to see contributing evidence." />
        )}
      </div>

      <div className="correlation-flow">
        <h3>Correlation Flow</h3>
        <div className="flow-steps">
          <div className="flow-step"><span>1</span><p>Permissions</p></div>
          <div className="flow-arrow">→</div>
          <div className="flow-step"><span>2</span><p>API Findings</p></div>
          <div className="flow-arrow">→</div>
          <div className="flow-step"><span>3</span><p>Static Findings</p></div>
          <div className="flow-arrow">→</div>
          <div className="flow-step"><span>4</span><p>IOCs</p></div>
          <div className="flow-arrow">→</div>
          <div className="flow-step"><span>5</span><p>Threat Intel</p></div>
          <div className="flow-arrow">→</div>
          <div className="flow-step"><span>6</span><p>Evidence Correlation</p></div>
          <div className="flow-arrow">→</div>
          <div className="flow-step"><span>7</span><p>Weighted Scoring</p></div>
          <div className="flow-arrow">→</div>
          <div className="flow-step final"><span>8</span><p>Risk Score</p></div>
        </div>
      </div>
    </div>
  );
}

function getRiskColor(level) {
  switch (level) {
    case 'CRITICAL': return '#fc6a7e';
    case 'HIGH': return '#f2b45c';
    case 'MEDIUM': return '#5d9bf5';
    case 'LOW': return '#39d0b7';
    default: return '#39d0b7';
  }
}
