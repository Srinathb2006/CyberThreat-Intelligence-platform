import { useEffect, useMemo, useState } from 'react';
import { Fingerprint, RefreshCw, RotateCcw, Search } from 'lucide-react';
import { Badge, Button, Card, EmptyState, ErrorState, Loading, Modal, Table } from '../components/ui';
import { getIocDetails, searchIocs } from '../api/iocExplorerApi';
import { matchState, PAGE_SIZE, pageRows } from '../utils/iocExplorer';

const text = value => value == null || value === '' ? '—' : String(value);
const dateTime = value => value ? new Date(value).toLocaleString() : '—';
const badge = value => <Badge tone={String(value || 'neutral').toLowerCase()}>{text(value)}</Badge>;

function ThreatMatches({ matches = [] }) {
  if (!matches.length) return <p className="ioc-muted">No stored threat-intelligence correlation exists for this IOC.</p>;
  return <div className="ioc-match-list">{matches.map((match, index) => <article className="ioc-match" key={match.id ?? index}>
    <div className="ioc-match-heading"><Badge tone={String(match.status || 'neutral').toLowerCase()}>{text(match.status)}</Badge>{badge(match.matchType)}{badge(match.severity)}{badge(match.confidence)}</div>
    <dl className="ioc-match-facts">
      <div><dt>Matched</dt><dd>{dateTime(match.matchedAt)}</dd></div>
      <div><dt>Threat</dt><dd>{text(match.threatName)}</dd></div>
      <div><dt>Family</dt><dd>{text(match.threatFamily)}</dd></div>
      <div><dt>Category</dt><dd>{text(match.threatCategory)}</dd></div>
      <div><dt>Intelligence indicator</dt><dd className="mono">{text(match.threatIndicator)}</dd></div>
      <div><dt>Source</dt><dd>{text(match.threatSource)}</dd></div>
    </dl>
    {match.description && <p className="ioc-match-description">{match.description}</p>}
  </article>)}</div>;
}

function IocDetail({ ioc, onClose }) {
  return <Modal title="IOC evidence" onClose={onClose}><div className="modal-body ioc-detail">
    <dl className="ioc-detail-facts">
      <div className="ioc-full"><dt>Indicator</dt><dd className="mono">{text(ioc.value)}</dd></div>
      <div><dt>Type</dt><dd>{badge(ioc.type)}</dd></div><div><dt>Severity</dt><dd>{badge(ioc.severity)}</dd></div><div><dt>Confidence</dt><dd>{badge(ioc.confidence)}</dd></div>
      <div><dt>Scan</dt><dd>{ioc.scanId == null ? '—' : `#${ioc.scanId}`}</dd></div><div className="ioc-full"><dt>Scan target</dt><dd className="mono">{text(ioc.scanTarget)}</dd></div>
      <div><dt>Source</dt><dd>{text(ioc.source)}</dd></div><div><dt>First seen</dt><dd>{dateTime(ioc.firstSeen)}</dd></div><div><dt>Last seen</dt><dd>{dateTime(ioc.lastSeen)}</dd></div>
      {ioc.description && <div className="ioc-full"><dt>Extraction note</dt><dd>{ioc.description}</dd></div>}
    </dl>
    <section className="ioc-detail-section"><h3>Threat-intelligence matches</h3><ThreatMatches matches={ioc.threatMatches} /></section>
  </div></Modal>;
}

export default function IocExplorer() {
  const [draft, setDraft] = useState({ search: '', type: '', severity: '', confidence: '', scanId: '' });
  const [filters, setFilters] = useState(draft);
  const [rows, setRows] = useState([]); const [loading, setLoading] = useState(true); const [error, setError] = useState('');
  const [page, setPage] = useState(0); const [selected, setSelected] = useState(null); const [detailLoading, setDetailLoading] = useState(false);
  const load = async (nextFilters = filters) => { setLoading(true); setError(''); try { setRows(await searchIocs(nextFilters)); setPage(0); } catch (cause) { setError(cause.response?.data?.message || cause.message || 'The IOC database could not be loaded.'); } finally { setLoading(false); } };
  useEffect(() => {
    let active = true;
    async function initialLoad() {
      setLoading(true); setError('');
      try { const initialRows = await searchIocs({}); if (active) setRows(initialRows); }
      catch (cause) { if (active) setError(cause.response?.data?.message || cause.message || 'The IOC database could not be loaded.'); }
      finally { if (active) setLoading(false); }
    }
    initialLoad();
    return () => { active = false; };
  }, []);
  const types = useMemo(() => [...new Set(rows.map(row => row.type).filter(Boolean))].sort(), [rows]);
  const scanIds = useMemo(() => [...new Set(rows.map(row => row.scanId).filter(value => value != null))].sort((a, b) => b - a), [rows]);
  const visible = pageRows(rows, page); const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const openDetail = async row => { setDetailLoading(true); try { setSelected(await getIocDetails(row.id)); } catch (cause) { setError(cause.response?.data?.message || 'The IOC details could not be loaded.'); } finally { setDetailLoading(false); } };
  const reset = () => { const empty = { search: '', type: '', severity: '', confidence: '', scanId: '' }; setDraft(empty); setFilters(empty); load(empty); };
  const columns = [
    { key: 'value', label: 'IOC', render: row => <code className="ioc-value">{text(row.value)}</code> },
    { key: 'type', label: 'TYPE', render: row => badge(row.type) },
    { key: 'severity', label: 'SEVERITY', render: row => badge(row.severity) },
    { key: 'confidence', label: 'CONFIDENCE', render: row => badge(row.confidence) },
    { key: 'scan', label: 'SCAN', render: row => <span className="ioc-scan">#{text(row.scanId)} <small>{text(row.scanTarget)}</small></span> },
    { key: 'match', label: 'INTELLIGENCE MATCH', render: row => { const state = matchState(row.threatMatches); return <span className="ioc-state"><Badge tone={state.tone}>{state.label}</Badge>{state.match?.threatName && <small>{state.match.threatName}</small>}</span>; } },
  ];
  if (loading) return <Loading />;
  if (error && !rows.length) return <ErrorState message={error} retry={() => load()} />;
  return <>
    <div className="page-heading"><div><div className="eyebrow">PERSISTED APK EVIDENCE</div><h1>IOC Explorer<span className="title-dot">.</span></h1><p>Search extracted indicators and the threat-intelligence correlations recorded with them.</p></div><span className="page-icon"><Fingerprint size={27} /></span></div>
    <Card className="ioc-explorer-panel"><div className="panel-heading"><div><h2>Indicator evidence</h2><p>{rows.length} result{rows.length === 1 ? '' : 's'} from your scans</p></div><Button variant="secondary" onClick={() => load()} disabled={loading}><RefreshCw size={15} className={loading ? 'spin' : ''} />Refresh</Button></div>
      <form className="filterbar ioc-filterbar" onSubmit={event => { event.preventDefault(); setFilters(draft); load(draft); }}>
        <label className="filter-input"><Search size={16} /><span className="sr-only">Search IOCs</span><input value={draft.search} onChange={event => setDraft({ ...draft, search: event.target.value })} placeholder="Search indicator, source, description…" /></label>
        <select aria-label="Filter by IOC type" value={draft.type} onChange={event => setDraft({ ...draft, type: event.target.value })}><option value="">All types</option>{types.map(value => <option key={value}>{value}</option>)}</select>
        <select aria-label="Filter by severity" value={draft.severity} onChange={event => setDraft({ ...draft, severity: event.target.value })}><option value="">All severities</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(value => <option key={value}>{value}</option>)}</select>
        <select aria-label="Filter by confidence" value={draft.confidence} onChange={event => setDraft({ ...draft, confidence: event.target.value })}><option value="">All confidence</option>{['HIGH', 'MEDIUM', 'LOW'].map(value => <option key={value}>{value}</option>)}</select>
        <select aria-label="Filter by scan" value={draft.scanId} onChange={event => setDraft({ ...draft, scanId: event.target.value })}><option value="">All scans</option>{scanIds.map(value => <option key={value} value={value}>Scan #{value}</option>)}</select>
        <Button type="submit"><Search size={15} />Search</Button><Button type="button" variant="secondary" onClick={reset}><RotateCcw size={14} />Reset</Button>
      </form>
      {error && <p className="form-error">{error}</p>}
      {rows.length ? <><Table columns={columns} rows={visible} onRowClick={openDetail} /><nav className="result-pagination" aria-label="IOC result pagination"><span>Page {page + 1} of {pages} · {rows.length} total</span><div className="apk-actions"><Button variant="secondary" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</Button><Button variant="secondary" disabled={page + 1 === pages} onClick={() => setPage(page + 1)}>Next</Button></div></nav></> : <EmptyState title="No IOC evidence found" message="No stored indicators match these filters. Try clearing the filters or analyse an APK first." />}
    </Card>
    {detailLoading && <div className="ioc-detail-loading" role="status">Loading IOC details…</div>}{selected && <IocDetail ioc={selected} onClose={() => setSelected(null)} />}
  </>;
}
