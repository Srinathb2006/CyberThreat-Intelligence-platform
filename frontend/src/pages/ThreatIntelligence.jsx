import { useEffect, useState, useMemo } from 'react';
import { Search, Filter, Download, Upload, Shield, AlertCircle, Target, Link2, RefreshCw, ChevronDown, Plus } from 'lucide-react';
import { Card, Badge, Button, Table, Loading, ErrorState, EmptyState, Modal } from '../components/ui';
import { getThreatIntelligence, searchThreatIntelligence, getThreatIntelligenceSources, importThreatIntelligence, exportThreatIntelligence } from '../api/scanApi';

const severityVariant = (sev) => {
  switch (sev) {
    case 'CRITICAL': return 'destructive';
    case 'HIGH': return 'destructive';
    case 'MEDIUM': return 'warning';
    case 'LOW': return 'secondary';
    default: return 'outline';
  }
};

const columns = [
  { key: 'indicator', label: 'INDICATOR', render: row => <code className="wrap-value extracted-text">{row.indicator}</code> },
  { key: 'indicatorType', label: 'TYPE', render: row => <Badge variant="outline">{row.indicatorType}</Badge> },
  { key: 'threatName', label: 'THREAT NAME', render: row => <strong>{row.threatName || 'Unknown'}</strong> },
  { key: 'threatFamily', label: 'THREAT FAMILY', render: row => <span className="mono">{row.threatFamily || 'N/A'}</span> },
  { key: 'category', label: 'CATEGORY', render: row => <Badge variant="secondary">{row.category || 'N/A'}</Badge> },
  { key: 'severity', label: 'SEVERITY', render: row => <Badge variant={severityVariant(row.severity)}>{row.severity}</Badge> },
  { key: 'confidence', label: 'CONFIDENCE', render: row => <Badge variant="outline">{row.confidence}</Badge> },
  { key: 'description', label: 'DESCRIPTION', render: row => <span className="wrap-description">{row.description || 'No description'}</span> },
  { key: 'source', label: 'SOURCE', render: row => <span className="mono">{row.source || 'N/A'}</span> },
  { key: 'firstSeen', label: 'FIRST SEEN', render: row => <span className="mono">{row.firstSeen ? new Date(row.firstSeen).toLocaleDateString() : 'N/A'}</span> },
  { key: 'lastSeen', label: 'LAST SEEN', render: row => <span className="mono">{row.lastSeen ? new Date(row.lastSeen).toLocaleDateString() : 'N/A'}</span> },
];

export default function ThreatIntelligencePage() {
  const [data, setData] = useState([]);
  const [sources, setSources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [page, setPage] = useState(0);
  const [pageSize] = useState(50);
  const [importModalOpen, setImportModalOpen] = useState(false);
  const [importFile, setImportFile] = useState(null);
  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState(null);
  const [selectedItem, setSelectedItem] = useState(null);

  useEffect(() => {
    loadData();
    loadSources();
  }, []);

  async function loadData() {
    setLoading(true);
    setError('');
    try {
      const result = await getThreatIntelligence({
        type: typeFilter || undefined,
        severity: severityFilter || undefined,
        category: categoryFilter || undefined,
        source: sourceFilter || undefined
      });
      setData(result);
    } catch (e) {
      setError(e.message || 'Failed to load threat intelligence');
    } finally {
      setLoading(false);
    }
  }

  async function loadSources() {
    try {
      const result = await getThreatIntelligenceSources();
      setSources(result);
    } catch (e) {
      console.error('Failed to load sources:', e);
    }
  }

  const handleSearch = async () => {
    if (!query.trim()) {
      loadData();
      return;
    }
    setLoading(true);
    setError('');
    try {
      const result = await searchThreatIntelligence(query.trim());
      setData(result);
    } catch (e) {
      setError(e.message || 'Search failed');
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async () => {
    try {
      const blob = await exportThreatIntelligence();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `threat-intelligence-export-${new Date().toISOString().split('T')[0]}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e.message || 'Export failed');
    }
  };

  const handleImport = async () => {
    if (!importFile) return;
    setImporting(true);
    try {
      const result = await importThreatIntelligence(importFile);
      setImportResult(result);
      setImportFile(null);
      setImportModalOpen(false);
      loadData();
    } catch (e) {
      setImportResult({ imported: 0, errors: 1, errorDetails: [e.message || 'Import failed'] });
    } finally {
      setImporting(false);
    }
  };

  const filteredData = useMemo(() => {
    return data.filter(row => {
      const matchesQuery = !query || Object.values(row).some(v => String(v ?? '').toLowerCase().includes(query.toLowerCase()));
      const matchesType = !typeFilter || row.indicatorType === typeFilter;
      const matchesSeverity = !severityFilter || row.severity === severityFilter;
      const matchesCategory = !categoryFilter || row.category === categoryFilter;
      const matchesSource = !sourceFilter || row.source === sourceFilter;
      return matchesQuery && matchesType && matchesSeverity && matchesCategory && matchesSource;
    });
  }, [data, query, typeFilter, severityFilter, categoryFilter, sourceFilter]);

  const types = useMemo(() => [...new Set(data.map(d => d.indicatorType).filter(Boolean))], [data]);
  const categories = useMemo(() => [...new Set(data.map(d => d.category).filter(Boolean))], [data]);
  const sourceNames = useMemo(() => [...new Set(data.map(d => d.source).filter(Boolean))], [data]);

  const severityCounts = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    data.forEach(d => {
      if (counts.hasOwnProperty(d.severity)) counts[d.severity]++;
    });
    return counts;
  }, [data]);

  const typeCounts = useMemo(() => {
    const counts = {};
    data.forEach(d => { counts[d.indicatorType] = (counts[d.indicatorType] || 0) + 1; });
    return counts;
  }, [data]);

  const pageCount = Math.max(1, Math.ceil(filteredData.length / pageSize));
  const currentPage = Math.min(page, pageCount - 1);
  const paginatedData = filteredData.slice(currentPage * pageSize, (currentPage + 1) * pageSize);

  if (loading) return <Loading />;
  if (error) return <ErrorState message={error} retry={loadData} />;

  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">INTELLIGENCE</div>
          <h1>Threat Intelligence<span className="title-dot">.</span></h1>
          <p>Local threat intelligence database. Search, correlate, and manage indicators of compromise.</p>
        </div>
        <span className="page-icon"><Shield size={27} /></span>
      </div>

      <div className="stats-grid">
        <Card className="stat-card"><div className="stat-label">Total Indicators<span className="stat-icon"><Target size={18} /></span></div><div className="stat-value">{data.length}</div><div className="stat-bottom"><span className="stat-change">Active records</span></div></Card>
        <Card className="stat-card critical"><div className="stat-label">Critical<span className="stat-icon"><AlertCircle size={18} /></span></div><div className="stat-value">{severityCounts.CRITICAL}</div><div className="stat-bottom"><span className="stat-change">Immediate action required</span></div></Card>
        <Card className="stat-card warning"><div className="stat-label">High<span className="stat-icon"><AlertCircle size={18} /></span></div><div className="stat-value">{severityCounts.HIGH}</div><div className="stat-bottom"><span className="stat-change">Elevated risk</span></div></Card>
        <Card className="stat-card"><div className="stat-label">Medium<span className="stat-icon"><AlertCircle size={18} /></span></div><div className="stat-value">{severityCounts.MEDIUM}</div><div className="stat-bottom"><span className="stat-change">Review recommended</span></div></Card>
        <Card className="stat-card"><div className="stat-label">Low<span className="stat-icon"><AlertCircle size={18} /></span></div><div className="stat-value">{severityCounts.LOW}</div><div className="stat-bottom"><span className="stat-change">Informational</span></div></Card>
        <Card className="stat-card"><div className="stat-label">Types<span className="stat-icon"><Link2 size={18} /></span></div><div className="stat-value">{Object.keys(typeCounts).length}</div><div className="stat-bottom"><span className="stat-change">Indicator categories</span></div></Card>
      </div>

      <div className="module-grid">
        <Card className="padded">
          <div className="panel-heading">
            <div><h2>Threat Intelligence Database</h2><p>{data.length} indicators · {filteredData.length} filtered</p></div>
            <div className="heading-actions">
              <Button variant="secondary" onClick={handleExport}><Download size={16} />Export CSV</Button>
              <Button onClick={() => setImportModalOpen(true)}><Upload size={16} />Import CSV</Button>
            </div>
          </div>

          <div className="filterbar">
            <div className="filter-input" style={{ flex: 1 }}>
              <Search size={16} />
              <input
                aria-label="Search indicators"
                placeholder="Search indicators, threat names, families…"
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSearch()}
              />
            </div>
            <Button onClick={handleSearch}><Search size={14} />Search</Button>
            <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(0); }} aria-label="Filter by type">
              <option value="">All Types</option>
              {types.map(t => <option key={t} value={t}>{t} ({typeCounts[t]})</option>)}
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
              {categories.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
            <select value={sourceFilter} onChange={e => { setSourceFilter(e.target.value); setPage(0); }} aria-label="Filter by source">
              <option value="">All Sources</option>
              {sourceNames.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>

          {data.length ? (
            <Table columns={columns} rows={paginatedData} onRowClick={setSelectedItem} />
          ) : (
            <EmptyState title="No threat intelligence loaded" message="Import a CSV file or add indicators manually to build your local threat database." />
          )}

          {pageCount > 1 && (
            <nav className="result-pagination" aria-label="Threat intelligence pagination">
              <span>Page {currentPage + 1} of {pageCount} · {pageSize} per page</span>
              <div className="apk-actions">
                <Button variant="secondary" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</Button>
                <Button variant="secondary" disabled={currentPage + 1 === pageCount} onClick={() => setPage(currentPage + 1)}>Next</Button>
              </div>
            </nav>
          )}
        </Card>

        <Card className="padded">
          <div className="panel-heading"><h2>Type Distribution</h2></div>
          <div className="type-distribution">
            {Object.entries(typeCounts).map(([type, count]) => (
              <div key={type} className="type-bar">
                <span className="type-label">{type}</span>
                <div className="type-bar-track"><div className="type-bar-fill" style={{ width: `${(count / data.length) * 100}%` }} /></div>
                <span className="type-count">{count}</span>
              </div>
            ))}
          </div>
        </Card>

        <Card className="padded">
          <div className="panel-heading"><h2>Configured Sources</h2></div>
          {sources.length ? (
            <Table columns={[
              { key: 'name', label: 'NAME', render: r => <strong>{r.name}</strong> },
              { key: 'sourceType', label: 'TYPE' },
              { key: 'url', label: 'URL', render: r => <span className="mono">{r.url || 'N/A'}</span> },
              { key: 'enabled', label: 'STATUS', render: r => <Badge variant={r.enabled ? 'success' : 'secondary'}>{r.enabled ? 'Enabled' : 'Disabled'}</Badge> },
            ]} rows={sources} />
          ) : (
            <EmptyState title="No sources configured" message="Add threat intelligence sources to track where indicators originate." />
          )}
        </Card>
      </div>

      {importModalOpen && (
        <Modal title="Import Threat Intelligence CSV" onClose={() => { setImportModalOpen(false); setImportFile(null); setImportResult(null); }}>
          <div className="modal-body">
            <p>Upload a CSV file with the following columns:</p>
            <pre className="csv-format">
indicator,indicatorType,threatName,threatFamily,category,severity,confidence,description,source,tags
            </pre>
            <p className="small muted">Valid types: URL, DOMAIN, IP, HASH, PACKAGE, API, STRING</p>
            <p className="small muted">Valid severities: LOW, MEDIUM, HIGH, CRITICAL</p>
            <p className="small muted">Valid confidence: LOW, MEDIUM, HIGH</p>
            <input type="file" accept=".csv" onChange={e => setImportFile(e.target.files[0])} />
            {importResult && (
              <div className={`import-result ${importResult.errors > 0 ? 'has-errors' : ''}`}>
                <h4>Import Result</h4>
                <p>Imported: <strong>{importResult.imported}</strong></p>
                <p>Errors: <strong>{importResult.errors}</strong></p>
                {importResult.errorDetails && importResult.errorDetails.length > 0 && (
                  <details><summary>Error Details</summary><ul>{importResult.errorDetails.map((e, i) => <li key={i}>{e}</li>)}</ul></details>
                )}
              </div>
            )}
          </div>
          <div className="modal-actions">
            <Button variant="secondary" onClick={() => { setImportModalOpen(false); setImportFile(null); setImportResult(null); }}>Cancel</Button>
            <Button disabled={!importFile || importing} onClick={handleImport}>
              {importing ? <RefreshCw size={14} className="spin" /> : ''}Import
            </Button>
          </div>
        </Modal>
      )}

      {selectedItem && (
        <Modal title={`Indicator: ${selectedItem.indicator}`} onClose={() => setSelectedItem(null)}>
          <div className="modal-body detail-view">
            <div className="detail-line"><span>Type</span><Badge variant="outline">{selectedItem.indicatorType}</Badge></div>
            <div className="detail-line"><span>Threat Name</span><strong>{selectedItem.threatName || 'Unknown'}</strong></div>
            <div className="detail-line"><span>Threat Family</span><span className="mono">{selectedItem.threatFamily || 'N/A'}</span></div>
            <div className="detail-line"><span>Category</span><Badge variant="secondary">{selectedItem.category || 'N/A'}</Badge></div>
            <div className="detail-line"><span>Severity</span><Badge variant={severityVariant(selectedItem.severity)}>{selectedItem.severity}</Badge></div>
            <div className="detail-line"><span>Confidence</span><Badge variant="outline">{selectedItem.confidence}</Badge></div>
            <div className="detail-line"><span>Source</span><span className="mono">{selectedItem.source || 'N/A'}</span></div>
            <div className="detail-line"><span>First Seen</span>{selectedItem.firstSeen ? new Date(selectedItem.firstSeen).toLocaleString() : 'N/A'}</div>
            <div className="detail-line"><span>Last Seen</span>{selectedItem.lastSeen ? new Date(selectedItem.lastSeen).toLocaleString() : 'N/A'}</div>
            <div className="detail-line"><span>Tags</span><span className="mono">{selectedItem.tags || 'None'}</span></div>
            <div className="detail-section">
              <h4>Description</h4>
              <p>{selectedItem.description || 'No description provided'}</p>
            </div>
          </div>
        </Modal>
      )}
    </>
  );
}