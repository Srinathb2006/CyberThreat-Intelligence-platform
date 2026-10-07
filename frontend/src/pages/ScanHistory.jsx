import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { History, Search, RefreshCw, FileText, Download, ShieldAlert, CheckCircle, ArrowUpRight, ExternalLink } from 'lucide-react';
import { Card, Badge, Button, Table, Loading, ErrorState } from '../components/ui';
import { getScanHistory } from '../api/scanHistoryApi';
import { downloadReport } from '../api/reportApi';

export default function ScanHistoryPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [packageName, setPackageName] = useState('');
  const [status, setStatus] = useState('All');
  const [riskLevel, setRiskLevel] = useState('All');
  const [downloading, setDownloading] = useState(null);

  async function loadData() {
    setLoading(true);
    setError('');
    try {
      const data = await getScanHistory({ search, packageName, status, riskLevel });
      setScans(data);
    } catch (e) {
      setError(e.response?.data?.message || e.message || 'Failed to load scan history');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, [status, riskLevel]);

  function handleFilter(e) {
    e.preventDefault();
    loadData();
  }

  async function handleDownload(scanId, format) {
    setDownloading(`${scanId}-${format}`);
    try {
      await downloadReport(scanId, format);
    } catch (e) {
      alert('Download failed: ' + (e.response?.data?.message || e.message));
    } finally {
      setDownloading(null);
    }
  }

  const columns = [
    {
      key: 'target',
      label: 'TARGET / APPLICATION',
      render: r => (
        <div>
          <strong>{r.applicationName || r.target}</strong>
          <small className="mono" style={{ display: 'block' }}>{r.packageName || 'Package unknown'}</small>
        </div>
      )
    },
    {
      key: 'sha256',
      label: 'SHA-256',
      render: r => (
        <span className="mono" title={r.sha256} style={{ fontSize: '11px', color: '#9bb1d0' }}>
          {r.sha256 ? `${r.sha256.substring(0, 16)}...` : 'N/A'}
        </span>
      )
    },
    {
      key: 'riskScore',
      label: 'RISK SCORE & LEVEL',
      render: r => (
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <strong style={{ fontSize: '14px' }}>{r.riskScore != null ? `${r.riskScore}/100` : '—'}</strong>
          <Badge tone={r.riskLevel === 'CRITICAL' ? 'red' : r.riskLevel === 'HIGH' ? 'amber' : r.riskLevel === 'MEDIUM' ? 'blue' : 'teal'}>
            {r.riskLevel || 'UNKNOWN'}
          </Badge>
        </div>
      )
    },
    {
      key: 'findingsCount',
      label: 'FINDINGS',
      render: r => <span className="mono">{r.findingsCount} findings</span>
    },
    {
      key: 'iocCount',
      label: 'IOCS / MATCHES',
      render: r => (
        <span className="mono">
          {r.iocCount} IOCs {r.threatMatchCount > 0 ? `(${r.threatMatchCount} matched)` : ''}
        </span>
      )
    },
    {
      key: 'status',
      label: 'STATUS',
      render: r => (
        <Badge tone={r.status === 'COMPLETED' ? 'teal' : r.status === 'RUNNING' ? 'blue' : r.status === 'FAILED' ? 'red' : 'neutral'}>
          {r.status}
        </Badge>
      )
    },
    {
      key: 'createdAt',
      label: 'SCAN DATE',
      render: r => <span className="mono">{r.createdAt ? new Date(r.createdAt).toLocaleDateString() : 'N/A'}</span>
    },
    {
      key: 'actions',
      label: 'ACTIONS & REPORTS',
      render: r => (
        <div style={{ display: 'flex', gap: '6px' }}>
          <button
            className="button small secondary"
            title="Download PDF Report"
            onClick={() => handleDownload(r.id, 'pdf')}
            disabled={downloading === `${r.id}-pdf`}
          >
            <Download size={13} /> PDF
          </button>
          <button
            className="button small secondary"
            title="Download JSON Export"
            onClick={() => handleDownload(r.id, 'json')}
            disabled={downloading === `${r.id}-json`}
          >
            JSON
          </button>
        </div>
      )
    }
  ];

  return (
    <div className="scan-history-container">
      <Card className="padded">
        <div className="panel-heading" style={{ marginBottom: '16px' }}>
          <div>
            <h2>Investigation & Scan History</h2>
            <p>Complete historical log of APK analyses, threat intelligence correlations, and security verdicts.</p>
          </div>
          <Button variant="secondary" onClick={loadData} disabled={loading}>
            <RefreshCw size={15} /> Refresh
          </Button>
        </div>

        <form onSubmit={handleFilter} className="filterbar" style={{ display: 'flex', gap: '10px', marginBottom: '16px', flexWrap: 'wrap' }}>
          <div className="filter-input" style={{ flex: 1, minWidth: '220px' }}>
            <Search size={16} />
            <input
              placeholder="Search filename, target, or SHA-256..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <input
            placeholder="Filter by package (e.g. com.bank)..."
            value={packageName}
            onChange={e => setPackageName(e.target.value)}
            style={{ padding: '8px 12px', background: '#101726', border: '1px solid #273852', borderRadius: '6px', color: '#fff', minWidth: '180px' }}
          />
          <select value={riskLevel} onChange={e => setRiskLevel(e.target.value)}>
            <option value="All">All Risk Levels</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select value={status} onChange={e => setStatus(e.target.value)}>
            <option value="All">All Statuses</option>
            <option value="COMPLETED">Completed</option>
            <option value="RUNNING">Running</option>
            <option value="PENDING">Pending</option>
            <option value="FAILED">Failed</option>
          </select>
          <Button type="submit">Filter</Button>
        </form>

        {error && <ErrorState message={error} retry={loadData} />}
        {loading ? <Loading /> : <Table columns={columns} rows={scans} />}
      </Card>
    </div>
  );
}
