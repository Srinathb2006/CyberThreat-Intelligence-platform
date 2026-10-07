import { useEffect, useState } from 'react';
import { Bell, ShieldAlert, CheckCircle, Search, RefreshCw, AlertTriangle, Eye, Shield, Check, ArrowUpRight } from 'lucide-react';
import { Card, Badge, Button, Table, Loading, ErrorState, Modal } from '../components/ui';
import { getAlerts, getAlertStats, updateAlertStatus, resolveAlert } from '../api/alertApi';

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('All');
  const [severity, setSeverity] = useState('All');
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [updating, setUpdating] = useState(false);
  const [resolveNotes, setResolveNotes] = useState('');

  async function loadData() {
    setLoading(true);
    setError('');
    try {
      const [alertsData, statsData] = await Promise.all([
        getAlerts({ status, severity, search }),
        getAlertStats(),
      ]);
      setAlerts(alertsData);
      setStats(statsData);
    } catch (e) {
      setError(e.response?.data?.message || e.message || 'Failed to load alerts');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, [status, severity]);

  function handleSearch(e) {
    e.preventDefault();
    loadData();
  }

  async function handleStatusChange(alertId, newStatus) {
    setUpdating(true);
    try {
      await updateAlertStatus(alertId, { status: newStatus });
      await loadData();
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert(prev => ({ ...prev, status: newStatus }));
      }
    } catch (e) {
      alert('Failed to update status: ' + (e.response?.data?.message || e.message));
    } finally {
      setUpdating(false);
    }
  }

  async function handleResolve(alertId) {
    setUpdating(true);
    try {
      await resolveAlert(alertId, { notes: resolveNotes, resolvedBy: 'Security Analyst' });
      await loadData();
      setSelectedAlert(null);
      setResolveNotes('');
    } catch (e) {
      alert('Failed to resolve alert: ' + (e.response?.data?.message || e.message));
    } finally {
      setUpdating(false);
    }
  }

  const columns = [
    {
      key: 'title',
      label: 'ALERT TITLE & SOURCE',
      render: r => (
        <div className="event-cell">
          <span className={`event-dot ${(r.severity || 'low').toLowerCase()}`} />
          <div>
            <strong>{r.title}</strong>
            <small className="mono">{r.source || 'Risk Engine'} {r.category ? `· ${r.category}` : ''}</small>
          </div>
        </div>
      )
    },
    {
      key: 'severity',
      label: 'SEVERITY',
      render: r => (
        <Badge tone={r.severity === 'CRITICAL' ? 'red' : r.severity === 'HIGH' ? 'amber' : r.severity === 'MEDIUM' ? 'blue' : 'teal'}>
          {r.severity}
        </Badge>
      )
    },
    {
      key: 'scanTarget',
      label: 'TARGET / SCAN',
      render: r => (
        <div>
          <span>{r.scanTarget || 'System Alert'}</span>
          {r.scanId && <small className="mono">Scan #{r.scanId}</small>}
        </div>
      )
    },
    {
      key: 'status',
      label: 'STATUS',
      render: r => (
        <Badge tone={r.status === 'RESOLVED' ? 'teal' : r.status === 'INVESTIGATING' ? 'amber' : 'red'}>
          {r.status || 'NEW'}
        </Badge>
      )
    },
    {
      key: 'createdAt',
      label: 'TIME',
      render: r => <span className="mono">{r.createdAt ? new Date(r.createdAt).toLocaleString() : 'N/A'}</span>
    },
    {
      key: 'actions',
      label: 'ACTIONS',
      render: r => (
        <div style={{ display: 'flex', gap: '8px' }}>
          <button className="button small secondary" onClick={(e) => { e.stopPropagation(); setSelectedAlert(r); }}>
            <Eye size={14} /> Details
          </button>
        </div>
      )
    }
  ];

  return (
    <div className="alerts-container">
      {stats && (
        <div className="stats-grid" style={{ marginBottom: '20px' }}>
          <Card className="stat-card red">
            <div className="stat-label">Critical Alerts <span className="stat-icon"><ShieldAlert size={18} /></span></div>
            <div className="stat-value">{stats.criticalCount}</div>
            <div className="stat-bottom"><span>Immediate action required</span></div>
          </Card>
          <Card className="stat-card amber">
            <div className="stat-label">High Severity <span className="stat-icon"><AlertTriangle size={18} /></span></div>
            <div className="stat-value">{stats.highCount}</div>
            <div className="stat-bottom"><span>Under review</span></div>
          </Card>
          <Card className="stat-card blue">
            <div className="stat-label">New / Unassigned <span className="stat-icon"><Bell size={18} /></span></div>
            <div className="stat-value">{stats.newCount}</div>
            <div className="stat-bottom"><span>Pending triage</span></div>
          </Card>
          <Card className="stat-card teal">
            <div className="stat-label">Resolved Alerts <span className="stat-icon"><CheckCircle size={18} /></span></div>
            <div className="stat-value">{stats.resolvedCount}</div>
            <div className="stat-bottom"><span>Total resolved</span></div>
          </Card>
        </div>
      )}

      <Card className="padded">
        <div className="panel-heading" style={{ marginBottom: '16px' }}>
          <div>
            <h2>Active Security Alerts Queue</h2>
            <p>Real-time security signals automatically generated from APK risk assessments and threat matches.</p>
          </div>
          <Button variant="secondary" onClick={loadData} disabled={loading}>
            <RefreshCw size={15} /> Refresh
          </Button>
        </div>

        <form onSubmit={handleSearch} className="filterbar" style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
          <div className="filter-input" style={{ flex: 1 }}>
            <Search size={16} />
            <input
              placeholder="Search alert title, source, or description..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <select value={status} onChange={e => setStatus(e.target.value)}>
            <option value="All">All Statuses</option>
            <option value="NEW">New</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="RESOLVED">Resolved</option>
          </select>
          <select value={severity} onChange={e => setSeverity(e.target.value)}>
            <option value="All">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <Button type="submit">Filter</Button>
        </form>

        {error && <ErrorState message={error} retry={loadData} />}
        {loading ? <Loading /> : <Table columns={columns} rows={alerts} onRowClick={setSelectedAlert} />}
      </Card>

      {selectedAlert && (
        <Modal title={selectedAlert.title} onClose={() => setSelectedAlert(null)}>
          <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div className="detail-line"><span>Severity</span><Badge tone={selectedAlert.severity === 'CRITICAL' ? 'red' : 'amber'}>{selectedAlert.severity}</Badge></div>
              <div className="detail-line"><span>Status</span><Badge>{selectedAlert.status}</Badge></div>
              <div className="detail-line"><span>Source Engine</span><span className="mono">{selectedAlert.source}</span></div>
              <div className="detail-line"><span>Category</span><span className="mono">{selectedAlert.category || 'N/A'}</span></div>
              <div className="detail-line"><span>Scan Target</span><span>{selectedAlert.scanTarget || 'N/A'}</span></div>
              <div className="detail-line"><span>Created At</span><span className="mono">{new Date(selectedAlert.createdAt).toLocaleString()}</span></div>
            </div>

            <div>
              <strong>Description</strong>
              <p style={{ marginTop: '4px', background: '#121c2d', padding: '10px', borderRadius: '6px', fontSize: '13px' }}>
                {selectedAlert.description}
              </p>
            </div>

            {selectedAlert.notes && (
              <div>
                <strong>Analyst Notes / Resolution</strong>
                <p style={{ marginTop: '4px', background: '#18283f', padding: '10px', borderRadius: '6px', fontSize: '13px' }}>
                  {selectedAlert.notes}
                </p>
              </div>
            )}

            {selectedAlert.status !== 'RESOLVED' && (
              <div style={{ marginTop: '10px', borderTop: '1px solid #24344d', paddingTop: '14px' }}>
                <h4>Triage & Workflow Actions</h4>
                <div style={{ display: 'flex', gap: '10px', marginTop: '10px' }}>
                  {selectedAlert.status !== 'INVESTIGATING' && (
                    <Button
                      variant="secondary"
                      onClick={() => handleStatusChange(selectedAlert.id, 'INVESTIGATING')}
                      disabled={updating}
                    >
                      Mark as Investigating
                    </Button>
                  )}
                  <input
                    placeholder="Resolution notes (e.g., False positive, Mitigated, Remediated)..."
                    value={resolveNotes}
                    onChange={e => setResolveNotes(e.target.value)}
                    style={{ flex: 1, padding: '8px 12px', background: '#101726', border: '1px solid #273852', borderRadius: '6px', color: '#fff' }}
                  />
                  <Button
                    onClick={() => handleResolve(selectedAlert.id)}
                    disabled={updating}
                  >
                    <Check size={16} /> Resolve Alert
                  </Button>
                </div>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
}
