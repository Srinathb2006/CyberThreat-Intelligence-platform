import { useEffect, useState } from 'react';
import { FileText, Download, FileCode, Database, FileSpreadsheet, ShieldAlert, CheckCircle, RefreshCw, Layers } from 'lucide-react';
import { Card, Badge, Button, Loading, ErrorState } from '../components/ui';
import { getScanHistory } from '../api/scanHistoryApi';
import { downloadReport } from '../api/reportApi';

export default function ReportsPage() {
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [downloading, setDownloading] = useState(null);

  async function loadScans() {
    setLoading(true);
    setError('');
    try {
      const data = await getScanHistory();
      setScans(data);
      if (data.length > 0) {
        setSelectedScanId(String(data[0].id));
      }
    } catch (e) {
      setError(e.response?.data?.message || e.message || 'Failed to load scans for reports');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadScans();
  }, []);

  async function handleDownload(format) {
    if (!selectedScanId) return;
    setDownloading(format);
    try {
      await downloadReport(selectedScanId, format);
    } catch (e) {
      alert('Report download failed: ' + (e.response?.data?.message || e.message));
    } finally {
      setDownloading(null);
    }
  }

  const selectedScan = scans.find(s => String(s.id) === String(selectedScanId));

  const reportFormats = [
    {
      id: 'pdf',
      title: 'Executive & Technical PDF Report',
      description: 'Comprehensive report with executive summary, risk verdict, indicator breakdown, malware findings, threat matches, and security alerts.',
      icon: FileText,
      tag: 'PDF DOCUMENT',
      buttonLabel: 'Download PDF',
      color: '#fc6a7e'
    },
    {
      id: 'json',
      title: 'Structured Intelligence JSON Export',
      description: 'Complete machine-readable JSON dataset including all reverse-engineering metadata, APK permissions, API calls, strings, IOCs, and findings.',
      icon: FileCode,
      tag: 'JSON DATASET',
      buttonLabel: 'Export JSON',
      color: '#5d9bf5'
    },
    {
      id: 'findings',
      title: 'Malware Findings CSV',
      description: 'Tabular export of all static analysis malware detections, category tags, severity ratings, confidence levels, and disassembled code evidence.',
      icon: FileSpreadsheet,
      tag: 'CSV EXPORT',
      buttonLabel: 'Download Findings CSV',
      color: '#39d0b7'
    },
    {
      id: 'iocs',
      title: 'Extracted IOC Indicators CSV',
      description: 'Extracted network indicators, suspicious IP addresses, C2 domain names, and external infrastructure URLs identified during static inspection.',
      icon: Database,
      tag: 'CSV EXPORT',
      buttonLabel: 'Download IOCs CSV',
      color: '#b397ee'
    },
    {
      id: 'threat_matches',
      title: 'Threat Intelligence Matches CSV',
      description: 'Correlated matches against known threat intelligence feeds, banking trojans, malware families, and malicious infrastructure.',
      icon: Layers,
      tag: 'CSV EXPORT',
      buttonLabel: 'Download Threat Matches CSV',
      color: '#f2b45c'
    },
    {
      id: 'summary',
      title: 'Executive Summary CSV',
      description: 'Key investigation metrics, risk score, scan timestamp, application package identifier, and high-level risk assessment verdict.',
      icon: FileSpreadsheet,
      tag: 'CSV EXPORT',
      buttonLabel: 'Download Summary CSV',
      color: '#39d0b7'
    }
  ];

  if (loading) return <Loading />;
  if (error) return <ErrorState message={error} retry={loadScans} />;

  return (
    <div className="reports-page-container">
      <Card className="padded" style={{ marginBottom: '20px' }}>
        <div className="panel-heading" style={{ marginBottom: '16px' }}>
          <div>
            <h2>Investigation Report Generator</h2>
            <p>Export professional PDF reports and structured data files for auditing, compliance, and SIEM/SOAR ingestion.</p>
          </div>
          <Button variant="secondary" onClick={loadScans}>
            <RefreshCw size={15} /> Refresh Scans
          </Button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', background: '#121c2d', padding: '16px', borderRadius: '8px' }}>
          <label htmlFor="scan-selector" style={{ fontWeight: 'bold', whiteSpace: 'nowrap' }}>
            Select Investigation Target:
          </label>
          <select
            id="scan-selector"
            value={selectedScanId}
            onChange={e => setSelectedScanId(e.target.value)}
            style={{ flex: 1, padding: '10px 14px', background: '#0e1726', border: '1px solid #283a54', borderRadius: '6px', color: '#fff' }}
          >
            {scans.map(s => (
              <option key={s.id} value={s.id}>
                Scan #{s.id} — {s.applicationName || s.target} ({s.packageName || 'APK'}) · Risk: {s.riskLevel} ({s.riskScore != null ? `${s.riskScore}/100` : 'N/A'})
              </option>
            ))}
          </select>
        </div>

        {selectedScan && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px', marginTop: '16px' }}>
            <div className="detail-line"><span>Target Application</span><strong>{selectedScan.applicationName || selectedScan.target}</strong></div>
            <div className="detail-line"><span>Package Name</span><span className="mono">{selectedScan.packageName || 'N/A'}</span></div>
            <div className="detail-line"><span>Risk Verdict</span><Badge tone={selectedScan.riskLevel === 'CRITICAL' ? 'red' : selectedScan.riskLevel === 'HIGH' ? 'amber' : 'teal'}>{selectedScan.riskLevel} ({selectedScan.riskScore}/100)</Badge></div>
            <div className="detail-line"><span>Findings / IOCs</span><span className="mono">{selectedScan.findingsCount} findings · {selectedScan.iocCount} IOCs</span></div>
          </div>
        )}
      </Card>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
        {reportFormats.map(f => {
          const Icon = f.icon;
          const isCurrentDownloading = downloading === f.id;
          return (
            <Card key={f.id} className="padded" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <span style={{ color: f.color, background: `${f.color}15`, padding: '8px', borderRadius: '8px', display: 'inline-flex' }}>
                    <Icon size={24} />
                  </span>
                  <Badge tone="neutral">{f.tag}</Badge>
                </div>
                <h3 style={{ fontSize: '16px', marginBottom: '8px' }}>{f.title}</h3>
                <p className="muted" style={{ fontSize: '13px', lineHeight: '1.5', marginBottom: '16px' }}>
                  {f.description}
                </p>
              </div>

              <Button
                variant={f.id === 'pdf' ? 'primary' : 'secondary'}
                onClick={() => handleDownload(f.id)}
                disabled={!selectedScanId || isCurrentDownloading}
                style={{ width: '100%', justifyContent: 'center' }}
              >
                <Download size={15} /> {isCurrentDownloading ? 'Generating...' : f.buttonLabel}
              </Button>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
