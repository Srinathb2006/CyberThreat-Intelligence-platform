import { useEffect, useState, useMemo } from 'react';
import { Search, Gauge, AlertTriangle, ShieldCheck, TrendingUp, Download, ChevronDown } from 'lucide-react';
import { Card, Badge, Button, Table, Loading, ErrorState, EmptyState } from '../components/ui';
import { calculateRisk, getRiskAssessment, getRiskIndicators, getRiskBreakdown, getRiskRecommendations } from '../api/scanApi';
import { downloadReport } from '../api/reportApi';

const riskLevelVariant = (level) => {
  switch (level) {
    case 'CRITICAL': return 'destructive';
    case 'HIGH': return 'destructive';
    case 'MEDIUM': return 'warning';
    case 'LOW': return 'success';
    default: return 'outline';
  }
};

const severityVariant = (sev) => {
  switch (sev) {
    case 'CRITICAL': return 'destructive';
    case 'HIGH': return 'destructive';
    case 'MEDIUM': return 'warning';
    case 'LOW': return 'secondary';
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

export default function RiskCorrelationPage({ scanId }) {
  const [assessment, setAssessment] = useState(null);
  const [indicators, setIndicators] = useState([]);
  const [breakdown, setBreakdown] = useState(null);
  const [recommendations, setRecommendations] = useState([]);
  const [loading, setLoading] = useState(false);
  const [calculating, setCalculating] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    if (scanId) {
      loadAssessment();
    }
  }, [scanId]);

  async function loadAssessment() {
    setLoading(true);
    setError('');
    try {
      const result = await getRiskAssessment(scanId);
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
      const result = await calculateRisk(scanId);
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

  if (!scanId) {
    return (
      <div className="page-heading">
        <div>
          <div className="eyebrow">RISK CORRELATION</div>
          <h1>Risk Correlation Engine<span className="title-dot">.</span></h1>
          <p>Select an APK scan to analyze its risk profile.</p>
        </div>
        <span className="page-icon"><Gauge size={27} /></span>
      </div>
    );
  }

  if (loading) return <Loading />;
  if (error && !assessment) return <ErrorState message={error} retry={handleCalculate} />;

  const score = assessment?.score ?? 0;
  const riskLevel = assessment?.riskLevel ?? 'LOW';
  const confidence = assessment?.confidence ?? 'LOW';

  const gaugeValue = Math.min(100, Math.max(0, score));
  const gaugeAngle = (gaugeValue / 100) * 180 - 90;

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

  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">RISK CORRELATION</div>
          <h1>Risk Assessment<span className="title-dot">.</span></h1>
          <p>Explainable risk scoring based on static analysis, IOCs, and threat intelligence.</p>
        </div>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          {scanId && (
            <Button variant="secondary" onClick={() => downloadReport(scanId, 'pdf')}>
              <Download size={15} /> Export PDF Report
            </Button>
          )}
          <span className="page-icon"><Gauge size={27} /></span>
        </div>
      </div>

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
        <Card className="padded">
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
              {calculating ? <TrendingUp className="spin" size={16} /> : <Gauge size={16} />}
              {calculating ? 'Calculating...' : 'Calculate Risk'}
            </Button>
            {assessment && (
              <Button variant="secondary" onClick={() => downloadReport(assessment)}>
                <Download size={16} />Export Report
              </Button>
            )}
          </div>
        </Card>

        <Card className="padded">
          <div className="panel-heading"><h2>Risk Summary</h2></div>
          <div className="risk-summary">
            <p>{assessment?.summary || 'No risk assessment available. Click "Calculate Risk" to generate an assessment.'}</p>
          </div>
        </Card>
      </div>

      <div className="module-grid">
        <Card className="padded">
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
        </Card>

        <Card className="padded">
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
        </Card>
      </div>

      <Card className="padded">
        <div className="panel-heading">
          <h2>Contributing Indicators</h2>
          <p>{indicators.length} evidence items contributing to the risk score</p>
        </div>
        <div className="filterbar">
          <div className="filter-input" style={{ flex: 1 }}>
            <Search size={16} />
            <input
              placeholder="Filter indicators..."
              onChange={e => setFilter(e.target.value)}
            />
          </div>
        </div>
        {indicators.length ? (
          <Table columns={indicatorColumns} rows={filteredIndicators} />
        ) : (
          <EmptyState title="No indicators" message="Calculate risk to see contributing evidence." />
        )}
      </Card>

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
    </>
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