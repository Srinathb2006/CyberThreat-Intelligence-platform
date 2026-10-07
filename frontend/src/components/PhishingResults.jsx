import { Badge } from './ui';

const redirectStatus = {
  INSPECTED: 'Parsed from URL text',
  UNSUPPORTED_SCHEME: 'Unsupported destination scheme',
  INVALID: 'Invalid destination URL',
  EMPTY: 'Empty destination',
};

export default function PhishingResults({ result }) {
  return <div className="url-evidence">
    <div className="url-score"><div><span className="eyebrow">RULE-BASED ESTIMATE</span><strong>{result.score}<small>/100</small></strong><Badge>{result.riskLevel}</Badge></div><div><p>Rule points are added and capped at 100. This is a static estimate, not a verified phishing verdict. A low score does not establish safety.</p><p className="phishing-score-scale">LOW 0–25 · MEDIUM 26–50 · HIGH 51–75 · CRITICAL 76–100</p></div></div>
    <dl className="url-facts"><div><dt>Host</dt><dd>{result.host}</dd></div><div><dt>HTTPS scheme</dt><dd>{result.https ? 'Yes' : 'No'}</dd></div><div><dt>IP-based address</dt><dd>{result.ipBased ? 'Yes' : 'No'}</dd></div></dl>
    <div className="section-heading"><h3>Reasons for the score</h3><span className="muted small">{result.reasons.length} indicators</span></div>
    {result.reasons.length ? <ul className="url-findings">{result.reasons.map((reason, index) => <li key={`${reason.code}-${index}`}><div className="url-finding-heading"><Badge>{reason.severity}</Badge><strong>{reason.code.replaceAll('_', ' ')}</strong><span className="muted small">+{reason.contribution} points</span></div><p>{reason.description}</p>{reason.evidence && <code>{reason.evidence}</code>}</li>)}</ul> : <p className="url-no-findings">No configured phishing indicators were detected in the URL text.</p>}
    <div className="phishing-redirects"><div className="section-heading"><h3>Possible redirect parameters</h3><span className="muted small">{result.redirectIndicators.length} candidates</span></div><p className="phishing-redirect-note">Parameters indicate possible redirects only. No responses or redirects were observed, and no destination was visited.</p>
      {result.redirectIndicators.length ? <ul className="url-findings">{result.redirectIndicators.map((redirect, index) => <li key={`${redirect.parameter}-${index}`}><div className="url-finding-heading"><strong>{redirect.parameter}</strong><Badge tone="neutral">{redirectStatus[redirect.status] || redirect.status}</Badge></div><code>{redirect.destination || '(empty)'}</code><dl className="url-facts phishing-redirect-facts"><div><dt>Destination host</dt><dd>{redirect.host || 'Not inspectable'}</dd></div><div><dt>Host comparison</dt><dd>{redirect.status !== 'INSPECTED' ? 'Unknown' : redirect.crossHost ? 'Different host' : 'Same host'}</dd></div><div><dt>HTTPS scheme</dt><dd>{redirect.https == null ? 'Unknown' : redirect.https ? 'Yes' : 'No'}</dd></div></dl></li>)}</ul> : <p className="url-no-findings">No configured redirect parameters were found.</p>}
    </div>
  </div>;
}
