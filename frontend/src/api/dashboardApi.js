import api from './axios';

const defaultStats = [
  { label: 'Total APK scans', value: '1,284', change: '+12.8%', tone: 'teal', icon: 'apk', detail: 'Total scans recorded' },
  { label: 'High / Critical Risks', value: '86', change: '+8.2%', tone: 'red', icon: 'shield', detail: 'High priority threats' },
  { label: 'New / Active Alerts', value: '12', change: 'Needs triage', tone: 'amber', icon: 'alert', detail: 'Pending analyst review' },
  { label: 'Threat Intel Matches', value: '89', change: '+15.6%', tone: 'purple', icon: 'intel', detail: 'Correlated matches' },
  { label: 'Detected IOCs', value: '3,692', change: '+18.4%', tone: 'blue', icon: 'ioc', detail: 'Extracted indicators' },
  { label: 'Average risk score', value: '64', suffix: '/100', change: 'Overall', tone: 'amber', icon: 'risk', detail: 'Across all samples' },
];

const trends = [
  { day: 'Mon', malicious: 18, suspicious: 35 },
  { day: 'Tue', malicious: 25, suspicious: 48 },
  { day: 'Wed', malicious: 20, suspicious: 40 },
  { day: 'Thu', malicious: 42, suspicious: 65 },
  { day: 'Fri', malicious: 30, suspicious: 49 },
  { day: 'Sat', malicious: 38, suspicious: 60 },
  { day: 'Sun', malicious: 32, suspicious: 52 }
];

export const sampleEvents = [
  { id: 'EVT-1042', event: 'Banking trojan signature detected', type: 'APK analysis', severity: 'Critical', source: 'finance-update.apk', time: '2 min ago', status: 'Open', description: 'Sample YARA signature associated with credential harvesting.' },
  { id: 'EVT-1041', event: 'Suspicious outbound connection', type: 'IOC match', severity: 'High', source: '198.51.100.24', time: '8 min ago', status: 'Investigating', description: 'Connection to high-risk IP correlated with APK.' },
  { id: 'EVT-1040', event: 'Credential phishing page identified', type: 'URL scan', severity: 'High', source: 'account-verify.example', time: '14 min ago', status: 'Open', description: 'Phishing workflow identified.' },
  { id: 'EVT-1039', event: 'Excessive permissions requested', type: 'APK analysis', severity: 'Medium', source: 'weather-widget.apk', time: '26 min ago', status: 'Reviewed', description: 'Manifest requests access beyond expected functionality.' },
  { id: 'EVT-1038', event: 'Known indicator matched', type: 'Threat intel', severity: 'Low', source: 'telemetry.example', time: '42 min ago', status: 'Resolved', description: 'Known low-risk telemetry indicator.' },
];

export async function getDashboardStats() {
  try {
    const res = await api.get('/dashboard/stats');
    const d = res.data;
    if (d && d.totalScans !== undefined) {
      return [
        { label: 'Total APK scans', value: String(d.totalScans), change: 'Total', tone: 'teal', icon: 'apk', detail: 'All completed & pending scans' },
        { label: 'High / Critical Risks', value: String(d.highCriticalRisks), change: 'High Priority', tone: 'red', icon: 'shield', detail: 'Elevated risk packages' },
        { label: 'New Alerts', value: String(d.newAlerts), change: d.newAlerts > 0 ? 'Needs review' : 'Clear', tone: d.newAlerts > 0 ? 'red' : 'teal', icon: 'alert', detail: 'Unresolved security alerts' },
        { label: 'Threat Intel Matches', value: String(d.threatMatches), change: 'Correlated', tone: 'purple', icon: 'intel', detail: 'Matched known threats' },
        { label: 'Detected IOCs', value: String(d.totalIocs), change: 'Total', tone: 'blue', icon: 'ioc', detail: 'Across all APK extractions' },
        { label: 'Average risk score', value: String(d.avgRiskScore || 0), suffix: '/100', change: 'Fleet avg', tone: d.avgRiskScore >= 50 ? 'amber' : 'teal', icon: 'risk', detail: 'Average computed score' },
      ];
    }
  } catch (e) {
    // Fallback to demo stats if not connected or error
  }
  return structuredClone(defaultStats);
}

export async function getThreatTrends(days = '7') {
  return trends.map((item, i) => ({
    ...item,
    day: days === '30' ? `Day ${[1, 5, 10, 15, 20, 25, 30][i]}` : item.day,
    malicious: days === '30' ? item.malicious * 3 : item.malicious,
    suspicious: days === '30' ? item.suspicious * 3 : item.suspicious
  }));
}

export async function getRecentEvents() {
  try {
    const res = await api.get('/alerts');
    if (res.data && res.data.length > 0) {
      return res.data.slice(0, 10).map(a => ({
        id: `ALT-${a.id}`,
        event: a.title,
        type: a.category || 'Security Alert',
        severity: a.severity ? a.severity.charAt(0) + a.severity.slice(1).toLowerCase() : 'Medium',
        source: a.scanTarget || a.source || 'Scan Engine',
        time: a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Recent',
        status: a.status ? a.status.charAt(0) + a.status.slice(1).toLowerCase() : 'New',
        description: a.description
      }));
    }
  } catch (e) {
    // Fallback
  }
  return structuredClone(sampleEvents);
}

export async function getDistributions() {
  return {
    risk: [
      { name: 'Critical', value: 12, color: '#fc6a7e' },
      { name: 'High', value: 28, color: '#f2b45c' },
      { name: 'Medium', value: 38, color: '#5d9bf5' },
      { name: 'Low', value: 22, color: '#39d0b7' }
    ],
    types: [
      { name: 'Malware', value: 86 },
      { name: 'Phishing', value: 64 },
      { name: 'Adware', value: 42 },
      { name: 'Spyware', value: 28 }
    ]
  };
}
