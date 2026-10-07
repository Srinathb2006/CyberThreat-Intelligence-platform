import { LayoutDashboard, PackageSearch, Link, ShieldCheck, Radar, Fingerprint, Workflow, History, FileBarChart, Bell, Monitor, Settings } from 'lucide-react';
export const navigation = [
  { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, group: 'WORKSPACE' },
  { path: '/apk-analysis', label: 'APK Analysis', icon: PackageSearch },
  { path: '/url-scanner', label: 'URL Scanner', icon: Link },
  { path: '/phishing', label: 'Phishing Detection', icon: ShieldCheck },
  { path: '/threat-intelligence', label: 'Threat Intelligence', icon: Radar, group: 'INTELLIGENCE' },
  { path: '/ioc-explorer', label: 'IOC Explorer', icon: Fingerprint },
  { path: '/risk-correlation', label: 'Risk Correlation', icon: Workflow },
  { path: '/scan-history', label: 'Scan History', icon: History, group: 'OPERATIONS' },
  { path: '/reports', label: 'Reports', icon: FileBarChart },
  { path: '/alerts', label: 'Alerts', icon: Bell, count: 12 },
  { path: '/endpoint-monitoring', label: 'Endpoint Monitoring', icon: Monitor },
  { path: '/settings', label: 'Settings', icon: Settings },
];
