import { useEffect, useState } from 'react';
import { Activity, CircleAlert, Laptop, Plus, RefreshCw, ShieldCheck } from 'lucide-react';
import { Badge, Button, Card, EmptyState, ErrorState, Loading, Modal, Table } from '../components/ui';
import { getEndpoint, getEndpointEvents, listEndpoints, registerEndpoint } from '../api/endpointMonitoringApi';
import { dateTime, payloadForRegistration, riskTone, statusTone, text } from '../utils/endpointMonitoring';

const blankForm = { hostname: '', deviceName: '', operatingSystem: '', platform: '', status: 'ONLINE' };
const badge = (value, tone) => <Badge tone={tone}>{text(value)}</Badge>;

function EventDetail({ event, onClose }) {
  return <Modal title="Security event" onClose={onClose}><div className="modal-body endpoint-event-detail">
    <div className="endpoint-event-heading">{badge(event.severity, riskTone(event.severity))}{event.suspicious && <Badge tone="critical">SUSPICIOUS</Badge>}<Badge tone="neutral">DEMO DATA</Badge></div>
    <h3>{event.title}</h3><p>{event.description}</p>
    <dl className="endpoint-facts"><div><dt>Event type</dt><dd>{text(event.eventType)}</dd></div><div><dt>Observed</dt><dd>{dateTime(event.observedAt)}</dd></div><div><dt>Source</dt><dd>{text(event.source)}</dd></div><div><dt>Endpoint</dt><dd>{text(event.endpointId)}</dd></div></dl>
  </div></Modal>;
}

export default function EndpointMonitoring() {
  const [endpoints, setEndpoints] = useState([]); const [loading, setLoading] = useState(true); const [error, setError] = useState('');
  const [selected, setSelected] = useState(null); const [events, setEvents] = useState([]); const [detailLoading, setDetailLoading] = useState(false); const [suspiciousOnly, setSuspiciousOnly] = useState(false); const [event, setEvent] = useState(null);
  const [form, setForm] = useState(blankForm); const [registering, setRegistering] = useState(false); const [formError, setFormError] = useState('');
  const load = async () => { setLoading(true); setError(''); try { setEndpoints(await listEndpoints()); } catch (cause) { setError(cause.response?.data?.message || 'Endpoint inventory could not be loaded.'); } finally { setLoading(false); } };
  useEffect(() => { load(); }, []);
  const chooseEndpoint = async row => { setDetailLoading(true); setSelected(null); setEvents([]); setSuspiciousOnly(false); try { const detail = await getEndpoint(row.id); setSelected(detail.endpoint || detail); setEvents(detail.events || detail.recentEvents || []); } catch (cause) { setError(cause.response?.data?.message || 'Endpoint details could not be loaded.'); } finally { setDetailLoading(false); } };
  const refreshEvents = async (onlySuspicious = suspiciousOnly) => { if (!selected) return; setDetailLoading(true); try { setEvents(await getEndpointEvents(selected.id, onlySuspicious)); } catch (cause) { setError(cause.response?.data?.message || 'Endpoint events could not be loaded.'); } finally { setDetailLoading(false); } };
  const toggleSuspicious = checked => { setSuspiciousOnly(checked); refreshEvents(checked); };
  const submit = async e => { e.preventDefault(); setFormError(''); const payload = payloadForRegistration(form); if (!payload.hostname || !payload.deviceName || !payload.operatingSystem || !payload.platform) { setFormError('Hostname, device name, operating system, and platform are required.'); return; } setRegistering(true); try { const created = await registerEndpoint(payload); setForm(blankForm); await load(); chooseEndpoint(created); } catch (cause) { setFormError(cause.response?.data?.message || 'Endpoint registration could not be completed.'); } finally { setRegistering(false); } };
  const columns = [
    { key: 'hostname', label: 'ENDPOINT', render: row => <span className="endpoint-name"><strong>{text(row.hostname)}</strong><small>{text(row.deviceName)}</small></span> },
    { key: 'platform', label: 'DEVICE', render: row => <span className="endpoint-device">{text(row.operatingSystem)}<small>{text(row.platform)}</small></span> },
    { key: 'status', label: 'STATUS', render: row => badge(row.status, statusTone(row.status)) },
    { key: 'lastSeenAt', label: 'LAST SEEN', render: row => <span className="endpoint-time">{dateTime(row.lastSeenAt)}</span> },
    { key: 'risk', label: 'RISK', render: row => <span className="endpoint-risk">{badge(row.riskSummary?.riskLevel || 'UNKNOWN', riskTone(row.riskSummary?.riskLevel))}<small>{row.riskSummary?.score ?? 0}/100</small></span> },
  ];
  const eventColumns = [
    { key: 'title', label: 'EVENT', render: row => <span className="endpoint-name"><strong>{text(row.title)}</strong><small>{text(row.eventType)}</small></span> },
    { key: 'severity', label: 'SEVERITY', render: row => badge(row.severity, riskTone(row.severity)) },
    { key: 'observedAt', label: 'OBSERVED', render: row => dateTime(row.observedAt) },
    { key: 'source', label: 'SOURCE', render: row => <span>{text(row.source)} {row.suspicious && <Badge tone="critical">SUSPICIOUS</Badge>}</span> },
  ];
  if (loading) return <Loading />;
  if (error && !endpoints.length) return <ErrorState message={error} retry={load} />;
  const risk = selected?.riskSummary || { score: 0, riskLevel: 'UNKNOWN', totalEvents: 0, suspiciousEvents: 0, highOrCriticalEvents: 0 };
  return <>
    <div className="page-heading"><div><div className="eyebrow">LIGHTWEIGHT ENDPOINT INVENTORY <Badge tone="neutral">DEMO DATA</Badge></div><h1>Endpoint Monitoring<span className="title-dot">.</span></h1><p>Register devices and review deterministic demo security events when OS telemetry is unavailable.</p></div><span className="page-icon"><Laptop size={27} /></span></div>
    <div className="endpoint-notice"><CircleAlert size={17} /><span><strong>Demo mode.</strong> Events are deterministic records for demonstration. This module has no agent, kernel driver, packet capture, telemetry collection, or malware execution, and does not provide real-time monitoring.</span></div>
    <div className="endpoint-layout"><Card className="endpoint-register"><div className="panel-heading"><div><h2>Register endpoint</h2><p>Add a device to this demo inventory.</p></div><Plus size={18} /></div><form className="endpoint-form" onSubmit={submit}>
      {[['hostname', 'Hostname', 'workstation-04'], ['deviceName', 'Device name', 'Finance laptop'], ['operatingSystem', 'Operating system', 'Windows 11 Pro'], ['platform', 'Platform', 'Windows']].map(([key, label, placeholder]) => <label key={key}>{label}<input value={form[key]} placeholder={placeholder} onChange={e => setForm({ ...form, [key]: e.target.value })} /></label>)}
      <label>Status<select value={form.status} onChange={e => setForm({ ...form, status: e.target.value })}><option value="ONLINE">Online</option><option value="OFFLINE">Offline</option><option value="UNKNOWN">Unknown</option></select></label>
      {formError && <p className="form-error">{formError}</p>}<Button type="submit" disabled={registering}><Plus size={15} />{registering ? 'Registering…' : 'Register demo endpoint'}</Button>
    </form></Card>
    <Card className="endpoint-inventory"><div className="panel-heading"><div><h2>Endpoint inventory</h2><p>{endpoints.length} registered device{endpoints.length === 1 ? '' : 's'} · all records are demo data</p></div><Button variant="secondary" onClick={load}><RefreshCw size={15} />Refresh</Button></div>{error && <p className="form-error">{error}</p>}{endpoints.length ? <Table columns={columns} rows={endpoints} onRowClick={chooseEndpoint} /> : <EmptyState title="No endpoints registered" message="Register a demo endpoint to view its security event summary." />}</Card></div>
    <Card className="endpoint-detail"><div className="panel-heading"><div><h2>{selected ? selected.hostname : 'Endpoint detail'}</h2><p>{selected ? `${text(selected.deviceName)} · ${text(selected.operatingSystem)}` : 'Select an endpoint from the inventory to inspect its status and events.'}</p></div>{selected && badge(selected.status, statusTone(selected.status))}</div>
      {detailLoading ? <Loading /> : selected ? <><div className="endpoint-summary"><article className="endpoint-score"><span>RISK SCORE</span><strong>{risk.score}</strong><small>out of 100</small>{badge(risk.riskLevel, riskTone(risk.riskLevel))}</article><article><Activity size={18} /><strong>{risk.totalEvents}</strong><span>basic events</span></article><article><CircleAlert size={18} /><strong>{risk.suspiciousEvents}</strong><span>suspicious events</span></article><article><ShieldCheck size={18} /><strong>{risk.highOrCriticalEvents}</strong><span>high / critical</span></article></div>
      <div className="endpoint-events-head"><div><h3>Security events <Badge tone="neutral">DEMO DATA</Badge></h3><p>Basic stored records for this endpoint.</p></div><label className="endpoint-checkbox"><input type="checkbox" checked={suspiciousOnly} onChange={e => toggleSuspicious(e.target.checked)} /> Suspicious only</label></div>{events.length ? <Table columns={eventColumns} rows={events} onRowClick={setEvent} /> : <EmptyState title="No matching demo events" message="No stored events match the selected filter." />}</> : <EmptyState title="Choose an endpoint" message="Its device information, risk summary, and basic demo events will appear here." />}
    </Card>{event && <EventDetail event={event} onClose={() => setEvent(null)} />}
  </>;
}
