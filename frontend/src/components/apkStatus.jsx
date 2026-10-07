import { Badge } from './ui';
export function StatusBadge({ status }) { return <Badge tone={status === 'COMPLETED' || status === 'SUCCESS' ? 'teal' : ['FAILED', 'TIMEOUT'].includes(status) ? 'red' : ['RUNNING', 'QUEUED', 'MOCK'].includes(status) ? 'amber' : 'neutral'}>{status || 'PENDING'}</Badge>; }
