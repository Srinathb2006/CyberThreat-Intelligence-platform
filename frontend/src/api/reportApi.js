import api from './axios';

export async function downloadReport(scanId, format = 'pdf') {
  let endpoint;
  let filename;
  let mimeType;

  switch (format.toLowerCase()) {
    case 'pdf':
      endpoint = `/reports/${scanId}/pdf`;
      filename = `cyberintel-report-${scanId}.pdf`;
      mimeType = 'application/pdf';
      break;
    case 'json':
      endpoint = `/reports/${scanId}/json`;
      filename = `cyberintel-report-${scanId}.json`;
      mimeType = 'application/json';
      break;
    case 'findings':
    case 'findings_csv':
      endpoint = `/reports/${scanId}/findings.csv`;
      filename = `findings-${scanId}.csv`;
      mimeType = 'text/csv';
      break;
    case 'iocs':
    case 'iocs_csv':
      endpoint = `/reports/${scanId}/iocs.csv`;
      filename = `iocs-${scanId}.csv`;
      mimeType = 'text/csv';
      break;
    case 'threat_matches':
    case 'threat_matches_csv':
      endpoint = `/reports/${scanId}/threat-matches.csv`;
      filename = `threat-matches-${scanId}.csv`;
      mimeType = 'text/csv';
      break;
    case 'summary':
    case 'summary_csv':
      endpoint = `/reports/${scanId}/summary.csv`;
      filename = `summary-${scanId}.csv`;
      mimeType = 'text/csv';
      break;
    default:
      endpoint = `/reports/${scanId}/pdf`;
      filename = `cyberintel-report-${scanId}.pdf`;
      mimeType = 'application/pdf';
  }

  const response = await api.get(endpoint, { responseType: 'blob' });
  const blob = new Blob([response.data], { type: mimeType });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  link.parentNode.removeChild(link);
  window.URL.revokeObjectURL(url);
}
