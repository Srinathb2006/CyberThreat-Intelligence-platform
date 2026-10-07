export const PAGE_SIZE = 25;

export function matchState(matches = []) {
  if (!matches.length) return { label: 'No intelligence match', tone: 'neutral' };
  const matched = matches.find(match => String(match.status).toUpperCase() === 'MATCHED');
  if (matched) return { label: 'Matched', tone: String(matched.severity || 'medium').toLowerCase(), match: matched };
  const reviewed = matches.find(match => ['REVIEW', 'REVIEWED', 'NO_MATCH'].includes(String(match.status).toUpperCase()));
  return { label: reviewed?.status === 'NO_MATCH' ? 'No match after review' : 'Review recorded', tone: 'neutral', match: reviewed };
}

export function pageRows(rows, page, size = PAGE_SIZE) {
  return rows.slice(page * size, page * size + size);
}
