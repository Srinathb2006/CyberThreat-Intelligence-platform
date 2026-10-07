import { useEffect, useRef } from 'react';
import { X, LoaderCircle, SearchX, TriangleAlert } from 'lucide-react';
export function Card({ children, className = '', ...props }) { return <section className={`panel ${className}`} {...props}>{children}</section>; }
export function Button({ children, variant = 'primary', className = '', ...props }) { return <button className={`button ${variant} ${className}`} {...props}>{children}</button>; }
export function Badge({ children, tone }) { return <span className={`badge ${tone || String(children).toLowerCase()}`}>{children}</span>; }
export function Loading() { return <div className="state" role="status"><LoaderCircle className="spin" size={26} /><h3>Loading your workspace</h3><p>Retrieving the latest view…</p></div>; }
export function EmptyState({ title = 'No matching results', message = 'Try a different search or clear your filters.' }) { return <div className="state"><SearchX size={30} /><h3>{title}</h3><p>{message}</p></div>; }
export function ErrorState({ message, retry }) { return <div className="state" role="alert"><TriangleAlert size={30} /><h3>Unable to load this view</h3><p>{message}</p>{retry && <Button onClick={retry}>Try again</Button>}</div>; }
export function Table({ columns, rows, onRowClick }) { return rows.length ? <div className="table-scroll"><table><thead><tr>{columns.map(c => <th key={c.key}>{c.label}</th>)}</tr></thead><tbody>{rows.map((row, i) => <tr key={row.id || i}>{columns.map((c, index) => <td key={c.key}>{index === 0 && onRowClick ? <button className="table-link" onClick={() => onRowClick(row)}>{c.render ? c.render(row) : row[c.key]}</button> : c.render ? c.render(row) : row[c.key]}</td>)}</tr>)}</tbody></table></div> : <EmptyState />; }
export function Modal({ title, children, onClose }) {
  const ref = useRef(null);
  useEffect(() => { const dialog = ref.current; dialog.showModal(); return () => dialog.close(); }, []);
  return <dialog ref={ref} onCancel={onClose} onClick={e => { if (e.target === ref.current) onClose(); }}><div className="modal-head"><h2>{title}</h2><button className="icon-button" aria-label="Close dialog" onClick={onClose}><X size={20} /></button></div>{children}</dialog>;
}
