import { useEffect, useRef, useState } from 'react';
import { NavLink, Outlet, Link, useLocation, useNavigate } from 'react-router-dom';
import { Shield, Search, Bell, ChevronDown, LogOut, Menu, X, ArrowUpRight } from 'lucide-react';
import { navigation } from '../utils/navigation';
import { useAuth } from '../hooks/useAuth';
export default function Workspace() {
  const [drawer, setDrawer] = useState(false); const [query, setQuery] = useState('');
  const sidebar = useRef(null); const drawerTrigger = useRef(null);
  useEffect(() => {
    if (!drawer) return;
    const trigger = drawerTrigger.current;
    const previousOverflow = document.body.style.overflow; document.body.style.overflow = 'hidden';
    const focusables = () => [...sidebar.current.querySelectorAll('a,button')].filter(el => el.getClientRects().length > 0);
    focusables()[0]?.focus();
    function handleKey(e) {
      if (e.key === 'Escape') { setDrawer(false); return; }
      if (e.key !== 'Tab') return;
      const items = focusables(); const first = items[0]; const last = items.at(-1);
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last?.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus(); }
    }
    document.addEventListener('keydown', handleKey);
    return () => { document.body.style.overflow = previousOverflow; document.removeEventListener('keydown', handleKey); trigger?.focus(); };
  }, [drawer]);
  const { session, logout } = useAuth(); const location = useLocation(); const navigate = useNavigate();
  const active = navigation.find(n => n.path === location.pathname);
  const results = query.trim() ? navigation.filter(n => n.label.toLowerCase().includes(query.toLowerCase())) : [];
  return <div className="workspace">
    {drawer && <button className="drawer-backdrop" aria-label="Close navigation" onClick={() => setDrawer(false)} />}
    <aside ref={sidebar} className={`sidebar ${drawer ? 'open' : ''}`} role={drawer ? 'dialog' : undefined} aria-modal={drawer || undefined} aria-label={drawer ? 'Workspace navigation' : undefined}><Link className="brand" to="/dashboard" onClick={() => setDrawer(false)}><span className="brand-icon"><Shield size={23} /></span><span>Cyber<span className="brand-accent">Intel</span><small>THREAT INTELLIGENCE</small></span></Link><button className="mobile-close icon-button" aria-label="Close navigation" onClick={() => setDrawer(false)}><X /></button>
      <nav aria-label="Main navigation">{navigation.map(({ path, label, icon: Icon, group, count }) => <div key={path}>{group && <div className="nav-group">{group}</div>}<NavLink to={path} onClick={() => setDrawer(false)}><Icon size={18} /><span>{label}</span>{count && <span className="nav-count">{count}</span>}</NavLink></div>)}</nav>
      <div className="sidebar-bottom"><div className="status-dot" /><span>Foundation environment<small>Sample data · Step 01</small></span><ArrowUpRight size={15} /></div>
      <div className="profile"><span className="avatar">{session.user.name.split(' ').map(n => n[0]).slice(0, 2).join('')}</span><div><strong>{session.user.name}</strong><small>{session.user.role === 'ADMIN' ? 'Administrator' : session.user.role}</small></div><button className="icon-button" aria-label="Sign out" title="Sign out" onClick={logout}><LogOut size={17} /></button></div>
    </aside>
    <div className="main-shell" inert={drawer || undefined}><header className="topbar"><button ref={drawerTrigger} className="mobile-menu icon-button" aria-label="Open navigation" onClick={() => setDrawer(true)}><Menu /></button><div className="breadcrumb">Workspace <span>/</span> <strong>{active?.label || 'Page not found'}</strong></div><div className="top-actions"><div className="global-search"><Search size={16} /><input aria-label="Search workspace pages" placeholder="Search workspace…" value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => { if (e.key === 'Escape') setQuery(''); if (e.key === 'Enter' && results[0]) { navigate(results[0].path); setQuery(''); } }} /><kbd>↵</kbd>{query && <div className="search-results">{results.length ? results.map(n => <Link key={n.path} to={n.path} onClick={() => setQuery('')}>{n.label}<ArrowUpRight size={14} /></Link>) : <p>No pages found</p>}</div>}</div><span className="environment"><i />{session.demo ? 'Demo workspace' : 'API connected'}</span><Link className="notification icon-button" aria-label="View sample alerts" to="/alerts"><Bell size={19} /><i /></Link><Link className="top-avatar" aria-label="Account settings" to="/settings">{session.user.name.charAt(0)}<ChevronDown size={12} /></Link></div></header><main className="page-container"><Outlet /></main><footer>CYBERINTEL <span>Reverse Engineering Based Cyber Threat Intelligence Platform</span><span>Foundation v0.1.0</span></footer></div>
  </div>;
}

