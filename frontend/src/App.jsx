import { useEffect, useState, useCallback } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link } from 'react-router-dom';
import { AuthContext } from './hooks/useAuth';
import { readSession, saveSession, clearSession } from './utils/session';
import { login, register, getCurrentUser } from './api/authApi';
import ProtectedRoute from './routes/ProtectedRoute';
import Workspace from './layouts/Workspace';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import ModulePage from './pages/ModulePage';
import ApkAnalysis from './pages/ApkAnalysis';
import UrlScanner from './pages/UrlScanner';
import PhishingDetection from './pages/PhishingDetection';
import IocExplorer from './pages/IocExplorer';
import EndpointMonitoring from './pages/EndpointMonitoring';
import { navigation } from './utils/navigation';
export default function App() {
  const [session, setSession] = useState(readSession); const [loading, setLoading] = useState(true);
  const logout = useCallback(() => { clearSession(); setSession(null); }, []);
  useEffect(() => { let active = true; const initial = readSession(); if (initial && !initial.demo) getCurrentUser().then(user => { if (active) setSession(s => s ? { ...s, user } : null); }).catch(() => { if (active) logout(); }).finally(() => { if (active) setLoading(false); }); else setLoading(false); return () => { active = false; }; }, [logout]);
  useEffect(() => { window.addEventListener('auth-expired', logout); const timer = session ? setTimeout(logout, Math.max(0, Math.min(session.expiresAt - Date.now(), 2147483647))) : null; return () => { window.removeEventListener('auth-expired', logout); clearTimeout(timer); }; }, [session, logout]);
  async function signIn(credentials, remember) { const data = await login(credentials); setSession(saveSession(data, remember)); }
  async function signUp(details, remember) { const data = await register(details); setSession(saveSession(data, remember)); }
return <AuthContext.Provider value={{ session, loading, logout, signIn, signUp }}><BrowserRouter><Routes><Route path="/login" element={<Login />} /><Route element={<ProtectedRoute />}><Route element={<Workspace />}><Route index element={<Navigate to="/dashboard" replace />} /><Route path="/dashboard" element={<Dashboard />} /><Route path="/apk-analysis" element={<ApkAnalysis />} /><Route path="/url-scanner" element={<UrlScanner />} /><Route path="/phishing" element={<PhishingDetection />} /><Route path="/ioc-explorer" element={<IocExplorer />} /><Route path="/endpoint-monitoring" element={<EndpointMonitoring />} />{navigation.filter(n => !['/dashboard', '/apk-analysis', '/url-scanner', '/phishing', '/ioc-explorer', '/endpoint-monitoring'].includes(n.path)).map(n => <Route key={n.path} path={n.path} element={<ModulePage key={n.path} module={n} />} />)}<Route path="*" element={<div className="state"><h1>Page not found</h1><p>This workspace page does not exist.</p><Link className="button primary" to="/dashboard">Return to dashboard</Link></div>} /></Route></Route></Routes></BrowserRouter></AuthContext.Provider>;
}
