import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { Loading } from '../components/ui';
export default function ProtectedRoute() { const { session, loading } = useAuth(); const location = useLocation(); if (loading) return <Loading />; return session ? <Outlet /> : <Navigate to="/login" state={{ from: location.pathname }} replace />; }
