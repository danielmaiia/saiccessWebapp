import { Outlet, useNavigate } from 'react-router-dom';
import Shell from './components/Shell';
import { useEffect } from 'react';
import { useAuth } from './lib/store';

export default function App() {
  const nav = useNavigate();
  const { token } = useAuth();
  useEffect(()=>{ if(!localStorage.getItem('token')) nav('/login'); },[token]);
  return <Shell><Outlet/></Shell>;
}