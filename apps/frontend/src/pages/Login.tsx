import { useState } from 'react';
import { api } from '../lib/api';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/store';

export default function Login(){
  const [email,setEmail] = useState('admin@acme.test');
  const [password,setPassword] = useState('Admin@123');
  const [err,setErr] = useState<string|null>(null);
  const nav = useNavigate();
  const { setSession } = useAuth();

  async function submit(e: React.FormEvent){
    e.preventDefault();
    try{
      const res = await api('/auth/login',{ method:'POST', body: JSON.stringify({ email, password }) });
      setSession(res.user, res.access);
      localStorage.setItem('tenant','acme');
      nav('/');
    }catch(ex:any){ setErr(ex.message||'erro'); }
  }

  return (
    <div className="min-h-screen grid place-items-center bg-gray-50">
      <form onSubmit={submit} className="bg-white border rounded-2xl shadow p-6 w-96 space-y-4">
        <h1 className="text-xl font-semibold">Entrar</h1>
        {err && <div className="text-red-600 text-sm">{err}</div>}
        <input className="w-full border rounded px-3 py-2" value={email} onChange={e=>setEmail(e.target.value)} placeholder="email"/>
        <input type="password" className="w-full border rounded px-3 py-2" value={password} onChange={e=>setPassword(e.target.value)} placeholder="senha"/>
        <button className="w-full bg-black text-white rounded px-3 py-2">Acessar</button>
      </form>
    </div>
  );
}