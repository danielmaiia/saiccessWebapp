export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

export async function api(path: string, opts: RequestInit = {}) {
  const token = localStorage.getItem('token');
  const headers = new Headers(opts.headers);
  headers.set('Content-Type','application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  headers.set('X-Tenant', localStorage.getItem('tenant') || 'acme');
  const res = await fetch(`${API_URL}${path}`, { ...opts, headers });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}