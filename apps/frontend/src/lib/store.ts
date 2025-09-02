import { create } from 'zustand';

type AuthState = {
  user: { id:string; email:string; name:string } | null;
  token: string | null;
  setSession: (u:any, t:string)=>void;
  clear: ()=>void;
};

export const useAuth = create<AuthState>((set)=>({
  user: null, token: null,
  setSession: (user, token)=>{ localStorage.setItem('token', token); set({ user, token }); },
  clear: ()=>{ localStorage.removeItem('token'); set({ user: null, token: null }); }
}));