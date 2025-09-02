import { useEffect, useState } from 'react';
import { api } from '../lib/api';

export default function Users(){
  const [users,setUsers] = useState<any[]>([]);
  useEffect(()=>{ api('/users').then(setUsers).catch(console.error); },[]);
  return (
    <div>
      <h2 className="text-lg font-semibold mb-3">Usuários</h2>
      <table className="w-full bg-white border rounded-2xl overflow-hidden">
        <thead className="bg-gray-50">
          <tr><th className="text-left p-2">Nome</th><th className="text-left p-2">Email</th></tr>
        </thead>
        <tbody>
          {users.map(u=> (
            <tr key={u.id} className="border-t">
              <td className="p-2">{u.name}</td><td className="p-2">{u.email}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}