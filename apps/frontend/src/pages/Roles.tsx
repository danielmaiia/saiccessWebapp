import { useEffect, useState } from 'react';
import { api } from '../lib/api';

export default function Roles(){
  const [roles,setRoles] = useState<any[]>([]);
  useEffect(()=>{ api('/roles').then(setRoles); },[]);
  return (
    <div>
      <h2 className="text-lg font-semibold mb-3">Papéis (RBAC)</h2>
      <div className="grid md:grid-cols-2 gap-3">
        {roles.map(r=> (
          <div key={r.id} className="bg-white border rounded-2xl p-4">
            <div className="font-medium">{r.name}</div>
            <div className="text-xs text-gray-500">{r.key}</div>
            <ul className="mt-2 text-sm list-disc list-inside">
              {r.grants.map((g:any)=> <li key={g.id}>{g.effect}:{g.action}@{g.resource}</li>)}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}