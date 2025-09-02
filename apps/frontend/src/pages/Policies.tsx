import { useEffect, useState } from 'react';
import { api } from '../lib/api';

export default function Policies(){
  const [policies,setPolicies] = useState<any[]>([]);
  useEffect(()=>{ api('/policies').then(setPolicies); },[]);
  return (
    <div>
      <h2 className="text-lg font-semibold mb-3">Políticas (SoD)</h2>
      <ul className="space-y-2">
        {policies.map(p=> (
          <li key={p.id} className="bg-white border rounded-2xl p-3">
            <div className="font-medium">{p.name}</div>
            <pre className="text-xs text-gray-500 mt-1">{JSON.stringify(p.rule,null,2)}</pre>
          </li>
        ))}
      </ul>
    </div>
  );
}