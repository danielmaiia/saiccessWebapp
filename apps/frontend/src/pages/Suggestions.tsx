import { useEffect, useState } from 'react';
import { api } from '../lib/api';

export default function Suggestions(){
  const [items,setItems] = useState<any[]>([]);
  // Exemplo: consulta de sugestões para o admin seedado
  useEffect(()=>{ api('/suggestions/user/seed').then(setItems).catch(()=>setItems([])); },[]);
  return (
    <div>
      <h2 className="text-lg font-semibold mb-3">Sugestões (IA)</h2>
      {items.length===0? <div className="text-sm text-gray-500">Sem dados suficientes.</div> : (
        <ul className="space-y-2">
          {items.map(i=> (
            <li key={i.roleKey} className="bg-white border rounded-2xl p-3 flex items-center justify-between">
              <div>{i.roleKey}</div>
              <div className="text-xs text-gray-500">score {(i.score*100).toFixed(0)}%</div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}