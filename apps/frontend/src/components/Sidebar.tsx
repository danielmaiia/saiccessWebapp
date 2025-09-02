import { Link, useLocation } from 'react-router-dom';
import { Shield, Users, KeyRound, GitBranch, ClipboardList, Wand2, Settings } from 'lucide-react';

const items = [
  { to:'/', label:'Dashboard', icon: Shield },
  { to:'/users', label:'Usuários', icon: Users },
  { to:'/roles', label:'Papéis (RBAC)', icon: KeyRound },
  { to:'/policies', label:'Políticas (SoD)', icon: GitBranch },
  { to:'/reviews', label:'Revisões de Acesso', icon: ClipboardList },
  { to:'/suggestions', label:'Sugestões (IA)', icon: Wand2 },
  { to:'/settings', label:'Configurações', icon: Settings }
];

export default function Sidebar(){
  const loc = useLocation();
  return (
    <aside className="w-64 border-r bg-white h-[calc(100vh-56px)] sticky top-14">
      <nav className="p-3 space-y-1">
        {items.map(({to,label,icon:Icon})=> (
          <Link key={to} to={to} className={`flex items-center gap-2 px-3 py-2 rounded-lg hover:bg-gray-100 ${loc.pathname===to? 'bg-gray-100 font-medium':''}`}>
            <Icon size={18}/> {label}
          </Link>
        ))}
      </nav>
    </aside>
  );
}