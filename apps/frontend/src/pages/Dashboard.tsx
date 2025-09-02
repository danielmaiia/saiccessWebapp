export default function Dashboard(){
  return (
    <div className="grid md:grid-cols-3 gap-4">
      <Card title="Usuários Ativos" value="42"/>
      <Card title="Papéis" value="12"/>
      <Card title="Alertas SoD" value="3"/>
    </div>
  );
}

function Card({title,value}:{title:string;value:string}){
  return (
    <div className="bg-white border rounded-2xl p-4 shadow-sm">
      <div className="text-sm text-gray-500">{title}</div>
      <div className="text-3xl font-semibold">{value}</div>
    </div>
  );
}