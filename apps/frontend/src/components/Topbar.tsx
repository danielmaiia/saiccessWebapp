export default function Topbar(){
  return (
    <header className="h-14 border-b bg-white flex items-center px-4 justify-between sticky top-0 z-10">
      <div className="font-semibold">SAIccess</div>
      <div className="text-sm text-gray-500">Multi-tenant • Zero Trust • RBAC</div>
    </header>
  );
}