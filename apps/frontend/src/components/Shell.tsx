import Sidebar from './Sidebar';
import Topbar from './Topbar';

export default function Shell({ children }: { children: React.ReactNode }){
  return (
    <div className="min-h-screen bg-gray-50 text-gray-900">
      <Topbar />
      <div className="flex">
        <Sidebar />
        <main className="flex-1 p-6">{children}</main>
      </div>
    </div>
  );
}