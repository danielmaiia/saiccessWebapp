import React from 'react';
import ReactDOM from 'react-dom/client';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import './index.css';
import App from './App';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Tenants from './pages/Tenants';
import Users from './pages/Users';
import Roles from './pages/Roles';
import Policies from './pages/Policies';
import Reviews from './pages/Reviews';
import Suggestions from './pages/Suggestions';
import Settings from './pages/Settings';

const router = createBrowserRouter([
  { path: '/login', element: <Login /> },
  { path: '/', element: <App />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'tenants', element: <Tenants /> },
      { path: 'users', element: <Users /> },
      { path: 'roles', element: <Roles /> },
      { path: 'policies', element: <Policies /> },
      { path: 'reviews', element: <Reviews /> },
      { path: 'suggestions', element: <Suggestions /> },
      { path: 'settings', element: <Settings /> }
    ] }
]);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>
);