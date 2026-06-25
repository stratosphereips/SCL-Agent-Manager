import { NavLink, Outlet, useLocation } from 'react-router-dom';
import {
  Bot,
  Settings,
  Sun,
  Moon,
  LayoutDashboard,
  Network,
  Search,
  Shield,
} from 'lucide-react';
import { ContainerStatusBar } from './ContainerStatusBar';
import { ReplayProvider, useReplayContext } from '@/contexts/ReplayContext';
import { useState, useEffect } from 'react';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/agents', icon: Bot, label: 'Agent Execution' },
  { to: '/topology', icon: Network, label: 'Topologies' },
  { to: '/discovery', icon: Search, label: 'Host Discovery' },
  { to: '/defender', icon: Shield, label: 'Defender' },
  { to: '/settings', icon: Settings, label: 'Settings' },
];

function LayoutContent() {
  const location = useLocation();

  // Theme management
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    const stored = localStorage.getItem('theme');
    if (stored === 'light' || stored === 'dark') return stored;
    // Default to dark mode
    return 'dark';
  });

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    localStorage.setItem('theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="flex w-64 flex-col border-r border-trident-border bg-trident-surface">
        {/* Logo */}
        <div className="flex items-center gap-3 border-b border-trident-border px-5 py-4">
          <div className="h-8 w-8 rounded-lg bg-trident-accent flex items-center justify-center">
            <span className="text-white font-bold text-sm">AM</span>
          </div>
          <div>
            <h1 className="font-heading text-lg font-bold tracking-tight text-trident-text">
              Agent Manager
            </h1>
            <p className="text-[10px] uppercase tracking-widest text-trident-muted">
              Dashboard
            </p>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 space-y-1 px-3 py-4">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/agents'}
              className={({ isActive }) =>
                `nav-link ${isActive ? 'active' : ''}`
              }
            >
              <Icon size={18} />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Theme toggle */}
        <div className="px-3 py-4 border-t border-trident-border">
          <button
            onClick={toggleTheme}
            className="nav-link w-full justify-start"
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
            {theme === 'dark' ? 'Light Mode' : 'Dark Mode'}
          </button>
        </div>

        {/* Status bar at bottom */}
        <ContainerStatusBar />
      </aside>

      {/* Main content */}
      <main className="flex-1 flex flex-col overflow-hidden bg-trident-bg text-trident-text">
        <div className="flex-1 overflow-auto p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

export function Layout() {
  return (
    <ReplayProvider>
      <LayoutContent />
    </ReplayProvider>
  );
}
