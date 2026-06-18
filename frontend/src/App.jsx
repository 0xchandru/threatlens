import { useState, useEffect } from 'react'
import { Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import LookupPage from './pages/LookupPage'
import SearchPage from './pages/SearchPage'
import ReportsPage from './pages/ReportsPage'

const NAV_ITEMS = [
  {
    to: '/', label: 'Dashboard', exact: true,
    icon: (
      <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
      </svg>
    ),
  },
  {
    to: '/lookup', label: 'IOC Lookup',
    icon: (
      <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
      </svg>
    ),
  },
  {
    to: '/search', label: 'Threat Hunt',
    icon: (
      <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    ),
  },
  {
    to: '/reports', label: 'Reports',
    icon: (
      <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
      </svg>
    ),
  },
]

function UtcClock() {
  const [time, setTime] = useState(() => new Date())
  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(id)
  }, [])
  return (
    <span className="font-mono text-xs" style={{ color: '#8892a4' }}>
      {time.toUTCString().slice(17, 25)} UTC
    </span>
  )
}

export default function App() {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <div className="flex min-h-screen" style={{ background: '#0a0e1a' }}>
      {/* Sidebar */}
      <aside
        className="sidebar-transition flex-shrink-0 flex flex-col"
        style={{
          width: collapsed ? 60 : 220,
          background: '#0f1629',
          borderRight: '1px solid rgba(255,255,255,0.06)',
          position: 'sticky',
          top: 0,
          height: '100vh',
          overflow: 'hidden',
        }}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-3 pt-5 pb-5" style={{ borderBottom: '1px solid rgba(255,255,255,0.06)', minHeight: 64 }}>
          <div className="flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ background: 'rgba(0,212,255,0.15)', border: '1px solid rgba(0,212,255,0.3)', boxShadow: '0 0 12px rgba(0,212,255,0.2)' }}>
            <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="#00d4ff" strokeWidth="2">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          {!collapsed && (
            <div>
              <div className="text-sm font-bold text-white tracking-wide">ThreatLens</div>
              <div className="text-xs" style={{ color: '#8892a4' }}>SOC Intelligence</div>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav className="flex-1 px-2 py-4 space-y-1">
          {NAV_ITEMS.map(({ to, label, icon, exact }) => (
            <NavLink
              key={to}
              to={to}
              end={exact}
              className={({ isActive }) =>
                `sidebar-nav-item ${isActive ? 'active' : ''}`
              }
              title={collapsed ? label : undefined}
            >
              <span className="flex-shrink-0">{icon}</span>
              {!collapsed && <span>{label}</span>}
            </NavLink>
          ))}
        </nav>

        {/* Collapse toggle */}
        <button
          onClick={() => setCollapsed(c => !c)}
          className="mx-2 mb-4 flex items-center justify-center rounded-lg p-2 transition-colors"
          style={{ color: '#8892a4', border: '1px solid rgba(255,255,255,0.06)' }}
          onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.04)'}
          onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2"
            style={{ transform: collapsed ? 'rotate(180deg)' : 'none', transition: 'transform 0.25s' }}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
          </svg>
          {!collapsed && <span className="ml-2 text-xs">Collapse</span>}
        </button>
      </aside>

      {/* Main */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="flex items-center justify-between px-6 py-3 flex-shrink-0"
          style={{ background: '#0f1629', borderBottom: '1px solid rgba(255,255,255,0.06)', minHeight: 56 }}>
          <div />
          <div className="flex items-center gap-4">
            <UtcClock />
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full" style={{ background: '#00ff88', boxShadow: '0 0 6px #00ff88' }} />
              <span className="text-xs" style={{ color: '#8892a4' }}>Systems Online</span>
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-auto p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/lookup" element={<LookupPage />} />
            <Route path="/search" element={<SearchPage />} />
            <Route path="/reports" element={<ReportsPage />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}
