import { useState, useEffect, useCallback } from 'react'
import Header from './components/Header'
import StatsBar from './components/StatsBar'
import Nav from './components/Nav'
import SessionList from './components/SessionList'
import EventFeed from './components/EventFeed'
import ChainStatePanel from './components/ChainStatePanel'
import RoutingTable from './components/RoutingTable'
import ThreatPanel from './components/ThreatPanel'
import RulesPanel from './components/RulesPanel'
import BackendsPanel from './components/BackendsPanel'
import AnomalyPanel from './components/AnomalyPanel'
import ScenariosPanel from './components/ScenariosPanel'
import ToolChangesPanel from './components/ToolChangesPanel'
import { fetchSessions, fetchStats } from './api'
import { createWebSocket } from './ws'

const MONITOR_TABS = [
  { id: 'events', label: 'Events' },
  { id: 'chain', label: 'Chain State' },
  { id: 'routing', label: 'Routing Table' },
]

export default function App() {
  const [page, setPage] = useState('monitor')
  const [sessions, setSessions] = useState([])
  const [stats, setStats] = useState(null)
  const [selectedSession, setSelectedSession] = useState(null)
  const [monitorTab, setMonitorTab] = useState('events')
  const [liveEvents, setLiveEvents] = useState([])
  const [wsStatus, setWsStatus] = useState('connecting')
  const [refreshToken, setRefreshToken] = useState(0)

  const refresh = useCallback(async () => {
    try {
      const [s, st] = await Promise.all([fetchSessions(), fetchStats()])
      setSessions(s)
      setStats(st)
      setRefreshToken((prev) => prev + 1)
    } catch { /* API may not be running yet */ }
  }, [])

  useEffect(() => {
    refresh()
    const interval = setInterval(refresh, 5000)
    return () => clearInterval(interval)
  }, [refresh])

  useEffect(() => {
    const ws = createWebSocket({
      onOpen: () => setWsStatus('connected'),
      onClose: () => setWsStatus('disconnected'),
      onEvent: (event) => {
        setLiveEvents((prev) => [event, ...prev].slice(0, 1000))
        refresh()
      },
    })
    return () => ws.close()
  }, [refresh])

  const handleSelectSession = (sessionId) => {
    setSelectedSession((prev) => (prev === sessionId ? null : sessionId))
    setMonitorTab('events')
  }

  const handleRuntimeReset = () => {
    setSelectedSession(null)
    setLiveEvents([])
    refresh()
  }

  const showSidebar = page === 'monitor'

  return (
    <div className="flex flex-col h-screen overflow-hidden bg-gray-950">
      <Header wsStatus={wsStatus} />
      <StatsBar stats={stats} />

      <div className="flex flex-1 overflow-hidden">
        <Nav activePage={page} onNavigate={setPage} />

        {/* Session sidebar — only on Monitor page */}
        {showSidebar && (
          <aside className="w-64 flex-shrink-0 border-r border-gray-800 flex flex-col overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
              <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Sessions
              </span>
              {selectedSession && (
                <button
                  onClick={() => setSelectedSession(null)}
                  className="text-xs text-gray-500 hover:text-gray-300"
                >
                  Clear
                </button>
              )}
            </div>
            <div className="flex-1 overflow-y-auto">
              <SessionList
                sessions={sessions}
                selectedSession={selectedSession}
                onSelect={handleSelectSession}
              />
            </div>
          </aside>
        )}

        {/* Main content */}
        <main className="flex-1 flex flex-col overflow-hidden">
          {page === 'monitor' && (
            <>
              <div className="flex border-b border-gray-800 px-4 bg-gray-900">
                {MONITOR_TABS.map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setMonitorTab(tab.id)}
                    className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                      monitorTab === tab.id
                        ? 'border-blue-500 text-blue-400'
                        : 'border-transparent text-gray-400 hover:text-gray-200'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
                {selectedSession && (
                  <span className="ml-auto self-center text-xs text-gray-600 mono">
                    {selectedSession.slice(0, 8)}…
                  </span>
                )}
              </div>
              <div className="flex-1 overflow-hidden">
                {monitorTab === 'events' && (
                  <EventFeed
                    liveEvents={liveEvents}
                    selectedSession={selectedSession}
                    refreshToken={refreshToken}
                  />
                )}
                {monitorTab === 'chain' && (
                  <ChainStatePanel sessionId={selectedSession} />
                )}
                {monitorTab === 'routing' && <RoutingTable />}
              </div>
            </>
          )}

          {page === 'threats' && <ThreatPanel />}
          {page === 'rules' && <RulesPanel />}
          {page === 'backends' && (
            <BackendsPanel onRescan={refresh} onRuntimeReset={handleRuntimeReset} />
          )}
          {page === 'anomaly' && <AnomalyPanel />}
          {page === 'scenarios' && <ScenariosPanel />}
          {page === 'tool-changes' && <ToolChangesPanel />}
        </main>
      </div>
    </div>
  )
}
