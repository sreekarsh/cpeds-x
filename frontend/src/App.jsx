import { useState, useEffect } from 'react'
import { Activity, Brain, BarChart3, Network, UploadCloud, Swords, History, Radio, TerminalSquare } from 'lucide-react'
import Header from './components/Header'
import AttackSimulator from './components/AttackSimulator'
import ScenarioRunner from './components/ScenarioRunner'
import LogAnalysis from './components/LogAnalysis'
import LiveContainment from './components/LiveContainment'
import IncidentHistory from './components/IncidentHistory'
import XAIView from './components/XAIView'
import MetricsView from './components/MetricsView'
import AttackMap from './components/AttackMap'
import TerminalDeck from './components/TerminalDeck'
import AuthScreen from './components/auth/AuthScreen'
import { useAuth } from './context/AuthContext'
import { checkHealth } from './api'

export default function App() {
  const { isAuthenticated, initializing } = useAuth()
  const [activeTab, setActiveTab] = useState('simulator')
  const [selectedIncident, setSelectedIncident] = useState(null)
  const [serverStatus, setServerStatus] = useState('checking')

  // Check backend health on mount (uses VITE_API_BASE_URL, works in prod too).
  // /health is public, so this runs whether or not the user is signed in.
  useEffect(() => {
    checkHealth()
      .then(() => setServerStatus('active'))
      .catch(() => setServerStatus('offline'))
  }, [])

  const tabs = [
    { id: 'simulator', label: 'Attack Simulator', icon: Activity },
    { id: 'scenarios', label: 'Scenario Runner', icon: Swords },
    { id: 'analysis', label: 'Log Analysis', icon: UploadCloud },
    { id: 'live', label: 'Live Containment', icon: Radio },
    { id: 'history', label: 'Incident History', icon: History },
    { id: 'xai', label: 'XAI Breakdown', icon: Brain },
    { id: 'map', label: 'Attack Map', icon: Network },
    { id: 'metrics', label: 'Model Metrics', icon: BarChart3 },
    { id: 'terminal', label: 'Terminal', icon: TerminalSquare },
  ]

  // While restoring a saved session, show a minimal splash to avoid flicker.
  if (initializing) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-cyber-bg text-gray-500">
        <div className="flex items-center gap-3">
          <span className="h-5 w-5 animate-spin rounded-full border-2 border-cyber-border border-t-cyber-accent" />
          <span className="font-mono-soc text-xs uppercase tracking-widest">Loading console…</span>
        </div>
      </div>
    )
  }

  // Gate: unauthenticated users see the secure-access screen.
  if (!isAuthenticated) {
    return <AuthScreen serverStatus={serverStatus} />
  }

  return (
    <div className="min-h-screen bg-cyber-bg text-gray-100">
      <Header status={serverStatus} />

      {/* Tab Navigation */}
      <div className="border-b border-cyber-border bg-cyber-panel">
        <div className="max-w-7xl mx-auto px-6">
          <div className="flex gap-1">
            {tabs.map(tab => {
              const Icon = tab.icon
              const active = activeTab === tab.id
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`
                    flex items-center gap-2 px-4 py-3 border-b-2 transition-colors
                    ${active
                      ? 'border-cyber-accent text-cyber-accent'
                      : 'border-transparent text-gray-400 hover:text-gray-200'}
                  `}
                >
                  <Icon size={18} />
                  <span className="font-medium">{tab.label}</span>
                </button>
              )
            })}
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-6 py-8">
        {activeTab === 'simulator' && (
          <AttackSimulator
            onIncidentSelect={(inc) => {
              setSelectedIncident(inc)
              setActiveTab('xai')
            }}
          />
        )}
        {activeTab === 'scenarios' && (
          <ScenarioRunner
            onIncidentSelect={(inc) => {
              setSelectedIncident(inc)
              setActiveTab('xai')
            }}
          />
        )}
        {activeTab === 'analysis' && (
          <LogAnalysis
            onIncidentSelect={(inc) => {
              setSelectedIncident(inc)
              setActiveTab('xai')
            }}
          />
        )}
        {activeTab === 'live' && (
          <LiveContainment
            onIncidentSelect={(inc) => {
              setSelectedIncident(inc)
              setActiveTab('xai')
            }}
          />
        )}
        {activeTab === 'history' && (
          <IncidentHistory
            onIncidentSelect={(inc) => {
              setSelectedIncident(inc)
              setActiveTab('xai')
            }}
          />
        )}
        {activeTab === 'xai' && <XAIView incident={selectedIncident} />}
        {activeTab === 'map' && <AttackMap incident={selectedIncident} />}
        {activeTab === 'metrics' && <MetricsView />}
        {/* Terminal stays mounted (just hidden) so open consoles, their
            scrollback, and any running command survive leaving and returning to
            this tab. */}
        <div className={activeTab === 'terminal' ? '' : 'hidden'}>
          <TerminalDeck
            active={activeTab === 'terminal'}
            onIncidentSelect={(inc) => {
              setSelectedIncident(inc)
              setActiveTab('xai')
            }}
          />
        </div>
      </div>
    </div>
  )
}
