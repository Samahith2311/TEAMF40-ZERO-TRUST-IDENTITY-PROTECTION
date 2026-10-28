import { useEffect, useState, useRef } from 'react'

interface EvidenceRef {
  source_file: string
  record_id: string
}

interface Alert {
  alert_id: string
  incident_id: string
  subject: {
    type: string
    id: string
  }
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  what: string
  why: string
  evidence_refs: EvidenceRef[]
  risk_score_ref: string
  impact: string
  recommended_action: string
  status: string
  first_seen: string
  last_seen: string
  dup_count: number
}

interface ChainStage {
  stage: string
  event_ref: string
  link_provenance: string
}

interface IncidentChain {
  incident_id: string
  stages: ChainStage[]
  links: string[]
  subject_ids: string[]
  confidence: number
}

interface RiskFactor {
  name: string
  weight: number
  value: number
  contribution: number
}

interface RiskScore {
  subject: { type: string; id: string }
  total: number
  factors: RiskFactor[]
  explanation: {
    top_factors: string[]
    counterfactual?: string
  }
}

interface GraphNode {
  id: string
  label: string
  type: string
  sensitivity: string
  metadata?: Record<string, any>
}

interface GraphEdge {
  from: string
  to: string
  type: string
  provenance: string
}

interface RankedPath {
  path_id: string
  subject: string
  target: string
  risk_level: string
  hops: { node: string; type: string }[]
  description: string
}

interface SyntheticAttackSummary {
  incident_id: string
  attack_type: string
  target_identity: string
  identity_name: string
  assumed_role: string
  escalated_policy: string
  target_resource: string
  risk_score: number
  recommended_action: string
  detected_rules: string[]
  active_weights: Record<string, number>
}

interface TuningLogEntry {
  id: string
  timestamp: string
  trigger: string
  target_identity: string
  detected_rules: string[]
  reasons: string[]
  previous_weights: Record<string, number>
  tuned_weights: Record<string, number>
  status: string
}

export default function App() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [chains, setChains] = useState<IncidentChain[]>([])
  const [scores, setScores] = useState<RiskScore[]>([])
  const [graphData, setGraphData] = useState<{ nodes: GraphNode[]; edges: GraphEdge[]; ranked_paths: RankedPath[] } | null>(null)
  const [weights, setWeights] = useState<Record<string, number>>({})
  const [syntheticHistory, setSyntheticHistory] = useState<SyntheticAttackSummary[]>([])
  const [tuningLog, setTuningLog] = useState<TuningLogEntry[]>([])
  const [generating, setGenerating] = useState<boolean>(false)
  const [autoStream, setAutoStream] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)
  const [notification, setNotification] = useState<string | null>(null)
  const [simResult, setSimResult] = useState<string | null>(null)
  const [stepUpPrompt, setStepUpPrompt] = useState<string | null>(null)
  const [maskIdentities, setMaskIdentities] = useState<boolean>(true)
  const [activeTab, setActiveTab] = useState<'details' | 'graph' | 'tuning'>('details')
  const [selectedArchetype, setSelectedArchetype] = useState<string>('RANDOM')

  // Interactive Bubble Inspector Popover State
  const [activeBubble, setActiveBubble] = useState<{
    id: string
    title: string
    type: string
    roleDesc: string
    attributes: Record<string, string>
    color: string
    icon: string
  } | null>(null)

  const selectedAlertRef = useRef<Alert | null>(null)
  selectedAlertRef.current = selectedAlert

  const formatIdentity = (id: string) => {
    if (!maskIdentities) return id
    if (id.includes('@')) {
      const parts = id.split('@')
      return `${parts[0].slice(0, 2)}***@${parts[1]}`
    }
    return `${id.slice(0, 3)}***`
  }

  const loadData = (selectNewest: boolean = false) => {
    Promise.all([
      fetch('http://127.0.0.1:8000/api/alerts').then(r => r.json()),
      fetch('http://127.0.0.1:8000/api/chains').then(r => r.json()),
      fetch('http://127.0.0.1:8000/api/scores').then(r => r.json()),
      fetch('http://127.0.0.1:8000/api/graph').then(r => r.json()),
      fetch('http://127.0.0.1:8000/api/feedback/weights').then(r => r.json()),
      fetch('http://127.0.0.1:8000/api/feedback/tuning-log').then(r => r.json()).catch(() => ({ tuning_log: [] })),
      fetch('http://127.0.0.1:8000/api/synthetic/history').then(r => r.json()).catch(() => ({ history: [] })),
      fetch('http://127.0.0.1:8000/api/synthetic/status').then(r => r.json()).catch(() => ({ auto_streaming: false }))
    ])
      .then(([alertData, chainData, scoreData, gData, wData, tData, hData, sData]) => {
        const alts: Alert[] = alertData.alerts || []
        setAlerts(alts)

        if (selectNewest && alts.length > 0) {
          setSelectedAlert(alts[alts.length - 1])
        } else if (!selectedAlertRef.current && alts.length > 0) {
          setSelectedAlert(alts[0])
        } else if (selectedAlertRef.current) {
          const matched = alts.find(a => a.alert_id === selectedAlertRef.current?.alert_id)
          if (matched) setSelectedAlert(matched)
        }

        setChains(chainData.chains || [])
        setScores(scoreData.scores || [])
        setGraphData(gData.graph || null)
        setWeights(wData.weights || {})
        setTuningLog(tData.tuning_log || [])
        setSyntheticHistory(hData.history || [])
        if (sData.auto_streaming !== undefined) {
          setAutoStream(sData.auto_streaming)
        }
      })
      .catch(err => {
        setError(err.message)
      })
  }

  useEffect(() => {
    loadData()
    // Poll every 3 seconds for synchronous real-time threat detection
    const interval = setInterval(() => {
      loadData(false)
    }, 3000)
    return () => clearInterval(interval)
  }, [])

  const handleGenerateAttack = (arch?: string) => {
    setGenerating(true)
    setError(null)
    const targetArch = arch && arch !== 'RANDOM' ? arch : (selectedArchetype !== 'RANDOM' ? selectedArchetype : undefined)

    fetch('http://127.0.0.1:8000/api/synthetic/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ archetype: targetArch })
    })
      .then(r => r.json())
      .then(res => {
        setGenerating(false)
        if (res.status === 'SUCCESS') {
          setNotification(`⚡ Threat [${res.attack_type}] generated against ${res.identity_name} • Graph & Weights Synced`)
          loadData(true)
        } else {
          setError(res.detail || 'Failed to generate synthetic attack')
        }
      })
      .catch(err => {
        setGenerating(false)
        setError(err.message)
      })
  }

  const handleToggleAutoStream = () => {
    const nextState = !autoStream
    fetch('http://127.0.0.1:8000/api/synthetic/auto', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: nextState, interval: 6.0 })
    })
      .then(r => r.json())
      .then(res => {
        setAutoStream(res.auto_streaming)
        setNotification(res.auto_streaming ? '▶ Auto-Streaming Threat Scenarios (Every 6s)' : '⏸ Auto-Streaming Paused')
        loadData()
      })
      .catch(err => setError(err.message))
  }

  const handleApprove = () => {
    if (!selectedAlert) return
    fetch('http://127.0.0.1:8000/api/actions/approve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        incident_id: selectedAlert.incident_id,
        action: selectedAlert.recommended_action,
        target: selectedAlert.subject.id,
        approver: 'lead_analyst@corp.internal'
      })
    })
      .then(res => res.json())
      .then(data => {
        setSimResult(data.action?.result || 'SUCCESS_SIMULATED')
      })
      .catch(err => setError(err.message))
  }

  const handleStepUp = () => {
    if (!selectedAlert) return
    fetch('http://127.0.0.1:8000/api/actions/step-up', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        incident_id: selectedAlert.incident_id,
        target: selectedAlert.subject.id
      })
    })
      .then(res => res.json())
      .then(data => {
        setStepUpPrompt(data.prompt || 'MFA challenge dispatched')
      })
      .catch(err => setError(err.message))
  }

  const activeChain = chains.find(c => c.incident_id === selectedAlert?.incident_id)
  const activeScore = scores.find(s => s.subject.id === selectedAlert?.subject.id)

  // Dynamically extract the active attack path for the currently selected incident
  const activePath = graphData?.ranked_paths.find(p => p.path_id.includes(selectedAlert?.incident_id || '')) ||
    (graphData?.ranked_paths && graphData.ranked_paths.length > 0 ? graphData.ranked_paths[0] : null)

  const hopIdentity = activePath ? activePath.hops[0]?.node : (selectedAlert?.subject.id || 'Identity')
  const hopRole = activePath ? activePath.hops[1]?.node : 'CloudRole'
  const hopPolicy = activePath ? activePath.hops[2]?.node : 'EscalatedPolicy'
  const hopResource = activePath ? activePath.hops[3]?.node : 'TargetResource'

  return (
    <div className="h-screen w-screen bg-black text-zinc-200 flex flex-col font-sans overflow-hidden select-none">
      {/* Top System Status & Utility Bar */}
      <div className="bg-[#08080b] border-b border-[#181820] px-4 py-1.5 text-center text-[11px] font-mono tracking-wider text-zinc-400 flex items-center justify-between shrink-0">
        <div className="flex items-center space-x-2.5">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
          <span className="text-zinc-300 font-medium">AEGIS ZERO TRUST IDENTITY ENGINE</span>
          <span className="text-zinc-600">•</span>
          <span className="text-zinc-500">SYNCHRONOUS MULTI-STAGE REPLAY & SYNTHETIC TELEMETRY</span>
        </div>

        {/* Top Right Utility Group */}
        <div className="flex items-center space-x-2 text-[10px] text-zinc-400 font-mono">
          <button
            onClick={() => setActiveTab('tuning')}
            className={`px-2.5 py-1 rounded-lg border text-xs font-mono transition-all flex items-center space-x-1.5 cursor-pointer ${
              activeTab === 'tuning'
                ? 'bg-cyan-950/80 border-cyan-500/70 text-cyan-200 shadow-[0_0_12px_rgba(56,189,248,0.2)]'
                : 'bg-[#0e121a] hover:bg-[#151d2a] border-cyan-800/40 text-cyan-300'
            }`}
            title="Open Model Tuning"
          >
            <span className="text-xs">⚙️</span>
            <span className="font-semibold">Model Tuning</span>
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
          </button>
          <span className="px-2 py-1 rounded bg-[#101017] border border-[#222230] text-cyan-300">FastAPI :8000</span>
          <span className="px-2 py-1 rounded bg-[#101017] border border-[#222230] text-emerald-400">Engine Live</span>
        </div>
      </div>

      {/* Floating Notification Toast */}
      {notification && (
        <div className="bg-[#0c121e]/95 border-b border-cyan-800/40 px-4 py-1.5 text-xs font-mono text-cyan-200 flex items-center justify-between shrink-0 backdrop-blur">
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
            <span>{notification}</span>
          </div>
          <button onClick={() => setNotification(null)} className="text-cyan-400 hover:text-white px-2 cursor-pointer">✕</button>
        </div>
      )}

      {/* Main 3-Column Workstation */}
      <div className="flex-1 flex overflow-hidden">
        {/* ==============================================================
            LEFT COLUMN: Embedded Options with Lift-Up Hover Effect
           ============================================================== */}
        <aside className="w-80 shrink-0 border-r border-[#16161e] bg-[#050508] flex flex-col p-4 space-y-4 overflow-y-auto">
          {/* Brand Logo & Title with In-Tab Logo */}
          <div className="flex items-center space-x-3 pb-3 border-b border-[#181822]">
            <div className="relative w-10 h-10 shrink-0 flex items-center justify-center">
              <svg viewBox="0 0 48 48" className="w-10 h-10 drop-shadow-md">
                <defs>
                  <linearGradient id="softShieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#38bdf8" />
                    <stop offset="50%" stopColor="#2dd4bf" />
                    <stop offset="100%" stopColor="#a78bfa" />
                  </linearGradient>
                  <radialGradient id="softCoreGrad" cx="50%" cy="50%" r="50%">
                    <stop offset="0%" stopColor="#7dd3fc" />
                    <stop offset="100%" stopColor="#0f172a" />
                  </radialGradient>
                </defs>
                <path
                  d="M24 5 L40 11 C40 25 33 37 24 43 C15 37 8 25 8 11 Z"
                  fill="#030305"
                  stroke="url(#softShieldGrad)"
                  strokeWidth="2.2"
                />
                <circle cx="24" cy="24" r="7" fill="url(#softCoreGrad)" opacity="0.9" />
                <path d="M24 16 L24 32 M16 24 L32 24" stroke="#ffffff" strokeWidth="1.2" strokeLinecap="round" />
                <circle cx="24" cy="24" r="2.5" fill="#ffffff" />
                <circle cx="17" cy="19" r="1.5" fill="#38bdf8" />
                <circle cx="31" cy="19" r="1.5" fill="#a78bfa" />
              </svg>
            </div>
            <div>
              <div className="flex items-center space-x-1.5">
                <span className="font-extrabold text-sm tracking-tight text-white font-mono">AEGIS // ZERO</span>
                <span className="px-1.5 py-0.2 rounded bg-[#101624] text-cyan-300 text-[9px] font-mono border border-cyan-800/40">ZT-2</span>
              </div>
              <p className="text-[10px] text-zinc-400 font-mono">Identity Threat Protection</p>
            </div>
          </div>

          {/* Embedded Navigation Options (Lift-Up on Hover) */}
          <div className="space-y-2.5">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-zinc-400 px-1">
              Modules
            </span>

            {/* Option 1: Incident Queue */}
            <div
              onClick={() => setActiveTab('details')}
              className={`group cursor-pointer rounded-xl p-3 border transition-all duration-300 ease-out hover:-translate-y-1.5 hover:shadow-[0_12px_24px_-6px_rgba(56,189,248,0.18)] ${
                activeTab === 'details'
                  ? 'bg-[#10141e] border-cyan-500/50 shadow-[0_4px_16px_rgba(56,189,248,0.12)]'
                  : 'bg-[#09090d] border-[#181822] shadow-[inset_0_2px_4px_rgba(0,0,0,0.8)] hover:border-cyan-500/40 hover:bg-[#0f1118]'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-sm transition-transform duration-300 group-hover:scale-110 ${
                    activeTab === 'details' ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-700/50' : 'bg-[#121218] text-zinc-400 border border-[#20202a]'
                  }`}>
                    📋
                  </div>
                  <div>
                    <h4 className={`text-xs font-semibold tracking-wide ${activeTab === 'details' ? 'text-white' : 'text-zinc-300 group-hover:text-white'}`}>
                      Incident Queue
                    </h4>
                    <p className="text-[10px] text-zinc-400">Correlated threat alerts</p>
                  </div>
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
                  activeTab === 'details' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/50' : 'bg-[#15151e] text-zinc-400'
                }`}>
                  {alerts.length}
                </span>
              </div>
            </div>

            {/* Option 2: Live Attack Graph */}
            <div
              onClick={() => setActiveTab('graph')}
              className={`group cursor-pointer rounded-xl p-3 border transition-all duration-300 ease-out hover:-translate-y-1.5 hover:shadow-[0_12px_24px_-6px_rgba(56,189,248,0.18)] ${
                activeTab === 'graph'
                  ? 'bg-[#10141e] border-cyan-500/50 shadow-[0_4px_16px_rgba(56,189,248,0.12)]'
                  : 'bg-[#09090d] border-[#181822] shadow-[inset_0_2px_4px_rgba(0,0,0,0.8)] hover:border-cyan-500/40 hover:bg-[#0f1118]'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-sm transition-transform duration-300 group-hover:scale-110 ${
                    activeTab === 'graph' ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-700/50' : 'bg-[#121218] text-zinc-400 border border-[#20202a]'
                  }`}>
                    🕸️
                  </div>
                  <div>
                    <h4 className={`text-xs font-semibold tracking-wide ${activeTab === 'graph' ? 'text-white' : 'text-zinc-300 group-hover:text-white'}`}>
                      Live Attack Graph
                    </h4>
                    <p className="text-[10px] text-zinc-400">Interactive bubble canvas</p>
                  </div>
                </div>
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
              </div>
            </div>

            {/* Option 3: Model Tuning */}
            <div
              onClick={() => setActiveTab('tuning')}
              className={`group cursor-pointer rounded-xl p-3 border transition-all duration-300 ease-out hover:-translate-y-1.5 hover:shadow-[0_12px_24px_-6px_rgba(56,189,248,0.18)] ${
                activeTab === 'tuning'
                  ? 'bg-[#10141e] border-cyan-500/50 shadow-[0_4px_16px_rgba(56,189,248,0.12)]'
                  : 'bg-[#09090d] border-[#181822] shadow-[inset_0_2px_4px_rgba(0,0,0,0.8)] hover:border-cyan-500/40 hover:bg-[#0f1118]'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-sm transition-transform duration-300 group-hover:scale-110 ${
                    activeTab === 'tuning' ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-700/50' : 'bg-[#121218] text-zinc-400 border border-[#20202a]'
                  }`}>
                    ⚙️
                  </div>
                  <div>
                    <h4 className={`text-xs font-semibold tracking-wide ${activeTab === 'tuning' ? 'text-white' : 'text-zinc-300 group-hover:text-white'}`}>
                      Model Tuning
                    </h4>
                    <p className="text-[10px] text-zinc-400">Autonomous calibration</p>
                  </div>
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
                  activeTab === 'tuning' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/50' : 'bg-[#15151e] text-emerald-400'
                }`}>
                  Auto
                </span>
              </div>
            </div>
          </div>

          {/* Embedded Threat Generator Console (Lift-Up on Hover) */}
          <div className="group rounded-xl p-3.5 border border-[#1a1a24] bg-[#08080c] shadow-[inset_0_2px_4px_rgba(0,0,0,0.8)] transition-all duration-300 hover:-translate-y-1 hover:shadow-[0_12px_24px_-6px_rgba(56,189,248,0.14)] hover:border-cyan-500/40 hover:bg-[#0d0e14] space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-zinc-400">
                Threat Generator
              </span>
              <span className="text-[10px] font-mono text-cyan-400/90">Autonomous</span>
            </div>

            <div className="space-y-2">
              <label className="text-[10px] text-zinc-400 font-mono block">Threat Archetype:</label>
              <select
                value={selectedArchetype}
                onChange={e => setSelectedArchetype(e.target.value)}
                className="w-full bg-[#121218] border border-[#242432] text-zinc-200 text-xs rounded-lg px-2.5 py-1.5 outline-none font-mono cursor-pointer focus:border-cyan-500/50"
              >
                <option value="RANDOM">🎲 Random Threat Archetype</option>
                <option value="DORMANT_PRIV_ESCALATION">🛡️ Dormant Account Escalation</option>
                <option value="IMPOSSIBLE_TRAVEL_TOKEN_HIJACK">✈️ Impossible Travel & Hijack</option>
                <option value="LATERAL_ROLE_PIVOT_EXFIL">🔄 Lateral Role Pivot & Exfil</option>
                <option value="UNUSUAL_AUTOMATED_API_SWEEP">⚡ Unusual Automated API Sweep</option>
              </select>

              <button
                onClick={() => handleGenerateAttack()}
                disabled={generating}
                className="w-full py-2 px-3 rounded-lg text-xs font-semibold bg-gradient-to-r from-sky-600/80 to-teal-600/80 hover:from-sky-500/90 hover:to-teal-500/90 disabled:opacity-40 text-white shadow-sm transition-all cursor-pointer flex items-center justify-center space-x-2"
              >
                <span>{generating ? 'Synthesizing...' : '⚡ Generate Attack'}</span>
              </button>

              <button
                onClick={handleToggleAutoStream}
                className={`w-full py-1.5 px-3 rounded-lg text-xs font-medium border transition-all cursor-pointer flex items-center justify-center space-x-2 ${
                  autoStream
                    ? 'bg-emerald-950/60 border-emerald-600/60 text-emerald-300'
                    : 'bg-[#121218] border-[#22222e] hover:border-[#303040] text-zinc-300'
                }`}
              >
                <span className={`w-2 h-2 rounded-full ${autoStream ? 'bg-emerald-400 animate-ping' : 'bg-zinc-600'}`}></span>
                <span>{autoStream ? 'Streaming Active (6s)' : '▶ Auto-Stream Attacks'}</span>
              </button>
            </div>
          </div>

          {/* Embedded Privacy Control (Lift-Up on Hover) */}
          <div className="pt-2 border-t border-[#181822] space-y-2 mt-auto">
            <button
              onClick={() => setMaskIdentities(!maskIdentities)}
              className="w-full py-2 px-3 rounded-xl border border-[#1a1a24] bg-[#08080c] shadow-[inset_0_2px_4px_rgba(0,0,0,0.8)] hover:-translate-y-1 hover:border-cyan-500/40 hover:bg-[#0d0e14] transition-all duration-300 cursor-pointer flex items-center justify-between"
            >
              <span className="font-mono text-[11px] text-zinc-300">Identity Privacy</span>
              <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded bg-[#121218] text-cyan-300 border border-[#222230]">
                {maskIdentities ? '🔒 Masked' : '👁️ Unmasked'}
              </span>
            </button>
            <div className="text-[10px] font-mono text-zinc-400 text-center">
              Zero Trust Track 2 Engine • Pure Dark
            </div>
          </div>
        </aside>

        {/* ==============================================================
            MIDDLE COLUMN: Core Working Stage (Incidents & Bubble Graph)
           ============================================================== */}
        <main className="flex-1 overflow-y-auto p-6 space-y-6 bg-black">
          {error && (
            <div className="p-3.5 border border-rose-900/50 bg-[#160a0d] rounded-xl text-xs text-rose-300 flex items-center justify-between font-mono">
              <span>{error}</span>
              <button onClick={() => setError(null)} className="text-rose-400 hover:text-white px-2 cursor-pointer">✕</button>
            </div>
          )}

          {/* --- TAB 1: INCIDENTS --- */}
          {activeTab === 'details' && (
            <div className="space-y-6">
              {selectedAlert ? (
                <>
                  {/* Selected Incident Header */}
                  <div className="p-6 border border-[#1c1c26] rounded-2xl bg-[#08080c] space-y-3 shadow-sm">
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
                            {selectedAlert.alert_id}
                          </span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                            selectedAlert.severity === 'CRITICAL'
                              ? 'bg-[#220a0d] text-rose-300 border-rose-800/50'
                              : 'bg-[#221606] text-amber-300 border-amber-800/50'
                          }`}>
                            {selectedAlert.severity}
                          </span>
                        </div>
                        <h2 className="text-lg font-bold text-white mt-1.5">{selectedAlert.what}</h2>
                        <p className="text-xs text-zinc-400 mt-1">{selectedAlert.why}</p>
                      </div>
                      <div className="text-right font-mono text-[11px] text-zinc-400">
                        <div>First Seen: <span className="text-zinc-300">{selectedAlert.first_seen}</span></div>
                        <div>Last Seen: <span className="text-zinc-300">{selectedAlert.last_seen}</span></div>
                      </div>
                    </div>

                    <div className="p-3 bg-[#0c0c12] border border-[#1e1e28] rounded-xl text-xs">
                      <span className="text-zinc-400 font-semibold">Impact Assessment: </span>
                      <span className="text-zinc-200">{selectedAlert.impact}</span>
                    </div>
                  </div>

                  {/* Additive Factor Risk Score */}
                  {activeScore && (
                    <div className="p-6 border border-[#1c1c26] rounded-2xl bg-[#08080c] space-y-4 shadow-sm">
                      <div className="flex items-center justify-between">
                        <div>
                          <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400 font-mono">
                            Additive Factor Risk Score
                          </h3>
                          <p className="text-xs text-zinc-400">Transparent additive weighted model (0–100)</p>
                        </div>
                        <div className="text-2xl font-black font-mono text-rose-400">
                          {activeScore.total} <span className="text-xs text-zinc-400">/ 100</span>
                        </div>
                      </div>

                      <div className="space-y-2.5">
                        {activeScore.factors.map(f => (
                          <div key={f.name} className="space-y-1">
                            <div className="flex items-center justify-between text-xs font-mono">
                              <span className="text-zinc-300 capitalize">{f.name.replace(/_/g, ' ')}</span>
                              <span className="text-cyan-300">+{f.contribution} pts ({(f.weight * 100).toFixed(1)}% wt)</span>
                            </div>
                            <div className="w-full bg-[#121218] h-1.5 rounded-full overflow-hidden border border-[#1f1f2a]">
                              <div
                                className="bg-gradient-to-r from-sky-400 to-teal-400 h-full rounded-full transition-all duration-500"
                                style={{ width: `${Math.min(100, f.value)}%` }}
                              ></div>
                            </div>
                          </div>
                        ))}
                      </div>

                      <div className="p-3 bg-[#0c0c12] border border-[#1e1e28] rounded-xl text-xs space-y-1">
                        <div className="text-zinc-400 font-semibold">Top Threat Signals:</div>
                        <div className="flex flex-wrap gap-2 pt-1">
                          {activeScore.explanation.top_factors.map(tf => (
                            <span key={tf} className="px-2 py-0.5 rounded bg-[#10141f] text-cyan-300 border border-cyan-800/40 text-[11px] font-mono">
                              {tf}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Reconstructed Attack Chain Timeline */}
                  <div className="p-6 border border-[#1c1c26] rounded-2xl bg-[#08080c] space-y-4 shadow-sm">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400 font-mono">
                          Correlated Attack Chain Timeline
                        </h3>
                        <p className="text-xs text-zinc-400">Cross-source provenance stages</p>
                      </div>
                      {activeChain && (
                        <span className="text-xs font-mono text-emerald-400 border border-emerald-800/50 bg-[#071712] px-2.5 py-0.5 rounded-full">
                          Confidence: {(activeChain.confidence * 100).toFixed(0)}%
                        </span>
                      )}
                    </div>

                    <div className="relative pl-6 space-y-5 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#1f1f2b]">
                      {activeChain?.stages.map((st, idx) => {
                        const provColor =
                          st.link_provenance === 'VALIDATED_OBSERVATION'
                            ? 'border-emerald-500/70 bg-[#06140e] text-emerald-300'
                            : 'border-cyan-500/70 bg-[#061118] text-cyan-300'

                        return (
                          <div key={idx} className="relative">
                            <span className={`absolute -left-[27px] top-1 w-3 h-3 rounded-full border-2 ${provColor}`}></span>
                            <div className="flex items-center justify-between">
                              <h4 className="text-xs font-semibold text-white">{st.stage.replace(/_/g, ' ')}</h4>
                              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${provColor}`}>
                                {st.link_provenance}
                              </span>
                            </div>
                            <p className="text-[11px] font-mono text-zinc-400 mt-0.5">Event Ref: {st.event_ref}</p>
                          </div>
                        )
                      })}
                    </div>
                  </div>

                  {/* Policy Action Simulator */}
                  <div className="p-6 border border-[#1c1c26] rounded-2xl bg-[#08080c] space-y-4 shadow-sm">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400 font-mono">
                          Policy Containment Simulator
                        </h3>
                        <p className="text-xs text-zinc-400">Zero Trust automated mitigation</p>
                      </div>
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#1e1406] text-amber-300 border border-amber-800/40">
                        Action: {selectedAlert.recommended_action}
                      </span>
                    </div>

                    <div className="flex items-center justify-end space-x-3 pt-2">
                      <button
                        onClick={handleStepUp}
                        className="px-4 py-2 rounded-lg text-xs font-medium border border-[#2b2b3a] bg-[#121218] hover:bg-[#181822] text-cyan-200 transition-colors cursor-pointer"
                      >
                        Simulate Step-Up MFA
                      </button>

                      {simResult ? (
                        <span className="px-4 py-2 rounded-lg text-xs font-mono bg-[#061710] text-emerald-300 border border-emerald-800/50 flex items-center">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-2"></span>
                          Result: {simResult} (SIMULATED)
                        </span>
                      ) : (
                        <button
                          onClick={handleApprove}
                          className="px-5 py-2 rounded-lg text-xs font-semibold bg-rose-600/80 hover:bg-rose-500 text-white shadow transition-all cursor-pointer"
                        >
                          Authorize Simulated {selectedAlert.recommended_action}
                        </button>
                      )}
                    </div>

                    {stepUpPrompt && (
                      <div className="p-3 rounded-xl border border-cyan-800/40 bg-[#08121a] text-xs text-cyan-200 font-mono">
                        {stepUpPrompt}
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <div className="p-12 text-center border border-[#1c1c26] rounded-2xl bg-[#08080c] text-zinc-400 text-xs font-mono">
                  No incident selected. Select an alert from the left or trigger "⚡ Generate Attack".
                </div>
              )}
            </div>
          )}

          {/* --- TAB 2: LIVE ATTACK GRAPH (Interactive Bubble Network) --- */}
          {activeTab === 'graph' && (
            <div className="space-y-6">
              <div className="p-6 border border-[#1c1c26] rounded-2xl bg-[#08080c] space-y-4 shadow-sm">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-base font-bold text-white flex items-center space-x-2">
                      <span>Interactive Bubble Attack Graph</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#061710] text-emerald-300 border border-emerald-800/40 animate-pulse">
                        LIVE
                      </span>
                    </h2>
                    <p className="text-xs text-zinc-400">
                      Hover over any bubble node to inspect credentials, role escalation, and target vaults
                    </p>
                  </div>

                  {/* Incident selector */}
                  <div className="flex items-center space-x-2 text-xs font-mono">
                    <span className="text-zinc-400">Incident:</span>
                    <select
                      value={selectedAlert?.alert_id || ''}
                      onChange={e => {
                        const found = alerts.find(a => a.alert_id === e.target.value)
                        if (found) setSelectedAlert(found)
                      }}
                      className="bg-[#101016] border border-[#222230] text-zinc-200 text-xs rounded-lg px-2.5 py-1 font-mono outline-none cursor-pointer"
                    >
                      {alerts.map(a => (
                        <option key={a.alert_id} value={a.alert_id}>
                          {a.alert_id} ({formatIdentity(a.subject.id)})
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                {/* SVG Graph Canvas with Interactive Bubble Nodes */}
                <div className="relative w-full bg-black border border-[#181822] rounded-2xl p-6 min-h-[340px] flex items-center justify-center overflow-x-auto shadow-inner">
                  <svg viewBox="0 0 840 280" className="w-full h-72 min-w-[760px]">
                    <defs>
                      <marker id="arrow-cyan" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                        <path d="M 0 0 L 10 5 L 0 10 z" fill="#38bdf8" />
                      </marker>
                      <marker id="arrow-amber" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                        <path d="M 0 0 L 10 5 L 0 10 z" fill="#f59e0b" />
                      </marker>
                      <marker id="arrow-rose" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                        <path d="M 0 0 L 10 5 L 0 10 z" fill="#f43f5e" />
                      </marker>
                    </defs>

                    {/* Connecting Vector Lines */}
                    {/* Hop 1: Identity -> Role */}
                    <path
                      d="M 120 140 C 200 80, 240 80, 310 140"
                      fill="none"
                      stroke="#38bdf8"
                      strokeWidth="2.2"
                      strokeDasharray="4 3"
                      markerEnd="url(#arrow-cyan)"
                      opacity="0.85"
                    />
                    <text x="215" y="90" fill="#7dd3fc" fontSize="10" textAnchor="middle" fontFamily="monospace">
                      AssumeRole
                    </text>

                    {/* Hop 2: Role -> Policy */}
                    <path
                      d="M 310 140 C 380 200, 440 200, 500 140"
                      fill="none"
                      stroke="#f59e0b"
                      strokeWidth="2.2"
                      markerEnd="url(#arrow-amber)"
                      opacity="0.85"
                    />
                    <text x="405" y="195" fill="#fcd34d" fontSize="10" textAnchor="middle" fontFamily="monospace">
                      AttachPolicy
                    </text>

                    {/* Hop 3: Policy -> Target Resource */}
                    <path
                      d="M 500 140 C 580 80, 630 80, 700 140"
                      fill="none"
                      stroke="#f43f5e"
                      strokeWidth="2.2"
                      markerEnd="url(#arrow-rose)"
                      opacity="0.85"
                    />
                    <text x="600" y="90" fill="#fda4af" fontSize="10" textAnchor="middle" fontFamily="monospace">
                      Exfiltrate
                    </text>

                    {/* Node 1 Bubble: Attacker Identity (Info on Hover) */}
                    <g
                      transform="translate(120, 140)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: hopIdentity,
                        title: 'Attacker Principal Identity',
                        type: 'IDENTITY',
                        roleDesc: 'Compromised or dormant user account used as initial vector',
                        attributes: {
                          'Principal ID': hopIdentity,
                          'Source': 'Okta Session Authenticator',
                          'Threat Indicator': 'Dormant Login / Impossible Travel',
                          'Clearance': 'Tier 1 Contractor'
                        },
                        color: 'sky',
                        icon: '👤'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <circle cx="0" cy="0" r="48" fill="transparent" pointerEvents="all" />
                      <circle cx="0" cy="0" r="36" fill="#0b1320" stroke="#38bdf8" strokeWidth="2.5" className="group-hover:stroke-sky-300 group-hover:scale-105 transition-all drop-shadow-[0_0_8px_rgba(56,189,248,0.25)] pointer-events-none" />
                      <circle cx="0" cy="0" r="42" fill="none" stroke="#38bdf8" strokeWidth="1" strokeDasharray="3 3" opacity="0.4" className="animate-spin pointer-events-none" />
                      <text x="0" y="-7" fill="#ffffff" fontSize="15" textAnchor="middle" className="pointer-events-none">👤</text>
                      <text x="0" y="9" fill="#e0f2fe" fontSize="10" fontWeight="bold" textAnchor="middle" className="pointer-events-none">Attacker</text>
                      <text x="0" y="21" fill="#7dd3fc" fontSize="8" fontFamily="monospace" textAnchor="middle" className="pointer-events-none">{formatIdentity(hopIdentity).slice(0, 10)}</text>
                    </g>

                    {/* Node 2 Bubble: Cloud Role (Info on Hover) */}
                    <g
                      transform="translate(310, 140)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: hopRole,
                        title: 'Assumed AWS IAM Role',
                        type: 'ROLE',
                        roleDesc: 'Intermediate cloud service role assumed via STS tokens',
                        attributes: {
                          'Role Name': hopRole,
                          'Service': 'AWS IAM / STS',
                          'Session Continuity': 'Correlated via Session ID & IP',
                          'Privilege Scope': 'Intermediate Cloud Access'
                        },
                        color: 'amber',
                        icon: '🔑'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <circle cx="0" cy="0" r="44" fill="transparent" pointerEvents="all" />
                      <circle cx="0" cy="0" r="32" fill="#181308" stroke="#f59e0b" strokeWidth="2.2" className="group-hover:stroke-amber-300 group-hover:scale-105 transition-all drop-shadow-[0_0_8px_rgba(245,158,11,0.2)] pointer-events-none" />
                      <text x="0" y="-5" fill="#ffffff" fontSize="13" textAnchor="middle" className="pointer-events-none">🔑</text>
                      <text x="0" y="9" fill="#fef3c7" fontSize="10" fontWeight="bold" textAnchor="middle" className="pointer-events-none">Cloud Role</text>
                      <text x="0" y="20" fill="#fcd34d" fontSize="8" fontFamily="monospace" textAnchor="middle" className="pointer-events-none">{hopRole.slice(0, 11)}..</text>
                    </g>

                    {/* Node 3 Bubble: Escalated Policy (Info on Hover) */}
                    <g
                      transform="translate(500, 140)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: hopPolicy,
                        title: 'Escalated IAM Policy',
                        type: 'POLICY',
                        roleDesc: 'Critical administrative permission policy attached illicitly',
                        attributes: {
                          'Policy ARN': `arn:aws:iam::aws:policy/${hopPolicy}`,
                          'Escalation Level': 'CRITICAL Privilege Grant',
                          'Action Type': 'AttachUserPolicy / PutPolicy',
                          'Risk Level': 'Maximum Administrative Scope'
                        },
                        color: 'rose',
                        icon: '⚡'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <circle cx="0" cy="0" r="44" fill="transparent" pointerEvents="all" />
                      <circle cx="0" cy="0" r="32" fill="#200a0e" stroke="#f43f5e" strokeWidth="2.2" className="group-hover:stroke-rose-300 group-hover:scale-105 transition-all drop-shadow-[0_0_8px_rgba(244,63,94,0.2)] pointer-events-none" />
                      <text x="0" y="-5" fill="#ffffff" fontSize="13" textAnchor="middle" className="pointer-events-none">⚡</text>
                      <text x="0" y="9" fill="#ffe4e6" fontSize="10" fontWeight="bold" textAnchor="middle" className="pointer-events-none">Escalated</text>
                      <text x="0" y="20" fill="#fda4af" fontSize="8" fontFamily="monospace" textAnchor="middle" className="pointer-events-none">{hopPolicy.slice(0, 11)}..</text>
                    </g>

                    {/* Node 4 Bubble: Target Resource (Info on Hover) */}
                    <g
                      transform="translate(700, 140)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: hopResource,
                        title: 'Target Sensitive Resource',
                        type: 'RESOURCE',
                        roleDesc: 'High-sensitivity catalog resource accessed or staged for exfiltration',
                        attributes: {
                          'Resource Target': hopResource,
                          'Data Classification': 'HIGH SENSITIVITY (PII / Keys)',
                          'Action': 's3:GetObject / DataExport',
                          'Status': 'Under Containment Simulation'
                        },
                        color: 'red',
                        icon: '🛑'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <circle cx="0" cy="0" r="48" fill="transparent" pointerEvents="all" />
                      <circle cx="0" cy="0" r="36" fill="#240a0e" stroke="#ef4444" strokeWidth="2.5" className="group-hover:stroke-red-300 group-hover:scale-105 transition-all drop-shadow-[0_0_8px_rgba(239,68,68,0.25)] pointer-events-none" />
                      <circle cx="0" cy="0" r="42" fill="none" stroke="#ef4444" strokeWidth="1" strokeDasharray="3 3" opacity="0.4" className="animate-spin pointer-events-none" />
                      <text x="0" y="-7" fill="#ffffff" fontSize="15" textAnchor="middle" className="pointer-events-none">🛑</text>
                      <text x="0" y="9" fill="#ffffff" fontSize="10" fontWeight="bold" textAnchor="middle" className="pointer-events-none">Vault Target</text>
                      <text x="0" y="21" fill="#fca5a5" fontSize="8" fontFamily="monospace" textAnchor="middle" className="pointer-events-none">{hopResource.slice(0, 12)}</text>
                    </g>
                  </svg>

                  {/* Bubble Inspection Flyout Card (Displays dynamically on hover) */}
                  {activeBubble ? (
                    <div className="absolute right-6 top-6 w-80 p-4 rounded-2xl border border-cyan-800/60 bg-[#070b12]/95 backdrop-blur-md shadow-2xl space-y-3 z-30 font-mono pointer-events-none animate-fadeIn">
                      <div className="flex items-center justify-between border-b border-[#182030] pb-2">
                        <div className="flex items-center space-x-2">
                          <span className="text-base">{activeBubble.icon}</span>
                          <span className="text-xs font-bold text-white uppercase tracking-wider">{activeBubble.title}</span>
                        </div>
                        <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-700/50 flex items-center space-x-1">
                          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
                          <span>HOVER TELEMETRY</span>
                        </span>
                      </div>

                      <p className="text-[11px] text-zinc-300 font-sans leading-tight">
                        {activeBubble.roleDesc}
                      </p>

                      <div className="space-y-1.5 bg-[#03060a] p-2.5 rounded-xl border border-[#141b29] text-[11px]">
                        {Object.entries(activeBubble.attributes).map(([k, v]) => (
                          <div key={k} className="flex items-start justify-between">
                            <span className="text-zinc-400">{k}:</span>
                            <span className="text-cyan-300 text-right font-semibold truncate max-w-[155px]">{v}</span>
                          </div>
                        ))}
                      </div>

                      <div className="text-[10px] text-cyan-400/80 text-right italic font-mono flex items-center justify-end space-x-1">
                        <span>●</span>
                        <span>Hovering node • Move cursor off to dismiss</span>
                      </div>
                    </div>
                  ) : (
                    <div className="absolute right-6 top-6 px-3.5 py-2 rounded-xl border border-[#181824] bg-[#07070b]/80 backdrop-blur text-[11px] font-mono text-zinc-400 pointer-events-none flex items-center space-x-2 shadow-sm">
                      <span className="w-2 h-2 rounded-full bg-cyan-500/60 animate-pulse"></span>
                      <span>Hover over any bubble node to inspect credentials</span>
                    </div>
                  )}
                </div>

                <div className="flex items-center justify-between text-xs font-mono text-zinc-400 pt-1">
                  <span>💡 Tip: Hover over any bubble node in the canvas above to inspect details without clutter.</span>
                  <span className="text-cyan-400/80">{graphData?.nodes.length} Nodes Mapped</span>
                </div>
              </div>
            </div>
          )}

          {/* --- TAB 3: AUTONOMOUS MODEL TUNING (Option 3 on Left) --- */}
          {activeTab === 'tuning' && (
            <div className="space-y-6">
              {/* Header Card */}
              <div className="p-6 border border-[#1c1c26] rounded-2xl bg-[#08080c] space-y-3 shadow-sm font-mono">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">
                        Autonomous Factor Tuning
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-amber-950/60 text-amber-300 border border-amber-800/40">
                        🔒 User Tamper Restricted
                      </span>
                    </div>
                    <h2 className="text-lg font-bold text-white mt-1.5">Zero Trust Additive Weight Calibration</h2>
                    <p className="text-xs text-zinc-400 mt-1 font-sans">
                      Model factor weights adapt autonomously based on live synthetic threat patterns and detection confidence.
                      Manual modifications are strictly locked by Zero Trust governance to prevent human confirmation bias.
                    </p>
                  </div>
                  <div className="text-right text-[11px] text-zinc-400">
                    <div>Status: <span className="text-emerald-400 font-bold">Self-Calibrating</span></div>
                    <div>Calibrated Factors: <span className="text-cyan-300 font-bold">{Object.keys(weights).length} Active</span></div>
                  </div>
                </div>

                <div className="p-3 bg-[#0c0c12] border border-[#1e1e28] rounded-xl text-xs flex items-center justify-between">
                  <div className="text-zinc-300 font-sans">
                    <span className="text-cyan-400 font-semibold font-mono">Governed Bounds: </span>
                    Each weight is mathematically bounded within [0.5×, 2.0×] of its baseline and normalized so ∑ w_i = 1.0.
                  </div>
                  <span className="text-xs font-mono px-2.5 py-1 rounded bg-[#10141f] text-cyan-300 border border-cyan-800/40 shrink-0">
                    ∑ w_i = 1.00
                  </span>
                </div>
              </div>

              {/* 5 Active Calibrated Factor Weights Cards */}
              <div className="p-6 border border-[#1c1c26] rounded-2xl bg-[#08080c] space-y-4 shadow-sm font-mono">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400">
                      Active Factor Weights & Delta Telemetry
                    </h3>
                    <p className="text-xs text-zinc-400 font-sans">Dynamic sensitivity calibrated across threat archetypes</p>
                  </div>
                  <span className="text-xs text-zinc-400">Baseline Target: 1.00 Total</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {Object.entries(weights).map(([factor, weight]) => {
                    const baselineWeight = factor === 'behavioral_anomaly' ? 0.25 : (factor === 'privilege_level' ? 0.20 : (factor === 'privilege_delta' ? 0.25 : 0.15))
                    const deltaPct = (((weight - baselineWeight) / baselineWeight) * 100).toFixed(1)

                    return (
                      <div key={factor} className="p-4 border border-[#1a1a26] bg-[#09090e] rounded-xl space-y-2.5 hover:border-cyan-500/40 transition-colors">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-semibold text-white capitalize">{factor.replace(/_/g, ' ')}</span>
                          <div className="flex items-center space-x-2">
                            <span className="text-cyan-300 font-bold text-sm">{weight}</span>
                            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${Number(deltaPct) >= 0 ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/40' : 'bg-rose-950/80 text-rose-300 border border-rose-800/40'}`}>
                              {Number(deltaPct) >= 0 ? `+${deltaPct}%` : `${deltaPct}%`}
                            </span>
                          </div>
                        </div>

                        <div className="w-full bg-[#121218] h-2 rounded-full overflow-hidden border border-[#1c1c28]">
                          <div
                            className="bg-gradient-to-r from-sky-400 via-cyan-400 to-teal-400 h-full rounded-full transition-all duration-500"
                            style={{ width: `${Math.min(100, weight * 200)}%` }}
                          ></div>
                        </div>

                        <div className="flex items-center justify-between text-[11px] text-zinc-400 pt-1">
                          <span>Baseline: <span className="text-zinc-300">{baselineWeight}</span></span>
                          <span className="text-cyan-400/90 flex items-center space-x-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
                            <span>Self-Calibrated</span>
                          </span>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Dynamic Tuning Log History */}
              <div className="p-6 border border-[#1c1c26] rounded-2xl bg-[#08080c] space-y-4 shadow-sm font-mono">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400">
                      Recent Dynamic Calibration Log
                    </h3>
                    <p className="text-xs text-zinc-400 font-sans">Audit trail of self-tuning weight adjustments triggered by synthetic scenarios</p>
                  </div>
                  <span className="text-xs text-cyan-400 border border-cyan-800/50 bg-[#07121c] px-2.5 py-0.5 rounded-full">
                    {tuningLog.length} Calibrations Logged
                  </span>
                </div>

                <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
                  {tuningLog.length === 0 ? (
                    <div className="p-8 text-center text-xs text-zinc-500 border border-[#181822] rounded-xl bg-[#06060a]">
                      No dynamic calibrations recorded yet. Generate a synthetic threat to observe autonomous model tuning.
                    </div>
                  ) : (
                    [...tuningLog].reverse().map(entry => (
                      <div key={entry.id} className="p-3.5 rounded-xl border border-[#181824] bg-[#07070b] space-y-2">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-bold text-cyan-300">{entry.trigger}</span>
                          <span className="text-zinc-500 text-[11px]">{entry.timestamp} UTC</span>
                        </div>

                        <div className="text-xs text-zinc-300">
                          Target Identity: <span className="text-white font-semibold">{formatIdentity(entry.target_identity)}</span>
                        </div>

                        <div className="p-2.5 bg-[#0a0a10] border border-[#161622] rounded-lg text-xs text-emerald-300 space-y-1">
                          <div className="font-semibold text-zinc-400 text-[11px]">Tuning Rationale:</div>
                          {entry.reasons.map((r, ri) => (
                            <div key={ri} className="flex items-start space-x-1.5">
                              <span className="text-cyan-400">▸</span>
                              <span>{r}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}
        </main>

        {/* ==============================================================
            RIGHT COLUMN: Synthetic Attack Threat Feed
           ============================================================== */}
        <aside className="w-80 shrink-0 border-l border-[#16161e] bg-[#050508] flex flex-col p-4 space-y-3.5 overflow-hidden">
          <div className="flex items-center justify-between pb-2 border-b border-[#181822]">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
                <span>Synthetic Threat Feed</span>
              </h3>
              <p className="text-[10px] text-zinc-400 font-mono">Real-time generated attack stream</p>
            </div>
            <span className="text-xs font-mono text-zinc-400">
              {syntheticHistory.length} Detected
            </span>
          </div>

          {/* Stream Item Cards */}
          <div className="space-y-2.5 flex-1 overflow-y-auto pr-1">
            {syntheticHistory.length === 0 ? (
              <div className="p-6 border border-[#1a1a24] rounded-xl bg-[#08080c] text-center text-xs text-zinc-400 font-mono">
                No synthetic attacks triggered yet. Click "⚡ Generate Attack" in the left panel to launch a scenario.
              </div>
            ) : (
              [...syntheticHistory].reverse().map((att, i) => (
                <div
                  key={i}
                  onClick={() => {
                    const match = alerts.find(a => a.incident_id === att.incident_id)
                    if (match) {
                      setSelectedAlert(match)
                      setActiveTab('details')
                    }
                  }}
                  className="p-3 border border-[#181824] hover:border-cyan-500/50 bg-[#09090e] rounded-xl space-y-2 cursor-pointer transition-all hover:-translate-y-0.5 hover:shadow-lg font-mono"
                >
                  <div className="flex items-center justify-between text-[10px]">
                    <span className="px-2 py-0.5 rounded bg-[#1e0d11] text-rose-300 border border-rose-800/40 font-bold">
                      {att.attack_type.slice(0, 16)}..
                    </span>
                    <span className="text-rose-400 font-bold">
                      Score: {att.risk_score}
                    </span>
                  </div>

                  <div className="text-xs font-semibold text-white truncate">
                    {formatIdentity(att.target_identity)}
                  </div>

                  <div className="text-[11px] text-zinc-400 space-y-0.5">
                    <div className="truncate">Role: <span className="text-zinc-300">{att.assumed_role}</span></div>
                    <div className="truncate">Policy: <span className="text-rose-300">{att.escalated_policy}</span></div>
                    <div className="truncate">Vault: <span className="text-amber-300">{att.target_resource}</span></div>
                  </div>

                  <div className="flex items-center justify-between pt-1 border-t border-[#14141c] text-[10px] text-zinc-400">
                    <span>Rules: {att.detected_rules.join(', ') || 'N/A'}</span>
                    <span className="text-cyan-400 hover:text-white">View →</span>
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Quick Model Tuning Bar with Switch Button */}
          <div
            onClick={() => setActiveTab('tuning')}
            className="p-2.5 rounded-xl border border-[#181824] hover:border-cyan-500/40 bg-[#08080c] hover:bg-[#0c0c14] cursor-pointer transition-all space-y-1 shrink-0 font-mono"
          >
            <div className="flex items-center justify-between text-[10px]">
              <span className="font-bold uppercase tracking-wider text-zinc-400">Model Tuning Option</span>
              <span className="text-cyan-400 hover:text-cyan-200">Open Module →</span>
            </div>
            {tuningLog.length > 0 ? (
              <div>
                <div className="text-cyan-300 font-bold text-[11px] truncate">Last: {tuningLog[tuningLog.length - 1].trigger}</div>
                <div className="text-[10px] text-zinc-400 truncate">{tuningLog[tuningLog.length - 1].reasons[0]}</div>
              </div>
            ) : (
              <div className="text-[10px] text-zinc-400 flex items-center justify-between">
                <span>Autonomous model active</span>
                <span className="text-emerald-400">5 Weights Synced</span>
              </div>
            )}
          </div>
        </aside>
      </div>
    </div>
  )
}
