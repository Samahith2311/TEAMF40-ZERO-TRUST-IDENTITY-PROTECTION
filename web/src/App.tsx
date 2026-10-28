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
  const [activeTab, setActiveTab] = useState<'details' | 'graph' | 'tuning' | 'mtls'>('details')
  const [selectedArchetype, setSelectedArchetype] = useState<string>('RANDOM')

  // Phase 7 mTLS Decision Cache State
  const [mtlsStats, setMtlsStats] = useState<any>(null)
  const [mtlsResult, setMtlsResult] = useState<any>(null)
  const [mtlsLoading, setMtlsLoading] = useState<boolean>(false)

  // Live Attack Simulation State (Visual step-by-step kill-chain animation)
  const [simStep, setSimStep] = useState<number>(0) // 0: Idle, 1: Infiltration, 2: Token Abuse, 3: STS Role, 4: PrivEsc, 5: Exfiltration, 6: Revocation
  const [isSimulating, setIsSimulating] = useState<boolean>(false)
  const [simSpeed, setSimSpeed] = useState<number>(1400) // ms per step
  const simTimerRef = useRef<any>(null)

  const startAttackSimulation = () => {
    if (simTimerRef.current) clearInterval(simTimerRef.current)
    setSimStep(1)
    setIsSimulating(true)
  }

  const stopAttackSimulation = () => {
    if (simTimerRef.current) clearInterval(simTimerRef.current)
    setIsSimulating(false)
  }

  const resetAttackSimulation = () => {
    if (simTimerRef.current) clearInterval(simTimerRef.current)
    setIsSimulating(false)
    setSimStep(0)
  }

  useEffect(() => {
    if (isSimulating) {
      simTimerRef.current = setInterval(() => {
        setSimStep(prev => {
          if (prev >= 6) {
            setIsSimulating(false)
            if (simTimerRef.current) clearInterval(simTimerRef.current)
            return 6
          }
          return prev + 1
        })
      }, simSpeed)
    } else {
      if (simTimerRef.current) clearInterval(simTimerRef.current)
    }
    return () => {
      if (simTimerRef.current) clearInterval(simTimerRef.current)
    }
  }, [isSimulating, simSpeed])

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
          setNotification(`⚡ Threat [${res.attack_type}] generated against ${res.identity_name} • Live Attack Graph Simulating`)
          loadData(true)
          setActiveTab('graph')
          startAttackSimulation()
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

  const runMtlsTest = async (testType: 'legit' | 'replay' | 'rotate') => {
    setMtlsLoading(true)
    try {
      if (testType === 'legit') {
        await fetch('http://127.0.0.1:8000/api/mtls/bind', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            identity: 'alice@corp.internal',
            session_id: 'sess-alice-live',
            fingerprint: 'eb:bf:ba:d4:c7:96:2a:ee:d5:1b:8f:f9:77:e8:14:c1:23:31:e8:3a:9d:08:8c:8f:ad:84:8a:c8:22:23:2e:f9'
          })
        })
        const res = await fetch('http://127.0.0.1:8000/api/mtls/decide', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            identity: 'alice@corp.internal',
            session_id: 'sess-alice-live',
            cert_fingerprint: 'eb:bf:ba:d4:c7:96:2a:ee:d5:1b:8f:f9:77:e8:14:c1:23:31:e8:3a:9d:08:8c:8f:ad:84:8a:c8:22:23:2e:f9',
            current_risk_score: 15
          })
        })
        const data = await res.json()
        setMtlsResult(data)
      } else if (testType === 'replay') {
        const res = await fetch('http://127.0.0.1:8000/api/mtls/decide', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            identity: 'alice@corp.internal',
            session_id: 'sess-alice-live',
            cert_fingerprint: '59:80:87:09:70:79:59:2e:68:93:11:30:6d:7a:73:0c:0e:c1:0a:f5:02:87:85:89:8d:5a:1a:f4:19:25:cf:7e',
            current_risk_score: 15
          })
        })
        const data = await res.json()
        setMtlsResult(data)
      } else if (testType === 'rotate') {
        const newFp = '11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff'
        await fetch('http://127.0.0.1:8000/api/mtls/approve-rotation', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            identity: 'alice@corp.internal',
            session_id: 'sess-alice-live',
            new_fingerprint: newFp
          })
        })
        const res = await fetch('http://127.0.0.1:8000/api/mtls/decide', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            identity: 'alice@corp.internal',
            session_id: 'sess-alice-live',
            cert_fingerprint: newFp,
            current_risk_score: 15
          })
        })
        const data = await res.json()
        setMtlsResult(data)
      }
      const statsRes = await fetch('http://127.0.0.1:8000/api/mtls/stats')
      const statsData = await statsRes.json()
      setMtlsStats(statsData.stats)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setMtlsLoading(false)
    }
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

            {/* Option 4: mTLS Decision Cache */}
            <div
              onClick={() => {
                setActiveTab('mtls')
                fetch('http://127.0.0.1:8000/api/mtls/stats')
                  .then(r => r.json())
                  .then(d => setMtlsStats(d.stats))
                  .catch(() => {})
              }}
              className={`group cursor-pointer rounded-xl p-3 border transition-all duration-300 ease-out hover:-translate-y-1.5 hover:shadow-[0_12px_24px_-6px_rgba(56,189,248,0.18)] ${
                activeTab === 'mtls'
                  ? 'bg-[#10141e] border-cyan-500/50 shadow-[0_4px_16px_rgba(56,189,248,0.12)]'
                  : 'bg-[#09090d] border-[#181822] shadow-[inset_0_2px_4px_rgba(0,0,0,0.8)] hover:border-cyan-500/40 hover:bg-[#0f1118]'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center text-sm transition-transform duration-300 group-hover:scale-110 ${
                    activeTab === 'mtls' ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-700/50' : 'bg-[#121218] text-zinc-400 border border-[#20202a]'
                  }`}>
                    🔐
                  </div>
                  <div>
                    <h4 className={`text-xs font-semibold tracking-wide ${activeTab === 'mtls' ? 'text-white' : 'text-zinc-300 group-hover:text-white'}`}>
                      mTLS Decision Cache
                    </h4>
                    <p className="text-[10px] text-zinc-400">Risk-adaptive fast path</p>
                  </div>
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
                  activeTab === 'mtls' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/50' : 'bg-[#15151e] text-cyan-400'
                }`}>
                  Phase 7
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

          {/* --- TAB 2: LIVE ATTACK GRAPH (Interactive Swimlane Kill-Chain DAG) --- */}
          {activeTab === 'graph' && (
            <div className="space-y-3">
              <div className="p-4 border border-[#1c1c26] rounded-2xl bg-[#08080c] space-y-3 shadow-sm">
                {/* Header & Controls */}
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-2.5 pb-2 border-b border-[#161622]">
                  <div>
                    <h2 className="text-sm font-bold text-white flex items-center space-x-2">
                      <span>Live Attack Graph &amp; Kill-Chain DAG</span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                        isSimulating ? 'bg-rose-950 text-rose-300 border border-rose-800/60 animate-pulse' : 'bg-[#061710] text-emerald-300 border border-emerald-800/40'
                      }`}>
                        {isSimulating ? '● SIMULATING ATTACK' : 'LIVE TELEMETRY'}
                      </span>
                    </h2>
                    <p className="text-[11px] text-zinc-400">
                      Sequential attack propagation: Infiltration → Token Abuse → STS Role Assumption → IAM Privilege Escalation → Vault Exfiltration
                    </p>
                  </div>

                  <div className="flex items-center space-x-2.5 text-xs font-mono">
                    {/* Incident Selector */}
                    <div className="flex items-center space-x-1.5">
                      <span className="text-zinc-400 text-[11px]">Incident:</span>
                      <select
                        value={selectedAlert?.alert_id || ''}
                        onChange={e => {
                          const found = alerts.find(a => a.alert_id === e.target.value)
                          if (found) {
                            setSelectedAlert(found)
                            resetAttackSimulation()
                          }
                        }}
                        className="bg-[#101016] border border-[#222230] text-zinc-200 text-xs rounded-lg px-2 py-1 font-mono outline-none cursor-pointer"
                      >
                        {alerts.map(a => (
                          <option key={a.alert_id} value={a.alert_id}>
                            {a.alert_id} ({formatIdentity(a.subject.id)})
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Simulation Playback Controls */}
                    <div className="flex items-center space-x-1 bg-[#0e0e16] p-1 rounded-xl border border-[#1e1e2c]">
                      {isSimulating ? (
                        <button
                          onClick={stopAttackSimulation}
                          className="px-2.5 py-1 rounded-lg bg-amber-600/80 hover:bg-amber-500 text-white text-[11px] font-bold cursor-pointer transition-all flex items-center space-x-1"
                        >
                          <span>⏸ Pause</span>
                        </button>
                      ) : (
                        <button
                          onClick={startAttackSimulation}
                          className="px-2.5 py-1 rounded-lg bg-gradient-to-r from-cyan-600 to-sky-600 hover:from-cyan-500 hover:to-sky-500 text-white text-[11px] font-bold cursor-pointer transition-all flex items-center space-x-1 shadow-sm"
                        >
                          <span>▶ Play Simulation</span>
                        </button>
                      )}
                      <button
                        onClick={resetAttackSimulation}
                        className="px-2 py-1 rounded-lg bg-[#161622] hover:bg-[#202030] text-zinc-300 text-[11px] cursor-pointer transition-all"
                        title="Reset simulation to initial state"
                      >
                        ⟳ Reset
                      </button>
                    </div>
                  </div>
                </div>

                {/* Simulation Step Progress & Narrative Telemetry Ticker */}
                <div className="p-2.5 rounded-xl border border-[#181826] bg-[#060810] space-y-2 font-mono">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                        simStep === 0 ? 'bg-zinc-800 text-zinc-300' :
                        simStep === 1 ? 'bg-indigo-950 text-indigo-300 border border-indigo-700/50' :
                        simStep === 2 ? 'bg-rose-950 text-rose-300 border border-rose-700/50' :
                        simStep === 3 ? 'bg-amber-950 text-amber-300 border border-amber-700/50' :
                        simStep === 4 ? 'bg-sky-950 text-sky-300 border border-sky-700/50' :
                        simStep === 5 ? 'bg-red-950 text-red-200 border border-red-700/60' :
                        'bg-emerald-950 text-emerald-300 border border-emerald-700/50'
                      }`}>
                        {simStep === 0 && '⚪ IDLE • Click Play to Highlight Attack Arrows'}
                        {simStep === 1 && '🚨 STEP 1/5: INFILTRATION ARROW'}
                        {simStep === 2 && '⚡ STEP 2/5: TOKEN ABUSE & STS ARROWS'}
                        {simStep === 3 && '🔑 STEP 3/5: STS ROLE ARROW'}
                        {simStep === 4 && '⚡ STEP 4/5: PRIVILEGE ESCALATION ARROW'}
                        {simStep === 5 && '🛑 STEP 5/5: VAULT EXFILTRATION ARROW'}
                        {simStep === 6 && '🛡️ STEP 6: ZERO TRUST CONTAINMENT'}
                      </span>

                      <span className="text-zinc-400 text-[11px]">
                        Target: <span className="text-white font-semibold">{formatIdentity(hopIdentity)}</span>
                      </span>
                    </div>

                    {/* Step Quick Jump Pills */}
                    <div className="flex items-center space-x-1 text-[10px]">
                      {[
                        { step: 1, label: '1. Infiltrate' },
                        { step: 2, label: '2. Token' },
                        { step: 3, label: '3. STS Role' },
                        { step: 4, label: '4. PrivEsc' },
                        { step: 5, label: '5. Exfil' },
                        { step: 6, label: '6. Revoke' }
                      ].map(s => (
                        <button
                          key={s.step}
                          onClick={() => {
                            setSimStep(s.step)
                            setIsSimulating(false)
                          }}
                          className={`px-2 py-0.5 rounded cursor-pointer transition-all ${
                            simStep >= s.step
                              ? (s.step === 5 ? 'bg-red-900/60 text-red-200 border border-red-700/50 font-bold' : (s.step === 6 ? 'bg-emerald-950 text-emerald-300 border border-emerald-700/50' : 'bg-cyan-950 text-cyan-300 border border-cyan-800/40'))
                              : 'bg-[#101018] text-zinc-500 hover:text-zinc-300 border border-[#1a1a26]'
                          }`}
                        >
                          {s.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Narrative Ticker Message */}
                  <div className="text-xs text-zinc-300 bg-[#090d16] p-2 rounded-lg border border-[#141b2a] flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="text-cyan-400 font-bold">▶</span>
                      <span>
                        {simStep === 0 && 'Ready. Generate a synthetic attack or click "Play Simulation" to highlight attack vectors step-by-step.'}
                        {simStep === 1 && `[Arrow 1 Highlighted] Compromised credentials authenticated in Okta System Log. Anomaly flag: Dormant account reactivation / Impossible travel.`}
                        {simStep === 2 && `[Arrow 2 Highlighted] Bearer token assumed. Browser-to-SDK transition detected with anomalous IP roaming across internal sessions.`}
                        {simStep === 3 && `[Arrow 3 Highlighted] AWS STS AssumeRole API invoked. Principal acquired temporary cross-account cloud STS credentials.`}
                        {simStep === 4 && `[Arrow 4 Highlighted] IAM privilege escalation verified. Policy 'AdministratorAccess' illicitly attached to contractor principal.`}
                        {simStep === 5 && `[Arrow 5 Highlighted] CRITICAL ALERT: Unauthorized s3:GetObject dispatched against customer financial vault ('corp-customer-pii-vault')!`}
                        {simStep === 6 && `[CONTAINMENT ENFORCED] Zero Trust policy auto-executed REVOKE_SESSION. STS tokens purged and session access terminated.`}
                      </span>
                    </div>

                    {simStep === 6 && (
                      <span className="text-[10px] font-bold text-emerald-400 border border-emerald-800/50 bg-[#06180f] px-2 py-0.5 rounded shrink-0">
                        PROTECTION ACTIVE
                      </span>
                    )}
                  </div>
                </div>

                {/* SVG Graph Canvas - Fitted 100% to box with NO horizontal scrolling and NO rotating boxes */}
                <div className="relative w-full bg-[#030611] border border-[#161c2c] rounded-2xl p-2.5 flex items-center justify-center shadow-inner overflow-hidden">
                  <svg
                    viewBox="0 0 960 300"
                    className="w-full h-auto max-h-[360px]"
                    preserveAspectRatio="xMidYMid meet"
                  >
                    <defs>
                      <style>{`
                        @keyframes flowDash {
                          from { stroke-dashoffset: 24; }
                          to { stroke-dashoffset: 0; }
                        }
                        .attack-arrow-active {
                          stroke-dasharray: 8 4;
                          animation: flowDash 0.8s linear infinite;
                        }
                      `}</style>

                      {/* Inactive Muted Arrow Marker */}
                      <marker id="arrow-dim-red" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                        <path d="M 0 0 L 10 5 L 0 10 z" fill="#7f1d1d" opacity="0.6" />
                      </marker>

                      {/* Active Highlighted Glowing Red Arrow Marker */}
                      <marker id="arrow-bright-red" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                        <path d="M 0 0 L 10 5 L 0 10 z" fill="#ff2255" />
                      </marker>

                      {/* Benign Background Edge Arrow Marker */}
                      <marker id="arrow-teal" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
                        <path d="M 0 0 L 10 5 L 0 10 z" fill="#0d9488" opacity="0.5" />
                      </marker>

                      {/* Glow Filter for Active Arrows */}
                      <filter id="glow-arrow-red" x="-20%" y="-20%" width="140%" height="140%">
                        <feGaussianBlur stdDeviation="2.5" result="blur" />
                        <feMerge>
                          <feMergeNode in="blur" />
                          <feMergeNode in="SourceGraphic" />
                        </feMerge>
                      </filter>

                      <filter id="glow-indigo" x="-20%" y="-20%" width="140%" height="140%">
                        <feGaussianBlur stdDeviation="2.5" result="blur" />
                        <feMerge>
                          <feMergeNode in="blur" />
                          <feMergeNode in="SourceGraphic" />
                        </feMerge>
                      </filter>
                    </defs>

                    {/* Vertical Dashed Lane Dividers */}
                    <line x1="185" y1="8" x2="185" y2="292" stroke="#131e33" strokeWidth="1" strokeDasharray="4 4" />
                    <line x1="375" y1="8" x2="375" y2="292" stroke="#131e33" strokeWidth="1" strokeDasharray="4 4" />
                    <line x1="567" y1="8" x2="567" y2="292" stroke="#131e33" strokeWidth="1" strokeDasharray="4 4" />
                    <line x1="757" y1="8" x2="757" y2="292" stroke="#131e33" strokeWidth="1" strokeDasharray="4 4" />

                    {/* Column Lane Header Labels */}
                    <text x="89" y="18" fill="#475569" fontSize="9.5" fontWeight="bold" fontFamily="monospace" textAnchor="middle" letterSpacing="0.1em">IDENTITIES</text>
                    <text x="279" y="18" fill="#475569" fontSize="9.5" fontWeight="bold" fontFamily="monospace" textAnchor="middle" letterSpacing="0.1em">SESSIONS</text>
                    <text x="471" y="18" fill="#475569" fontSize="9.5" fontWeight="bold" fontFamily="monospace" textAnchor="middle" letterSpacing="0.1em">ROLES &amp; STS</text>
                    <text x="661" y="18" fill="#475569" fontSize="9.5" fontWeight="bold" fontFamily="monospace" textAnchor="middle" letterSpacing="0.1em">POLICIES</text>
                    <text x="851" y="18" fill="#475569" fontSize="9.5" fontWeight="bold" fontFamily="monospace" textAnchor="middle" letterSpacing="0.1em">TARGET RESOURCES</text>

                    {/* ========================================================
                        BACKGROUND EDGES (Benign Telemetry Curves)
                       ======================================================== */}
                    {/* Alice -> Session: sess-ch */}
                    <path d="M 160 60 C 185 60, 185 91, 212 91" fill="none" stroke="#0d9488" strokeWidth="1.2" opacity="0.35" markerEnd="url(#arrow-teal)" />
                    {/* Session: sess-ch -> sts.amazonaws.com */}
                    <path d="M 350 91 C 380 91, 380 140, 402 140" fill="none" stroke="#0d9488" strokeWidth="1.2" opacity="0.35" markerEnd="url(#arrow-teal)" />
                    {/* sts.amazonaws.com -> corp-analytics-r.. */}
                    <path d="M 544 140 C 640 140, 680 89, 782 89" fill="none" stroke="#0d9488" strokeWidth="1.2" opacity="0.35" markerEnd="url(#arrow-teal)" />
                    {/* sts.amazonaws.com -> corp-dev-builds */}
                    <path d="M 544 150 C 640 150, 680 207, 782 207" fill="none" stroke="#0d9488" strokeWidth="1.2" opacity="0.35" markerEnd="url(#arrow-teal)" />

                    {/* ========================================================
                        ACTIVE ATTACK PATH ARROWS (Highlighted Step-by-Step)
                       ======================================================== */}
                    {/* Arrow 1: Identity -> Session: bob-ses (Active at Step 1+) */}
                    <path
                      d="M 160 115 C 190 115, 180 49, 212 49"
                      fill="none"
                      stroke={simStep >= 1 ? '#ff2255' : '#7f1d1d'}
                      strokeWidth={simStep >= 1 ? '3' : '1.5'}
                      strokeDasharray={simStep >= 1 ? '8 4' : '5 3'}
                      markerEnd={simStep >= 1 ? 'url(#arrow-bright-red)' : 'url(#arrow-dim-red)'}
                      className={simStep >= 1 ? 'attack-arrow-active' : ''}
                      filter={simStep >= 1 ? 'url(#glow-arrow-red)' : undefined}
                      opacity={simStep >= 1 ? 1 : 0.45}
                    />

                    {/* Arrow 1b: Branching Token Probe -> Session: sess-di (Active at Step 2+) */}
                    <path
                      d="M 160 115 C 185 115, 185 133, 212 133"
                      fill="none"
                      stroke={simStep >= 2 ? '#ff4d4d' : '#450a0a'}
                      strokeWidth={simStep >= 2 ? '2.4' : '1.2'}
                      strokeDasharray="6 3"
                      markerEnd={simStep >= 2 ? 'url(#arrow-bright-red)' : 'url(#arrow-dim-red)'}
                      className={simStep >= 2 ? 'attack-arrow-active' : ''}
                      opacity={simStep >= 2 ? 0.9 : 0.3}
                    />

                    {/* Arrow 1c: Lateral Session Probes downward (Active at Step 2+) */}
                    <path
                      d="M 160 115 C 185 115, 175 217, 212 217"
                      fill="none"
                      stroke={simStep >= 2 ? '#ff4d4d' : '#450a0a'}
                      strokeWidth={simStep >= 2 ? '2' : '1.2'}
                      strokeDasharray="5 3"
                      markerEnd={simStep >= 2 ? 'url(#arrow-bright-red)' : 'url(#arrow-dim-red)'}
                      className={simStep >= 2 ? 'attack-arrow-active' : ''}
                      opacity={simStep >= 2 ? 0.85 : 0.25}
                    />

                    {/* Arrow 2: Session: bob-ses -> sts.amazonaws.com (Active at Step 2+) */}
                    <path
                      d="M 350 49 C 385 49, 375 140, 402 140"
                      fill="none"
                      stroke={simStep >= 2 ? '#ff2255' : '#7f1d1d'}
                      strokeWidth={simStep >= 2 ? '3' : '1.5'}
                      strokeDasharray={simStep >= 2 ? '8 4' : '5 3'}
                      markerEnd={simStep >= 2 ? 'url(#arrow-bright-red)' : 'url(#arrow-dim-red)'}
                      className={simStep >= 2 ? 'attack-arrow-active' : ''}
                      filter={simStep >= 2 ? 'url(#glow-arrow-red)' : undefined}
                      opacity={simStep >= 2 ? 1 : 0.45}
                    />

                    {/* Arrow 3: sts.amazonaws.com -> arn:aws:iam::aws.. (Active at Step 3+) */}
                    <path
                      d="M 544 147 L 592 147"
                      fill="none"
                      stroke={simStep >= 3 ? '#ff2255' : '#7f1d1d'}
                      strokeWidth={simStep >= 3 ? '3.2' : '1.5'}
                      strokeDasharray={simStep >= 3 ? '8 4' : '5 3'}
                      markerEnd={simStep >= 3 ? 'url(#arrow-bright-red)' : 'url(#arrow-dim-red)'}
                      className={simStep >= 3 ? 'attack-arrow-active' : ''}
                      filter={simStep >= 3 ? 'url(#glow-arrow-red)' : undefined}
                      opacity={simStep >= 3 ? 1 : 0.45}
                    />

                    {/* Arrow 4: arn:aws:iam::aws.. -> corp-customer-pi.. (Active at Step 4+) */}
                    <path
                      d="M 734 147 L 782 147"
                      fill="none"
                      stroke={simStep >= 4 ? '#ff1744' : '#7f1d1d'}
                      strokeWidth={simStep >= 4 ? '3.5' : '1.5'}
                      strokeDasharray={simStep >= 4 ? '8 4' : '5 3'}
                      markerEnd={simStep >= 4 ? 'url(#arrow-bright-red)' : 'url(#arrow-dim-red)'}
                      className={simStep >= 4 ? 'attack-arrow-active' : ''}
                      filter={simStep >= 4 ? 'url(#glow-arrow-red)' : undefined}
                      opacity={simStep >= 4 ? 1 : 0.45}
                    />

                    {/* ========================================================
                        COLUMN 1: IDENTITIES (Steady, non-turning cards)
                       ======================================================== */}
                    {/* 1.1: Alice */}
                    <g
                      transform="translate(22, 42)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: 'alice@corp.internal',
                        title: 'Alice (Internal Analyst)',
                        type: 'IDENTITY',
                        roleDesc: 'Standard data analyst principal identity',
                        attributes: { 'Status': 'Normal', 'Clearance': 'Tier 1 Analyst', '2FA': 'Enforced' },
                        color: 'sky',
                        icon: '👤'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <rect width="138" height="36" rx="6" fill="#09101d" stroke="#1b283d" strokeWidth="1" className="group-hover:stroke-cyan-500/50 transition-all" />
                      <text x="10" y="16" fill="#cbd5e1" fontSize="10.5" fontWeight="bold" fontFamily="monospace">alice@corp.inter..</text>
                      <text x="10" y="28" fill="#64748b" fontSize="8" fontWeight="600" fontFamily="monospace">IDENTITY • NORMAL</text>
                    </g>

                    {/* 1.2: Bob (Compromised Attacker - Steady card with glowing border) */}
                    <g
                      transform="translate(22, 96)"
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
                      <rect
                        width="138"
                        height="38"
                        rx="6"
                        fill="#0f172a"
                        stroke={simStep >= 1 ? '#ff2255' : '#6366f1'}
                        strokeWidth={simStep >= 1 ? '2.4' : '2'}
                        filter={simStep >= 1 ? 'url(#glow-arrow-red)' : 'url(#glow-indigo)'}
                        className="transition-all"
                      />
                      <text x="10" y="16" fill="#ffffff" fontSize="10.5" fontWeight="bold" fontFamily="monospace">
                        {formatIdentity(hopIdentity).slice(0, 15)}
                      </text>
                      <text x="10" y="29" fill={simStep >= 1 ? '#fca5a5' : '#a5b4fc'} fontSize="8" fontWeight="600" fontFamily="monospace">
                        IDENTITY • {simStep >= 1 ? 'COMPROMISED' : 'NORMAL'}
                      </text>
                    </g>

                    {/* 1.3: Charlie */}
                    <g
                      transform="translate(22, 150)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: 'charlie.analyst@corp.internal',
                        title: 'Charlie (Analyst)',
                        type: 'IDENTITY',
                        roleDesc: 'Ordinary data science identity',
                        attributes: { 'Status': 'Normal', 'Clearance': 'Tier 1 Analyst', 'Department': 'Finance Analytics' },
                        color: 'sky',
                        icon: '👤'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <rect width="138" height="36" rx="6" fill="#09101d" stroke="#1b283d" strokeWidth="1" className="group-hover:stroke-cyan-500/50 transition-all" />
                      <text x="10" y="16" fill="#cbd5e1" fontSize="10.5" fontWeight="bold" fontFamily="monospace">charlie.analyst@..</text>
                      <text x="10" y="28" fill="#64748b" fontSize="8" fontWeight="600" fontFamily="monospace">IDENTITY • NORMAL</text>
                    </g>

                    {/* 1.4: Diana Admin */}
                    <g
                      transform="translate(22, 204)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: 'diana.admin@corp.internal',
                        title: 'Diana Admin (Protected Safeguard)',
                        type: 'IDENTITY',
                        roleDesc: 'Critical infrastructure admin with break-glass safeguard active',
                        attributes: { 'Status': 'Protected', 'Break-Glass Safeguard': 'ACTIVE (Deny Action)', 'Privilege': 'Tier 4 Admin' },
                        color: 'rose',
                        icon: '🛡️'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <rect width="138" height="36" rx="6" fill="#18090d" stroke="#881337" strokeWidth="1.5" className="group-hover:stroke-rose-500 transition-all" />
                      <text x="10" y="16" fill="#fecdd3" fontSize="10.5" fontWeight="bold" fontFamily="monospace">diana.admin@corp..</text>
                      <text x="10" y="28" fill="#f43f5e" fontSize="8" fontWeight="bold" fontFamily="monospace">IDENTITY • HIGH</text>
                    </g>

                    {/* ========================================================
                        COLUMN 2: SESSIONS (Steady, non-turning cards)
                       ======================================================== */}
                    {/* 2.1: Attacker Session */}
                    <g
                      transform="translate(212, 32)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: 'Session: bob-ses..',
                        title: 'Attacker Authenticated Session',
                        type: 'SESSION',
                        roleDesc: 'Active Okta authenticated session established from anomalous IP',
                        attributes: { 'Session ID': 'bob-ses-091a', 'Transport': 'Browser-to-SDK', 'Status': simStep >= 2 ? 'HIJACKED' : 'ACTIVE' },
                        color: 'sky',
                        icon: '🔑'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <rect
                        width="138"
                        height="34"
                        rx="6"
                        fill="#0c1524"
                        stroke={simStep >= 2 ? '#ff2255' : '#1e293b'}
                        strokeWidth={simStep >= 2 ? '2' : '1'}
                        filter={simStep >= 2 ? 'url(#glow-arrow-red)' : undefined}
                        className="transition-all"
                      />
                      <text x="10" y="15" fill="#ffffff" fontSize="10.5" fontWeight="bold" fontFamily="monospace">Session: bob-ses..</text>
                      <text x="10" y="26" fill={simStep >= 2 ? '#fca5a5' : '#64748b'} fontSize="8" fontWeight="600" fontFamily="monospace">
                        SESSION • {simStep >= 2 ? 'HIJACKED' : 'NORMAL'}
                      </text>
                    </g>

                    {/* 2.2: sess-ch */}
                    <g transform="translate(212, 74)" className="cursor-pointer group">
                      <rect width="138" height="34" rx="6" fill="#080e18" stroke="#162032" strokeWidth="1" />
                      <text x="10" y="15" fill="#94a3b8" fontSize="10.5" fontWeight="bold" fontFamily="monospace">Session: sess-ch..</text>
                      <text x="10" y="26" fill="#475569" fontSize="8" fontWeight="600" fontFamily="monospace">SESSION • NORMAL</text>
                    </g>

                    {/* 2.3: sess-di */}
                    <g transform="translate(212, 116)" className="cursor-pointer group">
                      <rect width="138" height="34" rx="6" fill="#080e18" stroke={simStep >= 2 ? '#f43f5e' : '#162032'} strokeWidth="1" />
                      <text x="10" y="15" fill="#94a3b8" fontSize="10.5" fontWeight="bold" fontFamily="monospace">Session: sess-di..</text>
                      <text x="10" y="26" fill="#475569" fontSize="8" fontWeight="600" fontFamily="monospace">SESSION • NORMAL</text>
                    </g>

                    {/* 2.4: sess-ok */}
                    <g transform="translate(212, 158)" className="cursor-pointer group">
                      <rect width="138" height="34" rx="6" fill="#080e18" stroke="#162032" strokeWidth="1" />
                      <text x="10" y="15" fill="#94a3b8" fontSize="10.5" fontWeight="bold" fontFamily="monospace">Session: sess-ok..</text>
                      <text x="10" y="26" fill="#475569" fontSize="8" fontWeight="600" fontFamily="monospace">SESSION • NORMAL</text>
                    </g>

                    {/* 2.5: sess-ok */}
                    <g transform="translate(212, 200)" className="cursor-pointer group">
                      <rect width="138" height="34" rx="6" fill="#080e18" stroke="#162032" strokeWidth="1" />
                      <text x="10" y="15" fill="#94a3b8" fontSize="10.5" fontWeight="bold" fontFamily="monospace">Session: sess-ok..</text>
                      <text x="10" y="26" fill="#475569" fontSize="8" fontWeight="600" fontFamily="monospace">SESSION • NORMAL</text>
                    </g>

                    {/* 2.6: sess-ok */}
                    <g transform="translate(212, 242)" className="cursor-pointer group">
                      <rect width="138" height="34" rx="6" fill="#080e18" stroke="#162032" strokeWidth="1" />
                      <text x="10" y="15" fill="#94a3b8" fontSize="10.5" fontWeight="bold" fontFamily="monospace">Session: sess-ok..</text>
                      <text x="10" y="26" fill="#475569" fontSize="8" fontWeight="600" fontFamily="monospace">SESSION • NORMAL</text>
                    </g>

                    {/* ========================================================
                        COLUMN 3: ROLES & STS (Steady card)
                       ======================================================== */}
                    <g
                      transform="translate(402, 126)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: hopRole,
                        title: 'Assumed AWS IAM Role / STS Token',
                        type: 'ROLE',
                        roleDesc: 'Intermediate cloud service role assumed via STS tokens',
                        attributes: {
                          'Role Target': hopRole,
                          'Service': 'AWS IAM / STS (sts.amazonaws.com)',
                          'Action': 'sts:AssumeRole',
                          'Privilege Scope': 'Intermediate Cloud Access'
                        },
                        color: 'amber',
                        icon: '🔑'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <rect
                        width="142"
                        height="42"
                        rx="7"
                        fill="#451a03"
                        stroke={simStep >= 3 ? '#fbbf24' : '#f59e0b'}
                        strokeWidth={simStep >= 3 ? '2.4' : '2'}
                        className="transition-all"
                      />
                      <text x="10" y="18" fill="#ffffff" fontSize="11" fontWeight="bold" fontFamily="monospace">
                        {hopRole.includes('sts') ? hopRole : (hopRole.slice(0, 16))}
                      </text>
                      <text x="10" y="32" fill="#fcd34d" fontSize="8" fontWeight="bold" fontFamily="monospace">
                        ROLE • MEDIUM
                      </text>
                    </g>

                    {/* ========================================================
                        COLUMN 4: POLICIES (Steady card)
                       ======================================================== */}
                    <g
                      transform="translate(592, 126)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: hopPolicy,
                        title: 'Escalated IAM Policy',
                        type: 'POLICY',
                        roleDesc: 'Critical administrative permission policy attached illicitly',
                        attributes: {
                          'Policy ARN': `arn:aws:iam::aws:policy/${hopPolicy}`,
                          'Escalation Level': 'CRITICAL Administrative Privilege',
                          'Action Type': 'AttachUserPolicy / PutPolicy',
                          'Risk Level': 'Maximum Cloud Scope'
                        },
                        color: 'rose',
                        icon: '⚡'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <rect
                        width="142"
                        height="42"
                        rx="7"
                        fill="#0b1322"
                        stroke={simStep >= 4 ? '#38bdf8' : '#1e3a5f'}
                        strokeWidth={simStep >= 4 ? '2.2' : '1.5'}
                        className="transition-all"
                      />
                      <text x="10" y="18" fill="#ffffff" fontSize="10.5" fontWeight="bold" fontFamily="monospace">
                        arn:aws:iam::aws..
                      </text>
                      <text x="10" y="32" fill="#7dd3fc" fontSize="8" fontWeight="bold" fontFamily="monospace">
                        POLICY • MEDIUM
                      </text>
                    </g>

                    {/* ========================================================
                        COLUMN 5: TARGET RESOURCES (Steady cards)
                       ======================================================== */}
                    {/* 5.1: corp-analytics-r.. */}
                    <g transform="translate(782, 72)" className="cursor-pointer group">
                      <rect width="142" height="34" rx="6" fill="#061a14" stroke="#065f46" strokeWidth="1" />
                      <text x="10" y="15" fill="#cbd5e1" fontSize="10.5" fontWeight="bold" fontFamily="monospace">corp-analytics-r..</text>
                      <text x="10" y="26" fill="#34d399" fontSize="8" fontWeight="600" fontFamily="monospace">RESOURCE • NORMAL</text>
                    </g>

                    {/* 5.2: corp-customer-pi.. (High-Risk Exfiltration Target) */}
                    <g
                      transform="translate(782, 126)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: hopResource,
                        title: 'Target Sensitive Resource Vault',
                        type: 'RESOURCE',
                        roleDesc: 'High-sensitivity customer financial vault accessed illicitly',
                        attributes: {
                          'Target Resource': hopResource,
                          'Data Classification': 'HIGH SENSITIVITY (PII / Vault)',
                          'Action': 's3:GetObject / Exfiltration Attempt',
                          'Status': simStep >= 6 ? 'CONTAINED (REVOKE_SESSION)' : 'TARGET OF ACTIVE EXFILTRATION'
                        },
                        color: 'red',
                        icon: '🛑'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <rect
                        width="142"
                        height="42"
                        rx="7"
                        fill="#450a0a"
                        stroke={simStep >= 5 ? '#ff1744' : '#ef4444'}
                        strokeWidth={simStep >= 5 ? '2.5' : '1.8'}
                        className="transition-all"
                      />
                      <text x="10" y="18" fill="#ffffff" fontSize="10.5" fontWeight="bold" fontFamily="monospace">
                        {hopResource.includes('vault') ? 'corp-customer-pi..' : (hopResource.slice(0, 16))}
                      </text>
                      <text x="10" y="32" fill="#fca5a5" fontSize="8" fontWeight="bold" fontFamily="monospace">
                        RESOURCE • HIGH
                      </text>
                    </g>

                    {/* 5.3: corp-dev-builds */}
                    <g transform="translate(782, 190)" className="cursor-pointer group">
                      <rect width="142" height="34" rx="6" fill="#061a14" stroke="#065f46" strokeWidth="1" />
                      <text x="10" y="15" fill="#cbd5e1" fontSize="10.5" fontWeight="bold" fontFamily="monospace">corp-dev-builds</text>
                      <text x="10" y="26" fill="#34d399" fontSize="8" fontWeight="600" fontFamily="monospace">RESOURCE • NORMAL</text>
                    </g>

                    {/* Zero Trust Containment Shield Overlay when Step 6 reached */}
                    {simStep >= 6 && (
                      <g transform="translate(430, 65)">
                        <rect x="0" y="0" width="220" height="32" rx="7" fill="#03180f" stroke="#10b981" strokeWidth="1.8" />
                        <text x="110" y="20" fill="#6ee7b7" fontSize="10.5" fontWeight="bold" fontFamily="monospace" textAnchor="middle">
                          🛡️ REVOKE_SESSION ENFORCED
                        </text>
                      </g>
                    )}
                  </svg>

                  {/* Interactive Node Telemetry Flyout Card (Displays on hover) */}
                  {activeBubble ? (
                    <div className="absolute right-4 top-4 w-72 p-3.5 rounded-xl border border-cyan-800/60 bg-[#070b12]/95 backdrop-blur-md shadow-2xl space-y-2.5 z-30 font-mono pointer-events-none animate-fadeIn">
                      <div className="flex items-center justify-between border-b border-[#182030] pb-1.5">
                        <div className="flex items-center space-x-2">
                          <span className="text-sm">{activeBubble.icon}</span>
                          <span className="text-xs font-bold text-white uppercase tracking-wider">{activeBubble.title}</span>
                        </div>
                        <span className="px-1.5 py-0.5 rounded text-[8.5px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-700/50">
                          TELEMETRY
                        </span>
                      </div>

                      <p className="text-[10.5px] text-zinc-300 font-sans leading-tight">
                        {activeBubble.roleDesc}
                      </p>

                      <div className="space-y-1 bg-[#03060a] p-2 rounded-lg border border-[#141b29] text-[10.5px]">
                        {Object.entries(activeBubble.attributes).map(([k, v]) => (
                          <div key={k} className="flex items-start justify-between">
                            <span className="text-zinc-400">{k}:</span>
                            <span className="text-cyan-300 text-right font-semibold truncate max-w-[140px]">{v}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="absolute right-4 bottom-3 px-3 py-1 rounded-lg border border-[#181824] bg-[#07070b]/80 backdrop-blur text-[9.5px] font-mono text-zinc-400 pointer-events-none flex items-center space-x-1.5 shadow-sm">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-500/60 animate-pulse"></span>
                      <span>Hover over any card to inspect credentials and role details</span>
                    </div>
                  )}
                </div>

                <div className="flex items-center justify-between text-xs font-mono text-zinc-400 pt-0.5">
                  <span>💡 Tip: Click "Play Simulation" to highlight the attack arrows from Left to Right.</span>
                  <span className="text-cyan-400/80">5 Lanes • 15 Nodes Active</span>
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

          {/* ==============================================================
              TAB 4: Phase 7 Risk-Adaptive mTLS Decision Cache
             ============================================================== */}
          {activeTab === 'mtls' && (
            <div className="space-y-6">
              {/* Header Card */}
              <div className="p-6 border border-[#1a1a24] rounded-2xl bg-[#08080c] shadow-[inset_0_2px_4px_rgba(0,0,0,0.8)] space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-lg font-bold text-white flex items-center space-x-2">
                      <span>🔐</span>
                      <span>Phase 7: Risk-Adaptive mTLS Decision Cache</span>
                    </h2>
                    <p className="text-xs text-zinc-400 mt-1">
                      Continuous session validation binding TLS client certificates to active identity sessions with sub-millisecond fast-path bypass.
                    </p>
                  </div>
                  <button
                    onClick={() => {
                      fetch('http://127.0.0.1:8000/api/mtls/stats')
                        .then(r => r.json())
                        .then(d => setMtlsStats(d.stats))
                        .catch(() => {})
                    }}
                    className="px-3 py-1.5 rounded-lg border border-[#242436] bg-[#101018] hover:bg-[#161622] text-xs font-mono text-cyan-400 cursor-pointer transition-all"
                  >
                    Refresh Stats ⟳
                  </button>
                </div>

                {/* Key Metrics Grid */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-2">
                  <div className="p-3.5 rounded-xl border border-[#181824] bg-[#0c0c12]">
                    <div className="text-[10px] font-mono text-zinc-400 uppercase">Fast Path Hits</div>
                    <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
                      {mtlsStats?.fast_path_decisions ?? 0}
                    </div>
                    <div className="text-[10px] text-zinc-500 mt-0.5">~0.013 ms avg latency</div>
                  </div>
                  <div className="p-3.5 rounded-xl border border-[#181824] bg-[#0c0c12]">
                    <div className="text-[10px] font-mono text-zinc-400 uppercase">Full Path Fallbacks</div>
                    <div className="text-xl font-bold font-mono text-sky-400 mt-1">
                      {mtlsStats?.full_path_decisions ?? 0}
                    </div>
                    <div className="text-[10px] text-zinc-500 mt-0.5">Deep pipeline eval</div>
                  </div>
                  <div className="p-3.5 rounded-xl border border-[#181824] bg-[#0c0c12]">
                    <div className="text-[10px] font-mono text-zinc-400 uppercase">Cert Mismatches (DET-06)</div>
                    <div className="text-xl font-bold font-mono text-rose-400 mt-1">
                      {mtlsStats?.cert_mismatches ?? 0}
                    </div>
                    <div className="text-[10px] text-rose-500/80 mt-0.5">Stolen token attempts</div>
                  </div>
                  <div className="p-3.5 rounded-xl border border-[#181824] bg-[#0c0c12]">
                    <div className="text-[10px] font-mono text-zinc-400 uppercase">Active Cached Sessions</div>
                    <div className="text-xl font-bold font-mono text-cyan-400 mt-1">
                      {mtlsStats?.cache_size ?? 0}
                    </div>
                    <div className="text-[10px] text-zinc-500 mt-0.5">Invalidations: {mtlsStats?.invalidations ?? 0}</div>
                  </div>
                </div>
              </div>

              {/* Interactive Simulation Console */}
              <div className="p-6 border border-[#1c1c28] rounded-2xl bg-[#09090e] space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-300 font-mono">
                    Live mTLS Verification Simulator
                  </h3>
                  <span className="text-[10px] font-mono text-cyan-400">RFC 8705 & FIPS Proof</span>
                </div>
                <p className="text-xs text-zinc-400">
                  Trigger live cryptographic verification scenarios against the running FastAPI engine to verify sub-millisecond fast path caching and instant cache purging upon certificate mismatch.
                </p>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
                  <button
                    onClick={() => runMtlsTest('legit')}
                    disabled={mtlsLoading}
                    className="p-3.5 rounded-xl border border-emerald-800/40 bg-[#081810] hover:bg-[#0c2418] disabled:opacity-50 text-left transition-all cursor-pointer group"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-emerald-300 group-hover:text-emerald-200">
                        1. Legitimate Fast Path
                      </span>
                      <span className="text-xs">⚡</span>
                    </div>
                    <p className="text-[11px] text-emerald-400/80 mt-1">
                      Simulate Alice with valid certificate. Reuses cached decision (&lt;0.05ms).
                    </p>
                  </button>

                  <button
                    onClick={() => runMtlsTest('replay')}
                    disabled={mtlsLoading}
                    className="p-3.5 rounded-xl border border-rose-800/40 bg-[#1e0a0e] hover:bg-[#2c0e14] disabled:opacity-50 text-left transition-all cursor-pointer group"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-rose-300 group-hover:text-rose-200">
                        2. Token Replay / Mismatch
                      </span>
                      <span className="text-xs">🚨</span>
                    </div>
                    <p className="text-[11px] text-rose-400/80 mt-1">
                      Attacker presents stolen session with rogue cert. Triggers DET-06 & cache eviction.
                    </p>
                  </button>

                  <button
                    onClick={() => runMtlsTest('rotate')}
                    disabled={mtlsLoading}
                    className="p-3.5 rounded-xl border border-cyan-800/40 bg-[#081420] hover:bg-[#0c1e30] disabled:opacity-50 text-left transition-all cursor-pointer group"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-cyan-300 group-hover:text-cyan-200">
                        3. Approved Rotation
                      </span>
                      <span className="text-xs">🔄</span>
                    </div>
                    <p className="text-[11px] text-cyan-400/80 mt-1">
                      Authorized certificate rollover. Seamless transition with zero false positives.
                    </p>
                  </button>
                </div>

                {/* Simulation Result Box */}
                {mtlsResult && (
                  <div className="mt-4 p-4 rounded-xl border border-[#1e1e2c] bg-[#060609] space-y-3 font-mono">
                    <div className="flex items-center justify-between border-b border-[#14141e] pb-2">
                      <div className="flex items-center space-x-2">
                        <span className="text-[11px] text-zinc-400 uppercase">Decision Result:</span>
                        <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full ${
                          mtlsResult.decision === 'ALLOW'
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-700/50'
                            : mtlsResult.decision === 'REVOKE_SESSION' || mtlsResult.decision === 'REVOKE'
                            ? 'bg-rose-950 text-rose-300 border border-rose-700/50 animate-pulse'
                            : 'bg-amber-950 text-amber-300 border border-amber-700/50'
                        }`}>
                          {mtlsResult.decision}
                        </span>
                        <span className="text-xs px-2 py-0.5 rounded bg-[#10141e] text-cyan-300 border border-cyan-800/40">
                          {mtlsResult.decision_path}
                        </span>
                      </div>
                      <span className="text-xs text-zinc-400">
                        Binding: <span className={mtlsResult.binding_status === 'MISMATCH' ? 'text-rose-400 font-bold' : 'text-emerald-400'}>{mtlsResult.binding_status}</span>
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      <div>
                        <div className="text-zinc-500 text-[10px]">REASON</div>
                        <div className="text-zinc-200 mt-0.5">{mtlsResult.reason}</div>
                      </div>
                      <div>
                        <div className="text-zinc-500 text-[10px]">CACHE INVALIDATED</div>
                        <div className="text-zinc-200 mt-0.5 font-bold">
                          {mtlsResult.cache_invalidated ? 'YES (Immediate Eviction)' : 'NO (Cache Valid)'}
                        </div>
                      </div>
                    </div>

                    {mtlsResult.alert && (
                      <div className="p-3 rounded-lg border border-rose-800/40 bg-[#160608] text-xs space-y-1">
                        <div className="text-rose-300 font-bold flex items-center space-x-1">
                          <span>🚨</span>
                          <span>DET-06 Violation Alert Dispatched</span>
                        </div>
                        <div className="text-zinc-300 text-[11px]">{mtlsResult.alert.what}</div>
                        <div className="text-rose-400/90 text-[10px] truncate">
                          Action: {mtlsResult.alert.recommended_action} | Impact: {mtlsResult.alert.impact}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Zero Trust Architecture Spec Card */}
              <div className="p-6 border border-[#181824] rounded-2xl bg-[#08080c] space-y-3 font-mono">
                <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400">
                  Cryptographic Token-Binding Architecture
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 rounded-xl border border-[#161620] bg-[#0a0a10]">
                    <div className="text-cyan-400 font-semibold mb-1">1. Bound Proof-of-Possession</div>
                    <div className="text-zinc-400 text-[11px]">
                      Tokens are mathematically coupled to the client's mutual TLS certificate (SHA-256 fingerprint). Bearer tokens cannot be replayed from an external machine without the private key.
                    </div>
                  </div>
                  <div className="p-3 rounded-xl border border-[#161620] bg-[#0a0a10]">
                    <div className="text-cyan-400 font-semibold mb-1">2. Sub-Millisecond Fast Path</div>
                    <div className="text-zinc-400 text-[11px]">
                      When risk &lt; 30 and fingerprint matches cached session binding, decisions complete in ~0.013 ms (74,000+ req/sec), bypassing multi-hop graph re-evaluation.
                    </div>
                  </div>
                  <div className="p-3 rounded-xl border border-[#161620] bg-[#0a0a10]">
                    <div className="text-cyan-400 font-semibold mb-1">3. Atomic Invalidation</div>
                    <div className="text-zinc-400 text-[11px]">
                      Any certificate mismatch immediately triggers DET-06, evicts the session from cache, and dispatches a REVOKE_SESSION action to prevent unauthorized lateral traversal.
                    </div>
                  </div>
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
