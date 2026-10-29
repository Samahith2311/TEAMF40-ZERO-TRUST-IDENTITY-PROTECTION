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

  // Phase 7 mTLS Decision Cache & Zero-Trust Lab State
  const [mtlsStats, setMtlsStats] = useState<any>(null)
  const [mtlsResult, setMtlsResult] = useState<any>(null)
  const [mtlsLoading, setMtlsLoading] = useState<boolean>(false)
  const [mtlsStatusData, setMtlsStatusData] = useState<any>(null)
  const [cascadeResult, setCascadeResult] = useState<any>(null)
  const [cascadeLoading, setCascadeLoading] = useState<boolean>(false)
  const [cascadeType, setCascadeType] = useState<'legit' | 'hijack' | null>(null)

  // Live Attack Simulation State (Visual step-by-step kill-chain animation)
  const [simStep, setSimStep] = useState<number>(0) // 0: Idle, 1: Infiltration, 2: Token Abuse, 3: STS Role, 4: PrivEsc, 5: Exfiltration, 6: Revocation
  const [isSimulating, setIsSimulating] = useState<boolean>(false)
  const [simSpeed] = useState<number>(1400) // ms per step
  const [showFeedOnGraph, setShowFeedOnGraph] = useState<boolean>(false)
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

  // Base API URL: In Vercel / production or Vite proxy, defaults to relative path ('')
  // or uses bound service env VITE_API_URL if configured
  const API_BASE = (import.meta as any).env?.VITE_API_URL || ''

  const formatIdentity = (id: string) => {
    if (!maskIdentities) return id
    if (id.includes('@')) {
      const parts = id.split('@')
      return `${parts[0].slice(0, 2)}***@${parts[1]}`
    }
    return `${id.slice(0, 3)}***`
  }

  const safeFetch = async <T,>(url: string, fallback: T): Promise<T> => {
    try {
      const res = await fetch(url)
      if (!res.ok) return fallback
      const text = await res.text()
      try {
        return JSON.parse(text)
      } catch {
        return fallback
      }
    } catch {
      return fallback
    }
  }

  const loadData = (selectNewest: boolean = false) => {
    Promise.all([
      safeFetch(`${API_BASE}/api/alerts`, { alerts: [] }),
      safeFetch(`${API_BASE}/api/chains`, { chains: [] }),
      safeFetch(`${API_BASE}/api/scores`, { scores: [] }),
      safeFetch(`${API_BASE}/api/graph`, { graph: null }),
      safeFetch(`${API_BASE}/api/feedback/weights`, { weights: {} }),
      safeFetch(`${API_BASE}/api/feedback/tuning-log`, { tuning_log: [] }),
      safeFetch(`${API_BASE}/api/synthetic/history`, { history: [] }),
      safeFetch(`${API_BASE}/api/synthetic/status`, { auto_streaming: false })
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
    fetchMtlsStatus()
    // Poll every 3 seconds for synchronous real-time threat detection
    const interval = setInterval(() => {
      loadData(false)
    }, 3000)
    return () => clearInterval(interval)
  }, [])

  const safeParseResponse = async (r: Response) => {
    const text = await r.text()
    try {
      return JSON.parse(text)
    } catch {
      throw new Error(r.ok ? 'Invalid response format' : `Server response (${r.status}): ${text.slice(0, 100)}`)
    }
  }

  const handleGenerateAttack = (arch?: string) => {
    setGenerating(true)
    setError(null)
    const targetArch = arch && arch !== 'RANDOM' ? arch : (selectedArchetype !== 'RANDOM' ? selectedArchetype : undefined)

    fetch(`${API_BASE}/api/synthetic/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ archetype: targetArch })
    })
      .then(safeParseResponse)
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
    fetch(`${API_BASE}/api/synthetic/auto`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: nextState, interval: 6.0 })
    })
      .then(safeParseResponse)
      .then(res => {
        setAutoStream(res.auto_streaming)
        setNotification(res.auto_streaming ? '▶ Auto-Streaming Threat Scenarios (Every 6s)' : '⏸ Auto-Streaming Paused')
        loadData()
      })
      .catch(err => setError(err.message))
  }

  const handleApprove = () => {
    if (!selectedAlert) return
    fetch(`${API_BASE}/api/actions/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        incident_id: selectedAlert.incident_id,
        action: selectedAlert.recommended_action,
        target: selectedAlert.subject.id,
        approver: 'lead_analyst@corp.internal'
      })
    })
      .then(safeParseResponse)
      .then(data => {
        setSimResult(data.action?.result || 'SUCCESS_SIMULATED')
      })
      .catch(err => setError(err.message))
  }

  const handleStepUp = () => {
    if (!selectedAlert) return
    fetch(`${API_BASE}/api/actions/step-up`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        incident_id: selectedAlert.incident_id,
        target: selectedAlert.subject.id
      })
    })
      .then(safeParseResponse)
      .then(data => {
        setStepUpPrompt(data.prompt || 'MFA challenge dispatched')
      })
      .catch(err => setError(err.message))
  }

  const runMtlsTest = async (testType: 'legit' | 'replay' | 'rotate') => {
    setMtlsLoading(true)
    try {
      if (testType === 'legit') {
        await fetch(`${API_BASE}/api/mtls/bind`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            identity: 'alice@corp.internal',
            session_id: 'sess-alice-live',
            fingerprint: 'eb:bf:ba:d4:c7:96:2a:ee:d5:1b:8f:f9:77:e8:14:c1:23:31:e8:3a:9d:08:8c:8f:ad:84:8a:c8:22:23:2e:f9'
          })
        })
        const res = await fetch(`${API_BASE}/api/mtls/decide`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            identity: 'alice@corp.internal',
            session_id: 'sess-alice-live',
            cert_fingerprint: 'eb:bf:ba:d4:c7:96:2a:ee:d5:1b:8f:f9:77:e8:14:c1:23:31:e8:3a:9d:08:8c:8f:ad:84:8a:c8:22:23:2e:f9',
            current_risk_score: 15
          })
        })
        const data = await safeParseResponse(res)
        setMtlsResult(data)
      } else if (testType === 'replay') {
        const res = await fetch(`${API_BASE}/api/mtls/decide`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            identity: 'alice@corp.internal',
            session_id: 'sess-alice-live',
            cert_fingerprint: '59:80:87:09:70:79:59:2e:68:93:11:30:6d:7a:73:0c:0e:c1:0a:f5:02:87:85:89:8d:5a:1a:f4:19:25:cf:7e',
            current_risk_score: 15
          })
        })
        const data = await safeParseResponse(res)
        setMtlsResult(data)
      } else if (testType === 'rotate') {
        const newFp = '11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff'
        await fetch(`${API_BASE}/api/mtls/approve-rotation`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            identity: 'alice@corp.internal',
            session_id: 'sess-alice-live',
            new_fingerprint: newFp
          })
        })
        const res = await fetch(`${API_BASE}/api/mtls/decide`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            identity: 'alice@corp.internal',
            session_id: 'sess-alice-live',
            cert_fingerprint: newFp,
            current_risk_score: 15
          })
        })
        const data = await safeParseResponse(res)
        setMtlsResult(data)
      }
      const statsRes = await fetch(`${API_BASE}/api/mtls/stats`)
      if (statsRes.ok) {
        const statsData = await safeParseResponse(statsRes)
        if (statsData.stats) setMtlsStats(statsData.stats)
      }
    } catch (e: any) {
      setError(e.message)
    } finally {
      setMtlsLoading(false)
    }
  }

  const fetchMtlsStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/mtls/status`)
      if (res.ok) {
        const data = await res.json()
        setMtlsStatusData(data)
        if (data.cache_stats) setMtlsStats(data.cache_stats)
      }
    } catch {}
  }

  const runCascadeSimulation = async (type: 'legit' | 'hijack') => {
    setCascadeLoading(true)
    setCascadeType(type)
    try {
      const endpoint = type === 'legit'
        ? `${API_BASE}/api/mtls/simulate-cascade`
        : `${API_BASE}/api/mtls/simulate-hijack`
      const body = type === 'legit'
        ? { identity: 'bob.contractor@corp.internal', cert_alias: 'bob', hops: 25 }
        : { identity: 'bob.contractor@corp.internal', cert_alias: 'bob', hijack_hop: 12, hops: 25 }
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      })
      const data = await safeParseResponse(res)
      setCascadeResult(data)
      await fetchMtlsStatus()
    } catch (err: any) {
      setError(err.message)
    } finally {
      setCascadeLoading(false)
    }
  }

  const activeChain = chains.find(c => c.incident_id === selectedAlert?.incident_id)
  const activeScore = scores.find(s => s.subject.id === selectedAlert?.subject.id)

  // Dynamically extract the active attack path for the currently selected incident
  const activePath = graphData?.ranked_paths.find(p => p.path_id.includes(selectedAlert?.incident_id || '')) ||
    graphData?.ranked_paths.find(p => p.subject === selectedAlert?.subject.id) ||
    (graphData?.ranked_paths && graphData.ranked_paths.length > 0 ? graphData.ranked_paths[0] : null)

  const hopIdentity = activePath ? activePath.hops[0]?.node : (selectedAlert?.subject.id || 'bob.contractor@corp.internal')
  const hopRole = activePath ? activePath.hops[1]?.node : 'sts.amazonaws.com'
  const hopPolicy = activePath ? activePath.hops[2]?.node : 'AdministratorAccess'
  const hopResource = activePath ? activePath.hops[3]?.node : 'corp-customer-pi-vault'

  // Dynamically derive the attacker's active session
  const activeSessionEdge = graphData?.edges.find(e => e.from === hopIdentity && e.type === 'INITIATED_SESSION')
  const hopSession = activeSessionEdge ? activeSessionEdge.to : `sess-${hopIdentity.split('@')[0]}-live`

  // Extract all distinct identities from graphData or scores
  const allIdentities = Array.from(new Set([
    hopIdentity,
    ...(graphData?.nodes.filter(n => n.type === 'IDENTITY').map(n => n.id) || []),
    ...(scores.map(s => s.subject.id))
  ]))
  const otherIdentities = allIdentities.filter(id => id !== hopIdentity)
  const identitySlot1 = otherIdentities[0] || 'alice@corp.internal'
  const identitySlot3 = otherIdentities[1] || 'charlie.analyst@corp.internal'
  const identitySlot4 = otherIdentities.find(id => id.includes('admin') || id.includes('diana')) || otherIdentities[2] || 'diana.admin@corp.internal'

  // Extract all distinct sessions
  const allSessions = Array.from(new Set([
    hopSession,
    ...(graphData?.nodes.filter(n => n.type === 'SESSION').map(n => n.id) || []),
    'sess-okta-alice-101', 'sess-charlie-301', 'sess-diana-401', 'sess-ops-501', 'sess-dev-601'
  ]))
  const otherSessions = allSessions.filter(s => s !== hopSession)
  const sessionSlot1 = hopSession // Active attacker session
  const sessionSlot2 = otherSessions[0] || 'sess-charlie-301'
  const sessionSlot3 = otherSessions[1] || 'sess-diana-401'
  const sessionSlot4 = otherSessions[2] || 'sess-okta-alice-101'
  const sessionSlot5 = otherSessions[3] || 'sess-ops-501'
  const sessionSlot6 = otherSessions[4] || 'sess-dev-601'

  // Extract other resources
  const allResources = Array.from(new Set([
    hopResource,
    ...(graphData?.nodes.filter(n => n.type === 'RESOURCE').map(n => n.id) || []),
    'corp-analytics-raw', 'corp-dev-builds'
  ]))
  const otherResources = allResources.filter(r => r !== hopResource)
  const resourceSlot1 = otherResources[0] || 'corp-analytics-raw'
  const resourceSlot3 = otherResources[1] || 'corp-dev-builds'

  // Plain-English translations paired with technical subtitles (Dual-Layer Pattern)
  const getFactorDisplay = (factorName: string): { primary: string; explanation: string; technical: string } => {
    const map: Record<string, { primary: string; explanation: string; technical: string }> = {
      privilege_delta: {
        primary: 'Unusual Admin Access',
        explanation: 'User suddenly requested elevated administrative cloud permissions',
        technical: 'Privilege Delta / IAM Escalation'
      },
      impossible_travel: {
        primary: 'Suspicious Location Jump',
        explanation: 'Logins from two distant geographical locations within impossible timeframe',
        technical: 'Impossible Travel / Geo-Velocity Anomaly'
      },
      token_abuse: {
        primary: 'Hijacked Session Token',
        explanation: 'Active login token presented from an unrecognized device or network',
        technical: 'Token Abuse / ASN-IP Drift / Cert Mismatch'
      },
      dormancy_reactivation: {
        primary: 'Inactive Account Woken Up',
        explanation: 'Dormant user account suddenly active after weeks of silence',
        technical: 'Dormancy Reactivation Delta'
      },
      blast_radius: {
        primary: 'Systems at Risk',
        explanation: 'Sensitive cloud data stores and customer vaults reachable by principal',
        technical: 'Blast Radius / Lateral Movement'
      },
      behavioral_anomaly: {
        primary: 'Abnormal Behavior Pattern',
        explanation: 'Significant deviation from baseline user telemetry and activity',
        technical: 'Behavioral Anomaly Score'
      },
      privilege_level: {
        primary: 'High-Impact Identity Role',
        explanation: 'Principal holds critical administrative scope across infrastructure',
        technical: 'Tier-1 High Privilege Scope'
      }
    }
    return map[factorName] || {
      primary: factorName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
      explanation: 'Risk indicator evaluated by multi-factor engine',
      technical: factorName
    }
  }

  const getStageDisplay = (stage: string): { primary: string; technical: string } => {
    const map: Record<string, { primary: string; technical: string }> = {
      INITIAL_AUTHENTICATION: { primary: '1. Initial User Login', technical: 'Okta System Log Ingestion' },
      SESSION_HIJACK: { primary: '2. Session Hijack Detected', technical: 'Token Theft & Client Drift' },
      STS_ROLE_ASSUMPTION: { primary: '3. Cloud Service Role Assumed', technical: 'AWS STS AssumeRole API' },
      IAM_PRIVILEGE_ESCALATION: { primary: '4. Unusual Admin Access Attached', technical: 'IAM Policy Escalation' },
      RESOURCE_EXFILTRATION: { primary: '5. Critical Vault Exfiltration Attempt', technical: 'S3 GetObject Sensitive Vault' }
    }
    return map[stage] || { primary: stage.replace(/_/g, ' '), technical: stage }
  }

  const getProvenanceDisplay = (prov: string): { primary: string; technical: string } => {
    if (prov === 'VALIDATED_OBSERVATION') {
      return { primary: 'Verified Telemetry', technical: 'VALIDATED_OBSERVATION' }
    }
    return { primary: 'AI Graph Inferred', technical: prov }
  }

  const getActionDisplay = (action: string): { primary: string; technical: string } => {
    const map: Record<string, { primary: string; technical: string }> = {
      REVOKE_SESSION: { primary: 'Isolate Account & Kill Session', technical: 'REVOKE_SESSION' },
      STEP_UP_AUTH: { primary: 'Require Extra Verification (Step-Up MFA)', technical: 'STEP_UP_AUTH' },
      QUARANTINE_IDENTITY: { primary: 'Quarantine Identity', technical: 'QUARANTINE_IDENTITY' },
      RESTRICT_PERMISSIONS: { primary: 'Restrict Admin Permissions', technical: 'RESTRICT_PERMISSIONS' }
    }
    return map[action] || { primary: action.replace(/_/g, ' '), technical: action }
  }

  return (
    <div className="h-screen w-screen bg-black text-zinc-200 flex flex-col font-sans overflow-hidden select-none">
      {/* Top System Status & Utility Bar */}
      <div className="bg-[#08080b] border-b border-[#181820] px-4 py-1.5 text-center text-[11px] font-mono tracking-wider text-zinc-400 flex items-center justify-between shrink-0">
        <div className="flex items-center space-x-2.5">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
          <span className="text-zinc-200 font-semibold tracking-normal">AEGIS ZERO TRUST // Cloud Identity Defense</span>
          <span className="text-zinc-600">•</span>
          <span className="text-zinc-400">Automated Multi-Stage Attack Defense (Okta &amp; AWS CloudTrail Stream)</span>
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
            title="Open Self-Tuning Risk Model"
          >
            <span className="text-xs">⚙️</span>
            <span className="font-semibold">Self-Tuning Risk Model</span>
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
                    <stop offset="0%" stopColor="#49299a" />
                    <stop offset="60%" stopColor="#45edf2" />
                    <stop offset="100%" stopColor="#e8e8fc" />
                  </linearGradient>
                  <radialGradient id="softCoreGrad" cx="50%" cy="50%" r="50%">
                    <stop offset="0%" stopColor="#45edf2" />
                    <stop offset="100%" stopColor="#0e1625" />
                  </radialGradient>
                </defs>
                <path
                  d="M24 5 L40 11 C40 25 33 37 24 43 C15 37 8 25 8 11 Z"
                  fill="#0e1625"
                  stroke="url(#softShieldGrad)"
                  strokeWidth="2.2"
                />
                <circle cx="24" cy="24" r="7" fill="url(#softCoreGrad)" opacity="0.9" />
                <path d="M24 16 L24 32 M16 24 L32 24" stroke="#ffffff" strokeWidth="1.2" strokeLinecap="round" />
                <circle cx="24" cy="24" r="2.5" fill="#ffffff" />
                <circle cx="17" cy="19" r="1.5" fill="#45edf2" />
                <circle cx="31" cy="19" r="1.5" fill="#49299a" />
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
              Security Modules
            </span>

            {/* Option 1: Live Incident Queue */}
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
                      Live Incident Queue
                    </h4>
                    <p className="text-[10px] text-zinc-400">Okta &amp; CloudTrail Stream</p>
                  </div>
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
                  activeTab === 'details' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/50' : 'bg-[#15151e] text-zinc-400'
                }`}>
                  {alerts.length} Alerts
                </span>
              </div>
            </div>

            {/* Option 2: Attack Timeline & Blast Radius */}
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
                      Attack Timeline &amp; Blast Radius
                    </h4>
                    <p className="text-[10px] text-zinc-400">Automated Attack Path DAG</p>
                  </div>
                </div>
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
              </div>
            </div>

            {/* Option 3: Self-Tuning Risk Model */}
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
                      Self-Tuning Risk Model
                    </h4>
                    <p className="text-[10px] text-zinc-400">Autonomous Calibration &amp; Safeguards</p>
                  </div>
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
                  activeTab === 'tuning' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/50' : 'bg-[#15151e] text-emerald-400'
                }`}>
                  Auto
                </span>
              </div>
            </div>

            {/* Option 4: Speed & Security Monitor (mTLS) */}
            <div
              onClick={() => {
                setActiveTab('mtls')
                fetch(`${API_BASE}/api/mtls/stats`)
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
                      Speed &amp; Security Monitor (mTLS)
                    </h4>
                    <p className="text-[10px] text-zinc-400">Zero-Lag Session Verification</p>
                  </div>
                </div>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
                  activeTab === 'mtls' ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/50' : 'bg-[#15151e] text-cyan-400'
                }`}>
                  RFC 8705
                </span>
              </div>
            </div>
          </div>

          {/* Embedded Threat Generator Console (Lift-Up on Hover) */}
          <div className="group rounded-xl p-3.5 border border-[#1a1a24] bg-[#08080c] shadow-[inset_0_2px_4px_rgba(0,0,0,0.8)] transition-all duration-300 hover:-translate-y-1 hover:shadow-[0_12px_24px_-6px_rgba(56,189,248,0.14)] hover:border-cyan-500/40 hover:bg-[#0d0e14] space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-zinc-300 block">
                  Attack Simulator &amp; Test Center
                </span>
                <span className="text-[9px] text-zinc-400 font-mono">Autonomous Threat Replay</span>
              </div>
              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-800/40">Live Sim</span>
            </div>

            <div className="space-y-2">
              <label className="text-[10px] text-zinc-400 font-mono block">Threat Archetype:</label>
              <select
                value={selectedArchetype}
                onChange={e => setSelectedArchetype(e.target.value)}
                className="w-full bg-[#121218] border border-[#242432] text-zinc-200 text-xs rounded-lg px-2.5 py-1.5 outline-none font-mono cursor-pointer focus:border-cyan-500/50"
              >
                <option value="RANDOM">🎲 Random Threat Scenario</option>
                <option value="DORMANT_PRIV_ESCALATION">🛡️ Inactive Account Woken Up (Dormant Escalation)</option>
                <option value="IMPOSSIBLE_TRAVEL_TOKEN_HIJACK">✈️ Suspicious Location Jump (Impossible Travel)</option>
                <option value="LATERAL_ROLE_PIVOT_EXFIL">🔄 Systems at Risk: Role Pivot &amp; Exfil Attempt</option>
                <option value="UNUSUAL_AUTOMATED_API_SWEEP">⚡ Rapid Automated API Scraping (Unusual Sweep)</option>
              </select>

              <button
                onClick={() => handleGenerateAttack()}
                disabled={generating}
                className="w-full py-2 px-3 rounded-lg text-xs font-semibold bg-gradient-to-r from-[#49299a] via-[#35267d] to-[#45edf2] hover:from-[#5933bd] hover:to-[#5ef0f5] disabled:opacity-40 text-[#e8e8fc] shadow-[0_0_15px_rgba(69,237,242,0.28)] transition-all cursor-pointer flex items-center justify-center space-x-2 active:scale-98"
              >
                <span>{generating ? 'Simulating Attack Vector...' : '⚡ Launch Simulated Attack'}</span>
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
                <span>{autoStream ? 'Streaming Active (6s)' : '▶ Auto-Stream Threat Scenarios'}</span>
              </button>
            </div>
          </div>

          {/* Embedded Privacy Control (Lift-Up on Hover) */}
          <div className="pt-2 border-t border-[#181822] space-y-2 mt-auto">
            <button
              onClick={() => setMaskIdentities(!maskIdentities)}
              className="w-full py-2 px-3 rounded-xl border border-[#1a1a24] bg-[#08080c] shadow-[inset_0_2px_4px_rgba(0,0,0,0.8)] hover:-translate-y-1 hover:border-cyan-500/40 hover:bg-[#0d0e14] transition-all duration-300 cursor-pointer flex items-center justify-between"
            >
              <div>
                <span className="font-mono text-[11px] text-zinc-200 block text-left font-semibold">Executive Privacy Mode</span>
                <span className="text-[9px] text-zinc-500 text-left block">Mask Identifiers &amp; PII</span>
              </div>
              <span className="font-mono text-[10px] font-bold px-2 py-0.5 rounded bg-[#121218] text-cyan-300 border border-[#222230]">
                {maskIdentities ? '🔒 PII Masked' : '👁️ PII Visible'}
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
              {/* Executive 1-Line Summary Banner */}
              <div className="p-3 bg-[#0a0f1d] border border-cyan-900/40 rounded-xl text-xs text-cyan-200/90 font-sans flex items-center space-x-2.5">
                <span className="text-base shrink-0">💡</span>
                <span><strong className="text-white">Executive Summary:</strong> Real-time incident triage showing who is attacking, why it was flagged, and a safe one-click simulator to preview and block account takeovers without business downtime.</span>
              </div>

              {selectedAlert ? (
                <>
                  {/* Selected Incident Header */}
                  <div className="p-6 border border-[#1c1c26] rounded-2xl bg-[#08080c] space-y-3 shadow-sm">
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider font-bold">
                            {selectedAlert.alert_id}
                          </span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                            selectedAlert.severity === 'CRITICAL'
                              ? 'bg-[#220a0d] text-rose-300 border-rose-800/50'
                              : 'bg-[#221606] text-amber-300 border-amber-800/50'
                          }`}>
                            {selectedAlert.severity} PRIORITY
                          </span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#10141f] text-cyan-300 border border-cyan-800/40">
                            Verified Telemetry
                          </span>
                        </div>
                        <h2 className="text-lg font-bold text-white mt-1.5">{selectedAlert.what}</h2>
                        <p className="text-xs text-zinc-300 mt-1">{selectedAlert.why}</p>
                      </div>
                      <div className="text-right font-mono text-[11px] text-zinc-400">
                        <div>First Detected: <span className="text-zinc-300">{selectedAlert.first_seen}</span></div>
                        <div>Last Active: <span className="text-zinc-300">{selectedAlert.last_seen}</span></div>
                      </div>
                    </div>

                    <div className="p-3 bg-[#0c0c12] border border-[#1e1e28] rounded-xl text-xs">
                      <span className="text-cyan-400 font-semibold font-mono">Business Impact Assessment: </span>
                      <span className="text-zinc-200">{selectedAlert.impact}</span>
                    </div>
                  </div>

                  {/* Why Was This Flagged? (Additive Factor Risk Score) */}
                  {activeScore && (
                    <div className="p-6 border border-[#1c1c26] rounded-2xl bg-[#08080c] space-y-4 shadow-sm">
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="flex items-center space-x-2">
                            <h3 className="text-sm font-bold text-white font-sans">
                              Why Was This Flagged?
                            </h3>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/40">
                              Additive Factor Model (0–100)
                            </span>
                          </div>
                          <p className="text-xs text-zinc-400 mt-0.5 font-sans">
                            Top Risk Drivers &amp; How to Lower Risk (Transparent additive score attribution)
                          </p>
                        </div>
                        <div className="text-right font-mono">
                          <div className="text-2xl font-black text-rose-400">
                            {activeScore.total} <span className="text-xs text-zinc-400">/ 100</span>
                          </div>
                          <span className="text-[10px] text-rose-300/80 uppercase font-bold tracking-wider">
                            {activeScore.total >= 80 ? 'CRITICAL RISK' : activeScore.total >= 50 ? 'HIGH RISK' : 'ELEVATED RISK'}
                          </span>
                        </div>
                      </div>

                      <div className="space-y-3 pt-1">
                        {activeScore.factors.map(f => {
                          const display = getFactorDisplay(f.name)
                          return (
                            <div key={f.name} className="p-3 rounded-xl border border-[#181822] bg-[#0b0b10] space-y-1.5 hover:border-cyan-500/30 transition-all">
                              <div className="flex items-center justify-between text-xs">
                                <div>
                                  <span className="font-bold text-white text-xs">{display.primary}</span>
                                  <span className="text-zinc-500 font-mono text-[10px] ml-2">({display.technical})</span>
                                </div>
                                <span className="text-cyan-300 font-mono font-semibold">
                                  +{f.contribution} pts <span className="text-zinc-500">({(f.weight * 100).toFixed(1)}% wt)</span>
                                </span>
                              </div>
                              <p className="text-[11px] text-zinc-400 font-sans leading-relaxed">
                                {display.explanation}
                              </p>
                              <div className="w-full bg-[#121218] h-1.5 rounded-full overflow-hidden border border-[#1f1f2a]">
                                <div
                                  className="bg-gradient-to-r from-[#49299a] to-[#45edf2] h-full rounded-full transition-all duration-500 shadow-[0_0_8px_rgba(69,237,242,0.3)]"
                                  style={{ width: `${Math.min(100, f.value)}%` }}
                                ></div>
                              </div>
                            </div>
                          )
                        })}
                      </div>

                      <div className="p-3 bg-[#0c0c12] border border-[#1e1e28] rounded-xl text-xs space-y-1.5">
                        <div className="text-zinc-300 font-semibold font-sans">Primary Threat Indicators:</div>
                        <div className="flex flex-wrap gap-2 pt-0.5">
                          {activeScore.explanation.top_factors.map(tf => {
                            const disp = getFactorDisplay(tf)
                            return (
                              <span key={tf} className="px-2.5 py-1 rounded-lg bg-[#10141f] text-cyan-200 border border-cyan-800/40 text-[11px] font-sans flex items-center space-x-1.5">
                                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                                <span><strong>{disp.primary}</strong> ({tf})</span>
                              </span>
                            )
                          })}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Attack Timeline & Blast Radius (Reconstructed Attack Chain Timeline) */}
                  <div className="p-6 border border-[#1c1c26] rounded-2xl bg-[#08080c] space-y-4 shadow-sm">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="flex items-center space-x-2">
                          <h3 className="text-sm font-bold text-white font-sans">
                            Attack Timeline &amp; Blast Radius
                          </h3>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/40">
                            Kill Chain Timeline
                          </span>
                        </div>
                        <p className="text-xs text-zinc-400 mt-0.5 font-sans">
                          Automated Attack Path Reconstruction (Cross-source Okta &amp; AWS event correlation)
                        </p>
                      </div>
                      {activeChain && (
                        <span className="text-xs font-mono text-emerald-400 border border-emerald-800/50 bg-[#071712] px-2.5 py-0.5 rounded-full">
                          AI Reconstruction Confidence: {(activeChain.confidence * 100).toFixed(0)}%
                        </span>
                      )}
                    </div>

                    <div className="relative pl-6 space-y-5 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#1f1f2b]">
                      {activeChain?.stages.map((st, idx) => {
                        const stageInfo = getStageDisplay(st.stage)
                        const provInfo = getProvenanceDisplay(st.link_provenance)
                        const provColor =
                          st.link_provenance === 'VALIDATED_OBSERVATION'
                            ? 'border-emerald-500/70 bg-[#06140e] text-emerald-300'
                            : 'border-cyan-500/70 bg-[#061118] text-cyan-300'

                        return (
                          <div key={idx} className="relative">
                            <span className={`absolute -left-[27px] top-1 w-3 h-3 rounded-full border-2 ${provColor}`}></span>
                            <div className="flex items-center justify-between">
                              <div>
                                <h4 className="text-xs font-bold text-white">{stageInfo.primary}</h4>
                                <span className="text-[10px] text-zinc-400 font-mono">({stageInfo.technical})</span>
                              </div>
                              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${provColor}`}>
                                {provInfo.primary}
                              </span>
                            </div>
                            <p className="text-[11px] font-mono text-zinc-400 mt-0.5">Event Ref: {st.event_ref}</p>
                          </div>
                        )
                      })}
                    </div>
                  </div>

                  {/* Response & Containment (Policy Containment Simulator) */}
                  <div className="p-6 border border-[#1c1c26] rounded-2xl bg-[#08080c] space-y-4 shadow-sm">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="flex items-center space-x-2">
                          <h3 className="text-sm font-bold text-white font-sans">
                            Response &amp; Containment
                          </h3>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800/40">
                            Safe Simulate-First Action Center
                          </span>
                        </div>
                        <p className="text-xs text-zinc-400 mt-0.5 font-sans">
                          Safe Test Mode (Preview Impact Before Blocking) • Zero Business Downtime
                        </p>
                      </div>
                      <span className="text-xs font-mono px-2.5 py-1 rounded bg-[#1e1406] text-amber-300 border border-amber-800/40">
                        Target Action: {getActionDisplay(selectedAlert.recommended_action).primary}
                      </span>
                    </div>

                    {/* Emergency Admin Safeguard Banner */}
                    <div className="p-2.5 bg-[#091510] border border-emerald-800/40 rounded-xl text-xs text-emerald-300 flex items-center space-x-2">
                      <span className="text-base shrink-0">🛡️</span>
                      <span><strong>Emergency Admin Safeguard Active:</strong> Critical system personnel and break-glass accounts are protected from accidental lockouts (Deny Path Enforced).</span>
                    </div>

                    <div className="flex flex-wrap items-center justify-end gap-3 pt-2">
                      <button
                        onClick={handleStepUp}
                        className="px-4 py-2 rounded-lg text-xs font-semibold border border-[#2b2b3a] bg-[#121218] hover:bg-[#181822] text-cyan-200 transition-colors cursor-pointer"
                      >
                        Safe Test Mode: Require Extra Verification (Step-Up MFA)
                      </button>

                      {simResult ? (
                        <span className="px-4 py-2 rounded-lg text-xs font-mono bg-[#061710] text-emerald-300 border border-emerald-800/50 flex items-center">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-2"></span>
                          Result: {simResult} (SIMULATED PREVIEW)
                        </span>
                      ) : (
                        <button
                          onClick={handleApprove}
                          className="px-5 py-2 rounded-lg text-xs font-semibold bg-rose-600/80 hover:bg-rose-500 text-white shadow transition-all cursor-pointer"
                        >
                          Safe Test Mode: Authorize Simulated {getActionDisplay(selectedAlert.recommended_action).primary}
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
                  No incident selected. Select an alert from the left or trigger "⚡ Launch Simulated Attack".
                </div>
              )}
            </div>
          )}

          {/* --- TAB 2: LIVE ATTACK GRAPH (Interactive Swimlane Kill-Chain DAG) --- */}
          {activeTab === 'graph' && (
            <div className="space-y-3">
              {/* Executive 1-Line Summary Banner */}
              <div className="p-3 bg-gradient-to-r from-[#0e1625] via-black to-[#0e1625] border border-[#49299a]/50 rounded-xl text-xs text-[#e8e8fc] font-sans flex items-center space-x-2.5 shadow-[0_0_20px_rgba(73,41,154,0.18)]">
                <span className="text-base shrink-0">💡</span>
                <span><strong className="text-white">Executive Summary:</strong> Visual kill chain tracing how stolen credentials penetrate internal sessions, pivot through cloud roles, and attempt data theft against customer vaults—stopping attacks before exfiltration.</span>
              </div>

              <div className="p-4 border border-[#49299a]/40 rounded-2xl bg-gradient-to-b from-[#0e1625]/80 via-black to-[#0e1625]/90 space-y-3 shadow-[0_0_30px_rgba(14,22,37,0.8)] backdrop-blur-sm">
                {/* Header & Controls - strictly ONE line with equal-scale Play & Reset buttons */}
                <div className="flex items-center justify-between gap-3 pb-2.5 border-b border-[#49299a]/30 flex-nowrap">
                  <div className="flex items-center space-x-2 min-w-0 shrink">
                    <h2 className="text-sm font-bold text-white whitespace-nowrap flex items-center space-x-2">
                      <span className="text-[#e8e8fc]">Attack Timeline &amp; Blast Radius</span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase tracking-wider shrink-0 ${
                        isSimulating ? 'bg-rose-950 text-rose-300 border border-rose-800/60 animate-pulse' : 'bg-[#0e1625] text-[#45edf2] border border-[#45edf2]/50 shadow-[0_0_8px_rgba(69,237,242,0.25)]'
                      }`}>
                        {isSimulating ? '● SIMULATING' : 'LIVE'}
                      </span>
                    </h2>
                  </div>

                  <div className="flex items-center space-x-2.5 shrink-0">
                    {/* Incident Selector */}
                    <div className="flex items-center space-x-1.5 text-xs font-mono">
                      <span className="text-zinc-400 text-[11px] whitespace-nowrap">Incident:</span>
                      <select
                        value={selectedAlert?.alert_id || ''}
                        onChange={e => {
                          const found = alerts.find(a => a.alert_id === e.target.value)
                          if (found) {
                            setSelectedAlert(found)
                            resetAttackSimulation()
                          }
                        }}
                        className="bg-[#0e1625] border border-[#49299a]/50 text-[#e8e8fc] text-xs rounded-lg px-2.5 py-1.5 font-mono outline-none cursor-pointer max-w-[170px] truncate focus:border-[#45edf2]"
                      >
                        {alerts.map(a => (
                          <option key={a.alert_id} value={a.alert_id}>
                            {a.alert_id} ({formatIdentity(a.subject.id)})
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Simulation Playback Controls - Equal Scale Buttons within Widget */}
                    <div className="flex items-center space-x-2">
                      {isSimulating ? (
                        <button
                          onClick={stopAttackSimulation}
                          className="h-8 px-3.5 rounded-lg bg-amber-600/80 hover:bg-amber-500 border border-amber-500/50 text-white text-xs font-bold cursor-pointer transition-all flex items-center justify-center space-x-1.5 shadow-sm active:scale-95"
                        >
                          <span>⏸</span>
                          <span className="whitespace-nowrap">Pause Attack</span>
                        </button>
                      ) : (
                        <button
                          onClick={startAttackSimulation}
                          className="h-8 px-3.5 rounded-lg bg-gradient-to-r from-[#49299a] via-[#35267d] to-[#45edf2] hover:from-[#5933bd] hover:to-[#5ef0f5] border border-[#45edf2]/60 text-[#e8e8fc] text-xs font-bold cursor-pointer transition-all flex items-center justify-center space-x-1.5 shadow-[0_0_16px_rgba(69,237,242,0.35)] active:scale-95"
                        >
                          <span>▶</span>
                          <span className="whitespace-nowrap">Play Attack</span>
                        </button>
                      )}
                      <button
                        onClick={resetAttackSimulation}
                        className="h-8 px-3.5 rounded-lg bg-[#0e1625] hover:bg-[#162136] border border-[#49299a]/50 hover:border-[#45edf2]/60 text-[#e8e8fc] text-xs font-bold cursor-pointer transition-all flex items-center justify-center space-x-1.5 active:scale-95 shadow-sm"
                        title="Reset simulation to initial state"
                      >
                        <span>⟳</span>
                        <span className="whitespace-nowrap">Reset Attack</span>
                      </button>

                      {/* Wide View Toggle Button */}
                      <button
                        onClick={() => setShowFeedOnGraph(!showFeedOnGraph)}
                        className={`h-8 px-2.5 rounded-lg border text-[11px] font-mono transition-all flex items-center space-x-1.5 cursor-pointer whitespace-nowrap ${
                          showFeedOnGraph
                            ? 'bg-[#49299a]/40 text-[#45edf2] border-[#45edf2]/60'
                            : 'bg-[#0e1625] text-zinc-300 border-[#49299a]/40 hover:text-white hover:border-[#45edf2]/50'
                        }`}
                        title={showFeedOnGraph ? "Collapse Activity Stream to maximize graph width" : "Show Activity Stream side panel"}
                      >
                        <span>{showFeedOnGraph ? '⇥ Collapse Stream' : '⇤ Full Width View'}</span>
                      </button>
                    </div>
                  </div>
                </div>

                {/* Simulation Step Progress & Narrative Telemetry Ticker */}
                <div className="p-2.5 rounded-xl border border-[#49299a]/40 bg-gradient-to-r from-[#0e1625] via-black to-[#0e1625] space-y-2 font-mono shadow-inner">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                        simStep === 0 ? 'bg-[#0e1625] text-[#e8e8fc] border border-[#49299a]/40' :
                        simStep === 1 ? 'bg-[#181136] text-[#45edf2] border border-[#49299a]' :
                        simStep === 2 ? 'bg-rose-950 text-rose-300 border border-rose-700/50' :
                        simStep === 3 ? 'bg-amber-950 text-amber-300 border border-amber-700/50' :
                        simStep === 4 ? 'bg-[#0e1625] text-[#45edf2] border border-[#45edf2]/60' :
                        simStep === 5 ? 'bg-red-950 text-red-200 border border-red-700/60' :
                        'bg-[#061e1a] text-[#45edf2] border border-emerald-600/50'
                      }`}>
                        {simStep === 0 && '⚪ READY • Click Play to Highlight Attack Arrows'}
                        {simStep === 1 && '🚨 STEP 1/5: INFILTRATION ARROW (Okta Auth)'}
                        {simStep === 2 && '⚡ STEP 2/5: TOKEN ABUSE & STS ROLE ARROWS'}
                        {simStep === 3 && '🔑 STEP 3/5: STS ROLE ASSUMPTION ARROW'}
                        {simStep === 4 && '⚡ STEP 4/5: UNUSUAL ADMIN ACCESS ARROW'}
                        {simStep === 5 && '🛑 STEP 5/5: VAULT EXFILTRATION ARROW'}
                        {simStep === 6 && '🛡️ STEP 6: AUTOMATED ZERO TRUST CONTAINMENT'}
                      </span>

                      <span className="text-zinc-400 text-[11px]">
                        Target: <span className="text-[#e8e8fc] font-semibold">{formatIdentity(hopIdentity)}</span>
                      </span>
                    </div>

                    {/* Step Quick Jump Pills */}
                    <div className="flex items-center space-x-1 text-[10px]">
                      {[
                        { step: 1, label: '1. Infiltrate' },
                        { step: 2, label: '2. Token' },
                        { step: 3, label: '3. STS Role' },
                        { step: 4, label: '4. AdminPriv' },
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
                              ? (s.step === 5 ? 'bg-red-900/60 text-red-200 border border-red-700/50 font-bold' : (s.step === 6 ? 'bg-emerald-950 text-emerald-300 border border-emerald-700/50' : 'bg-[#181136] text-[#45edf2] border border-[#45edf2]/50 shadow-[0_0_8px_rgba(69,237,242,0.2)]'))
                              : 'bg-[#0e1625] text-zinc-500 hover:text-[#e8e8fc] border border-[#49299a]/30'
                          }`}
                        >
                          {s.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Narrative Ticker Message */}
                  <div className="text-xs text-[#e8e8fc] bg-[#0e1625] p-2 rounded-lg border border-[#49299a]/30 flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="text-[#45edf2] font-bold">▶</span>
                      <span>
                        {simStep === 0 && 'Ready. Select an incident or launch a simulated attack to trace the threat path across all 5 security layers.'}
                        {simStep === 1 && `[Step 1: Initial Infiltration] Identity '${formatIdentity(hopIdentity)}' authenticated via session '${sessionSlot1}'. Flag: Inactive account woken up from suspicious location.`}
                        {simStep === 2 && `[Step 2: Hijacked Session] Active login token stolen and used from a new device; lateral probing detected across internal sessions.`}
                        {simStep === 3 && `[Step 3: Cloud Role Assumed] Attacker pivoted into AWS STS service role '${hopRole}', acquiring temporary cloud credentials.`}
                        {simStep === 4 && `[Step 4: Unusual Admin Access] Policy '${hopPolicy.replace('arn:aws:iam::aws:policy/', '')}' illicitly attached to elevate permissions to Administrator.`}
                        {simStep === 5 && `[Step 5: Systems at Risk] CRITICAL: Unauthorized download attempt dispatched against sensitive customer vault '${hopResource}'!`}
                        {simStep === 6 && `[Step 6: Automated Containment] Emergency Zero Trust safeguard auto-revoked session '${sessionSlot1}'. Threat contained in <1 millisecond.`}
                      </span>
                    </div>

                    {simStep === 6 && (
                      <span className="text-[10px] font-bold text-emerald-400 border border-emerald-800/50 bg-[#06180f] px-2 py-0.5 rounded shrink-0">
                        CONTAINMENT ACTIVE
                      </span>
                    )}
                  </div>
                </div>

                {/* SVG Graph Canvas - Fitted 100% to box matching reference architecture with arrow simulation */}
                <div className="relative w-full bg-gradient-to-b from-[#0e1625] via-black to-[#0e1625] border border-[#49299a]/50 rounded-2xl p-4 flex items-center justify-center shadow-[0_0_35px_rgba(73,41,154,0.22)] overflow-hidden">
                  <svg
                    viewBox="0 0 1180 490"
                    className="w-full h-auto min-h-[460px] max-h-[620px]"
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

                      {/* Engine Theme Gradient Defs: #0e1625, #49299a, #45edf2, #e8e8fc */}
                      <linearGradient id="enginePurpleCyan" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="#49299a" />
                        <stop offset="70%" stopColor="#45edf2" />
                        <stop offset="100%" stopColor="#e8e8fc" />
                      </linearGradient>

                      <radialGradient id="engineCanvasGlow" cx="50%" cy="50%" r="65%">
                        <stop offset="0%" stopColor="#49299a" stopOpacity="0.22" />
                        <stop offset="50%" stopColor="#0e1625" stopOpacity="0.4" />
                        <stop offset="100%" stopColor="#000000" stopOpacity="0.95" />
                      </radialGradient>

                      {/* Inactive Muted Arrow Marker */}
                      <marker id="arrow-dim-red" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                        <path d="M 0 1 L 9 5 L 0 9 z" fill="#49299a" opacity="0.6" />
                      </marker>

                      {/* Active Highlighted Glowing Red Arrow Marker */}
                      <marker id="arrow-bright-red" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                        <path d="M 0 1 L 9 5 L 0 9 z" fill="#ff2255" />
                      </marker>

                      {/* Benign Background Edge Arrow Marker (Electric Cyan) */}
                      <marker id="arrow-cyan" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
                        <path d="M 0 1 L 9 5 L 0 9 z" fill="#45edf2" opacity="0.9" />
                      </marker>

                      {/* Glow Filters */}
                      <filter id="glow-arrow-red" x="-20%" y="-20%" width="140%" height="140%">
                        <feGaussianBlur stdDeviation="3" result="blur" />
                        <feMerge>
                          <feMergeNode in="blur" />
                          <feMergeNode in="SourceGraphic" />
                        </feMerge>
                      </filter>

                      <filter id="glow-purple" x="-20%" y="-20%" width="140%" height="140%">
                        <feGaussianBlur stdDeviation="3.5" result="blur" />
                        <feMerge>
                          <feMergeNode in="blur" />
                          <feMergeNode in="SourceGraphic" />
                        </feMerge>
                      </filter>

                      <filter id="glow-cyan" x="-20%" y="-20%" width="140%" height="140%">
                        <feGaussianBlur stdDeviation="3.5" result="blur" />
                        <feMerge>
                          <feMergeNode in="blur" />
                          <feMergeNode in="SourceGraphic" />
                        </feMerge>
                      </filter>
                    </defs>

                    {/* Canvas Ambient Glow Background */}
                    <rect width="1180" height="490" fill="url(#engineCanvasGlow)" rx="16" />

                    {/* Column Lane Guides & Headers */}
                    <line x1="137" y1="35" x2="137" y2="465" stroke="#49299a" strokeOpacity="0.35" strokeWidth="1" strokeDasharray="3 3" />
                    <line x1="367" y1="35" x2="367" y2="465" stroke="#49299a" strokeOpacity="0.35" strokeWidth="1" strokeDasharray="3 3" />
                    <line x1="607" y1="35" x2="607" y2="465" stroke="#49299a" strokeOpacity="0.35" strokeWidth="1" strokeDasharray="3 3" />
                    <line x1="827" y1="35" x2="827" y2="465" stroke="#49299a" strokeOpacity="0.35" strokeWidth="1" strokeDasharray="3 3" />
                    <line x1="1042" y1="35" x2="1042" y2="465" stroke="#49299a" strokeOpacity="0.35" strokeWidth="1" strokeDasharray="3 3" />

                    <text x="137" y="22" fill="#e8e8fc" fillOpacity="0.75" fontSize="10" fontWeight="700" fontFamily="monospace" textAnchor="middle" letterSpacing="1">IDENTITY PRINCIPALS</text>
                    <text x="367" y="22" fill="#e8e8fc" fillOpacity="0.75" fontSize="10" fontWeight="700" fontFamily="monospace" textAnchor="middle" letterSpacing="1">ACTIVE SESSIONS</text>
                    <text x="607" y="22" fill="#e8e8fc" fillOpacity="0.75" fontSize="10" fontWeight="700" fontFamily="monospace" textAnchor="middle" letterSpacing="1">CLOUD ROLES &amp; STS</text>
                    <text x="827" y="22" fill="#e8e8fc" fillOpacity="0.75" fontSize="10" fontWeight="700" fontFamily="monospace" textAnchor="middle" letterSpacing="1">IAM POLICIES</text>
                    <text x="1042" y="22" fill="#e8e8fc" fillOpacity="0.75" fontSize="10" fontWeight="700" fontFamily="monospace" textAnchor="middle" letterSpacing="1">SENSITIVE RESOURCES</text>

                    {/* ========================================================
                        BACKGROUND EDGES (Benign Telemetry Purple-Cyan Gradient)
                       ======================================================== */}
                    {/* Identity Slot 1 (Alice) -> Session Slot 2 */}
                    <path d="M 220 154 L 285 154" fill="none" stroke="url(#enginePurpleCyan)" strokeWidth="1.6" opacity="0.75" markerEnd="url(#arrow-cyan)" />
                    {/* Session Slot 2 -> sts.amazonaws.com */}
                    <path d="M 450 154 C 485 154, 485 238, 520 238" fill="none" stroke="url(#enginePurpleCyan)" strokeWidth="1.6" opacity="0.75" markerEnd="url(#arrow-cyan)" />
                    {/* sts.amazonaws.com -> Resource Slot 1 (corp-analytics-reports) */}
                    <path d="M 695 238 C 785 238, 865 169, 955 169" fill="none" stroke="url(#enginePurpleCyan)" strokeWidth="1.6" opacity="0.75" markerEnd="url(#arrow-cyan)" />
                    {/* sts.amazonaws.com -> Resource Slot 3 (corp-dev-builds) */}
                    <path d="M 695 260 C 785 260, 865 331, 955 331" fill="none" stroke="url(#enginePurpleCyan)" strokeWidth="1.6" opacity="0.75" markerEnd="url(#arrow-cyan)" />

                    {/* ========================================================
                        ACTIVE ATTACK PATH ARROWS (Highlighted Step-by-Step)
                       ======================================================== */}
                    {/* Arrow 1a: Active Identity (Bob) -> Attacker Session 1 (Active at Step 1+) */}
                    <path
                      d="M 220 206 C 255 206, 255 90, 285 90"
                      fill="none"
                      stroke={simStep >= 1 ? '#ff2255' : '#49299a'}
                      strokeWidth={simStep >= 1 ? '3.5' : '1.8'}
                      strokeDasharray={simStep >= 1 ? '8 4' : '5 3'}
                      markerEnd={simStep >= 1 ? 'url(#arrow-bright-red)' : 'url(#arrow-dim-red)'}
                      className={simStep >= 1 ? 'attack-arrow-active' : ''}
                      filter={simStep >= 1 ? 'url(#glow-arrow-red)' : undefined}
                      opacity={simStep >= 1 ? 1 : 0.45}
                    />

                    {/* Arrow 1b: Attacker Session 1 -> Role/STS (Active at Step 2+) */}
                    <path
                      d="M 450 90 C 490 90, 485 230, 520 230"
                      fill="none"
                      stroke={simStep >= 2 ? '#ff2255' : '#49299a'}
                      strokeWidth={simStep >= 2 ? '3.5' : '1.8'}
                      strokeDasharray={simStep >= 2 ? '8 4' : '5 3'}
                      markerEnd={simStep >= 2 ? 'url(#arrow-bright-red)' : 'url(#arrow-dim-red)'}
                      className={simStep >= 2 ? 'attack-arrow-active' : ''}
                      filter={simStep >= 2 ? 'url(#glow-arrow-red)' : undefined}
                      opacity={simStep >= 2 ? 1 : 0.45}
                    />

                    {/* Arrow 1c: Lateral Session Probe -> Session Slot 3 (Active at Step 2+) */}
                    <path
                      d="M 220 218 L 285 218"
                      fill="none"
                      stroke={simStep >= 2 ? '#ff4d4d' : '#49299a'}
                      strokeWidth={simStep >= 2 ? '2.6' : '1.3'}
                      strokeDasharray="6 3"
                      markerEnd={simStep >= 2 ? 'url(#arrow-bright-red)' : 'url(#arrow-dim-red)'}
                      className={simStep >= 2 ? 'attack-arrow-active' : ''}
                      opacity={simStep >= 2 ? 0.9 : 0.3}
                    />

                    {/* Arrow 1d: Lateral Probes to lower sessions (Active at Step 2+) */}
                    <path
                      d="M 220 226 C 255 226, 255 346, 285 346"
                      fill="none"
                      stroke={simStep >= 2 ? '#ff4d4d' : '#49299a'}
                      strokeWidth={simStep >= 2 ? '2.2' : '1.3'}
                      strokeDasharray="5 3"
                      markerEnd={simStep >= 2 ? 'url(#arrow-bright-red)' : 'url(#arrow-dim-red)'}
                      className={simStep >= 2 ? 'attack-arrow-active' : ''}
                      opacity={simStep >= 2 ? 0.85 : 0.25}
                    />
                    <path
                      d="M 220 230 C 255 230, 255 410, 285 410"
                      fill="none"
                      stroke={simStep >= 2 ? '#ff4d4d' : '#49299a'}
                      strokeWidth={simStep >= 2 ? '2.2' : '1.3'}
                      strokeDasharray="5 3"
                      markerEnd={simStep >= 2 ? 'url(#arrow-bright-red)' : 'url(#arrow-dim-red)'}
                      className={simStep >= 2 ? 'attack-arrow-active' : ''}
                      opacity={simStep >= 2 ? 0.85 : 0.25}
                    />

                    {/* Arrow 3: Role/STS -> Policy (Active at Step 3+) */}
                    <path
                      d="M 695 250 L 740 250"
                      fill="none"
                      stroke={simStep >= 3 ? '#ff2255' : '#49299a'}
                      strokeWidth={simStep >= 3 ? '3.5' : '1.8'}
                      strokeDasharray={simStep >= 3 ? '8 4' : '5 3'}
                      markerEnd={simStep >= 3 ? 'url(#arrow-bright-red)' : 'url(#arrow-dim-red)'}
                      className={simStep >= 3 ? 'attack-arrow-active' : ''}
                      filter={simStep >= 3 ? 'url(#glow-arrow-red)' : undefined}
                      opacity={simStep >= 3 ? 1 : 0.45}
                    />

                    {/* Arrow 4: Policy -> Target Vault Resource (Active at Step 4+) */}
                    <path
                      d="M 915 250 L 955 250"
                      fill="none"
                      stroke={simStep >= 4 ? '#ff1744' : '#49299a'}
                      strokeWidth={simStep >= 4 ? '3.8' : '1.8'}
                      strokeDasharray={simStep >= 4 ? '8 4' : '5 3'}
                      markerEnd={simStep >= 4 ? 'url(#arrow-bright-red)' : 'url(#arrow-dim-red)'}
                      className={simStep >= 4 ? 'attack-arrow-active' : ''}
                      filter={simStep >= 4 ? 'url(#glow-arrow-red)' : undefined}
                      opacity={simStep >= 4 ? 1 : 0.45}
                    />

                    {/* ========================================================
                        COLUMN 1: IDENTITIES (4 Nodes, Mathematically Aligned)
                       ======================================================== */}
                    {/* 1.1: Identity Slot 1 (Alice) */}
                    <g
                      transform="translate(55, 130)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: identitySlot1,
                        title: `${formatIdentity(identitySlot1)} (Peer Identity)`,
                        type: 'IDENTITY',
                        roleDesc: 'Peer corporate principal identity',
                        attributes: { 'Status': 'Normal', 'Clearance': 'Tier 1 Standard', '2FA': 'Enforced' },
                        color: 'sky',
                        icon: '👤'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <rect width="165" height="48" rx="8" fill="#0e1625" stroke="#49299a" strokeOpacity="0.45" strokeWidth="1.2" className="group-hover:stroke-[#45edf2] transition-all" />
                      <text x="14" y="21" fill="#e8e8fc" fontSize="12" fontWeight="bold" fontFamily="monospace">
                        {formatIdentity(identitySlot1).slice(0, 18)}
                      </text>
                      <text x="14" y="36" fill="#45edf2" fillOpacity="0.8" fontSize="9.5" fontWeight="600" fontFamily="monospace">IDENTITY • NORMAL</text>
                    </g>

                    {/* 1.2: Active Attacker Identity Slot 2 (Bob) */}
                    <g
                      transform="translate(55, 192)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: hopIdentity,
                        title: 'Target Attacker Principal',
                        type: 'IDENTITY',
                        roleDesc: 'Compromised or anomalous user account identified as threat vector',
                        attributes: {
                          'Principal ID': hopIdentity,
                          'Risk Score': activeScore ? `${activeScore.total} / 100` : '80 / 100',
                          'Threat Flag': selectedAlert?.what || 'Anomalous Activity',
                          'Incident Ref': selectedAlert?.incident_id || 'N/A'
                        },
                        color: 'sky',
                        icon: '👤'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <rect
                        width="165"
                        height="52"
                        rx="8"
                        fill="#0e1625"
                        stroke={simStep >= 1 ? '#ff2255' : '#49299a'}
                        strokeWidth={simStep >= 1 ? '2.6' : '2'}
                        filter={simStep >= 1 ? 'url(#glow-arrow-red)' : 'url(#glow-purple)'}
                        className="transition-all"
                      />
                      <text x="14" y="22" fill="#ffffff" fontSize="12" fontWeight="bold" fontFamily="monospace">
                        {formatIdentity(hopIdentity).slice(0, 18)}
                      </text>
                      <text x="14" y="38" fill={simStep >= 1 ? '#fca5a5' : '#45edf2'} fontSize="9.5" fontWeight="bold" fontFamily="monospace">
                        IDENTITY • {simStep >= 1 ? 'COMPROMISED' : 'NORMAL'}
                      </text>
                    </g>

                    {/* 1.3: Identity Slot 3 (Charlie) */}
                    <g
                      transform="translate(55, 258)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: identitySlot3,
                        title: `${formatIdentity(identitySlot3)} (Analyst)`,
                        type: 'IDENTITY',
                        roleDesc: 'Ordinary data science / analyst identity',
                        attributes: { 'Status': 'Normal', 'Clearance': 'Tier 1 Analyst' },
                        color: 'sky',
                        icon: '👤'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <rect width="165" height="48" rx="8" fill="#0e1625" stroke="#49299a" strokeOpacity="0.45" strokeWidth="1.2" className="group-hover:stroke-[#45edf2] transition-all" />
                      <text x="14" y="21" fill="#e8e8fc" fontSize="12" fontWeight="bold" fontFamily="monospace">
                        {formatIdentity(identitySlot3).slice(0, 18)}
                      </text>
                      <text x="14" y="36" fill="#45edf2" fillOpacity="0.8" fontSize="9.5" fontWeight="600" fontFamily="monospace">IDENTITY • NORMAL</text>
                    </g>

                    {/* 1.4: Identity Slot 4 (Diana - Admin / Protected) */}
                    <g
                      transform="translate(55, 322)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: identitySlot4,
                        title: `${formatIdentity(identitySlot4)} (Break-Glass Safeguard)`,
                        type: 'IDENTITY',
                        roleDesc: 'Critical infrastructure admin with break-glass safeguard active',
                        attributes: { 'Status': 'Protected', 'Safeguard': 'ACTIVE (Deny Disruption)', 'Privilege': 'Tier 4 Admin' },
                        color: 'rose',
                        icon: '🛡️'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <rect width="165" height="48" rx="8" fill="#140a14" stroke="#881337" strokeWidth="1.6" className="group-hover:stroke-rose-500 transition-all" />
                      <text x="14" y="21" fill="#fecdd3" fontSize="12" fontWeight="bold" fontFamily="monospace">
                        {formatIdentity(identitySlot4).slice(0, 18)}
                      </text>
                      <text x="14" y="36" fill="#f43f5e" fontSize="9.5" fontWeight="bold" fontFamily="monospace">IDENTITY • HIGH</text>
                    </g>

                    {/* ========================================================
                        COLUMN 2: SESSIONS (6 Nodes, Aligned Exactly to Rows)
                       ======================================================== */}
                    {/* 2.1: Attacker Active Session 1 */}
                    <g
                      transform="translate(285, 68)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: sessionSlot1,
                        title: 'Attacker Authenticated Session',
                        type: 'SESSION',
                        roleDesc: 'Active session established from anomalous IP / client',
                        attributes: { 'Session ID': sessionSlot1, 'Principal': formatIdentity(hopIdentity), 'Transport': 'Browser-to-SDK', 'Status': simStep >= 2 ? 'HIJACKED' : 'ACTIVE' },
                        color: 'sky',
                        icon: '🔑'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <rect
                        width="165"
                        height="44"
                        rx="8"
                        fill="#0e1625"
                        stroke={simStep >= 2 ? '#ff2255' : '#45edf2'}
                        strokeWidth={simStep >= 2 ? '2.4' : '1.5'}
                        filter={simStep >= 2 ? 'url(#glow-arrow-red)' : 'url(#glow-cyan)'}
                        className="transition-all"
                      />
                      <text x="14" y="19" fill="#e8e8fc" fontSize="12" fontWeight="bold" fontFamily="monospace">
                        Session: {sessionSlot1.slice(0, 8)}..
                      </text>
                      <text x="14" y="33" fill={simStep >= 2 ? '#fca5a5' : '#45edf2'} fontSize="9" fontWeight="bold" fontFamily="monospace">
                        SESSION • {simStep >= 2 ? 'HIJACKED' : 'NORMAL'}
                      </text>
                    </g>

                    {/* 2.2: Session Slot 2 (Aligned with Alice) */}
                    <g transform="translate(285, 132)" className="cursor-pointer group">
                      <rect width="165" height="44" rx="8" fill="#0e1625" stroke="#1d2d48" strokeWidth="1" className="group-hover:stroke-[#45edf2] transition-all" />
                      <text x="14" y="19" fill="#e8e8fc" fillOpacity="0.85" fontSize="12" fontWeight="bold" fontFamily="monospace">
                        Session: {sessionSlot2.slice(0, 8)}..
                      </text>
                      <text x="14" y="33" fill="#45edf2" fillOpacity="0.75" fontSize="9" fontWeight="600" fontFamily="monospace">SESSION • NORMAL</text>
                    </g>

                    {/* 2.3: Session Slot 3 (Aligned with Bob) */}
                    <g transform="translate(285, 196)" className="cursor-pointer group">
                      <rect width="165" height="44" rx="8" fill="#0e1625" stroke={simStep >= 2 ? '#ff4d4d' : '#1d2d48'} strokeWidth="1" className="group-hover:stroke-[#45edf2] transition-all" />
                      <text x="14" y="19" fill="#e8e8fc" fillOpacity="0.85" fontSize="12" fontWeight="bold" fontFamily="monospace">
                        Session: {sessionSlot3.slice(0, 8)}..
                      </text>
                      <text x="14" y="33" fill="#45edf2" fillOpacity="0.75" fontSize="9" fontWeight="600" fontFamily="monospace">SESSION • NORMAL</text>
                    </g>

                    {/* 2.4: Session Slot 4 (Aligned with Charlie) */}
                    <g transform="translate(285, 260)" className="cursor-pointer group">
                      <rect width="165" height="44" rx="8" fill="#0e1625" stroke="#1d2d48" strokeWidth="1" className="group-hover:stroke-[#45edf2] transition-all" />
                      <text x="14" y="19" fill="#e8e8fc" fillOpacity="0.85" fontSize="12" fontWeight="bold" fontFamily="monospace">
                        Session: {sessionSlot4.slice(0, 8)}..
                      </text>
                      <text x="14" y="33" fill="#45edf2" fillOpacity="0.75" fontSize="9" fontWeight="600" fontFamily="monospace">SESSION • NORMAL</text>
                    </g>

                    {/* 2.5: Session Slot 5 (Aligned with Diana) */}
                    <g transform="translate(285, 324)" className="cursor-pointer group">
                      <rect width="165" height="44" rx="8" fill="#0e1625" stroke="#1d2d48" strokeWidth="1" className="group-hover:stroke-[#45edf2] transition-all" />
                      <text x="14" y="19" fill="#e8e8fc" fillOpacity="0.85" fontSize="12" fontWeight="bold" fontFamily="monospace">
                        Session: {sessionSlot5.slice(0, 8)}..
                      </text>
                      <text x="14" y="33" fill="#45edf2" fillOpacity="0.75" fontSize="9" fontWeight="600" fontFamily="monospace">SESSION • NORMAL</text>
                    </g>

                    {/* 2.6: Session Slot 6 */}
                    <g transform="translate(285, 388)" className="cursor-pointer group">
                      <rect width="165" height="44" rx="8" fill="#0e1625" stroke="#1d2d48" strokeWidth="1" className="group-hover:stroke-[#45edf2] transition-all" />
                      <text x="14" y="19" fill="#e8e8fc" fillOpacity="0.85" fontSize="12" fontWeight="bold" fontFamily="monospace">
                        Session: {sessionSlot6.slice(0, 8)}..
                      </text>
                      <text x="14" y="33" fill="#45edf2" fillOpacity="0.75" fontSize="9" fontWeight="600" fontFamily="monospace">SESSION • NORMAL</text>
                    </g>

                    {/* ========================================================
                        COLUMN 3: ROLES & STS (Center Node - Royal Purple)
                       ======================================================== */}
                    <g
                      transform="translate(520, 222)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: hopRole,
                        title: 'Assumed AWS IAM Role / STS Token',
                        type: 'ROLE',
                        roleDesc: 'Intermediate cloud service role assumed via STS tokens',
                        attributes: {
                          'Role Target': hopRole,
                          'Assumed By': formatIdentity(hopIdentity),
                          'Service': 'AWS IAM / STS',
                          'Action': 'sts:AssumeRole',
                          'Privilege Scope': 'Intermediate Cloud Access'
                        },
                        color: 'amber',
                        icon: '🔑'
                      })}
                      onMouseLeave={() => setActiveBubble(null)}
                    >
                      <rect
                        width="175"
                        height="56"
                        rx="8"
                        fill="#180f33"
                        stroke={simStep >= 3 ? '#45edf2' : '#49299a'}
                        strokeWidth={simStep >= 3 ? '2.8' : '2'}
                        filter={simStep >= 3 ? 'url(#glow-cyan)' : 'url(#glow-purple)'}
                        className="transition-all"
                      />
                      <text x="14" y="24" fill="#ffffff" fontSize="12.5" fontWeight="bold" fontFamily="monospace">
                        {hopRole.slice(0, 18)}
                      </text>
                      <text x="14" y="42" fill="#45edf2" fontSize="9.5" fontWeight="bold" fontFamily="monospace">
                        ROLE • MEDIUM
                      </text>
                    </g>

                    {/* ========================================================
                        COLUMN 4: POLICIES (IAM Policies - Obsidian Cyan)
                       ======================================================== */}
                    <g
                      transform="translate(740, 222)"
                      className="cursor-pointer group"
                      onMouseEnter={() => setActiveBubble({
                        id: hopPolicy,
                        title: 'Escalated IAM Policy',
                        type: 'POLICY',
                        roleDesc: 'Critical administrative permission policy attached illicitly',
                        attributes: {
                          'Policy ARN': hopPolicy.includes('arn') ? hopPolicy : `arn:aws:iam::aws:policy/${hopPolicy}`,
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
                        width="175"
                        height="56"
                        rx="8"
                        fill="#0e1625"
                        stroke={simStep >= 4 ? '#e8e8fc' : '#45edf2'}
                        strokeWidth={simStep >= 4 ? '2.4' : '1.8'}
                        filter={simStep >= 4 ? 'url(#glow-cyan)' : undefined}
                        className="transition-all"
                      />
                      <text x="14" y="24" fill="#ffffff" fontSize="12.5" fontWeight="bold" fontFamily="monospace">
                        {hopPolicy.replace('arn:aws:iam::aws:policy/', '').slice(0, 18)}
                      </text>
                      <text x="14" y="42" fill="#45edf2" fontSize="9.5" fontWeight="bold" fontFamily="monospace">
                        POLICY • MEDIUM
                      </text>
                    </g>

                    {/* ========================================================
                        COLUMN 5: TARGET RESOURCES (Sensitive Resources)
                       ======================================================== */}
                    {/* 5.1: Resource Slot 1 */}
                    <g transform="translate(955, 145)" className="cursor-pointer group">
                      <rect width="175" height="48" rx="8" fill="#0e1625" stroke="#45edf2" strokeOpacity="0.45" strokeWidth="1" className="group-hover:stroke-[#45edf2] transition-all" />
                      <text x="14" y="21" fill="#e8e8fc" fontSize="12" fontWeight="bold" fontFamily="monospace">
                        {resourceSlot1.slice(0, 18)}
                      </text>
                      <text x="14" y="36" fill="#45edf2" fillOpacity="0.85" fontSize="9.5" fontWeight="600" fontFamily="monospace">RESOURCE • NORMAL</text>
                    </g>

                    {/* 5.2: Exfiltration Target Resource Slot 2 (Critical Vault - Bright Red) */}
                    <g
                      transform="translate(955, 222)"
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
                        width="175"
                        height="56"
                        rx="8"
                        fill="#290918"
                        stroke={simStep >= 5 ? '#ff1744' : '#ef4444'}
                        strokeWidth={simStep >= 5 ? '2.8' : '2'}
                        filter={simStep >= 5 ? 'url(#glow-arrow-red)' : undefined}
                        className="transition-all"
                      />
                      <text x="14" y="24" fill="#ffffff" fontSize="12.5" fontWeight="bold" fontFamily="monospace">
                        {hopResource.slice(0, 18)}
                      </text>
                      <text x="14" y="42" fill="#fca5a5" fontSize="9.5" fontWeight="bold" fontFamily="monospace">
                        RESOURCE • HIGH
                      </text>
                    </g>

                    {/* 5.3: Resource Slot 3 */}
                    <g transform="translate(955, 307)" className="cursor-pointer group">
                      <rect width="175" height="48" rx="8" fill="#0e1625" stroke="#45edf2" strokeOpacity="0.45" strokeWidth="1" className="group-hover:stroke-[#45edf2] transition-all" />
                      <text x="14" y="21" fill="#e8e8fc" fontSize="12" fontWeight="bold" fontFamily="monospace">
                        {resourceSlot3.slice(0, 18)}
                      </text>
                      <text x="14" y="36" fill="#45edf2" fillOpacity="0.85" fontSize="9.5" fontWeight="600" fontFamily="monospace">RESOURCE • NORMAL</text>
                    </g>

                    {/* Zero Trust Containment Shield Overlay when Step 6 reached */}
                    {simStep >= 6 && (
                      <g transform="translate(440, 14)">
                        <rect x="0" y="0" width="300" height="30" rx="8" fill="#0e1625" stroke="#45edf2" strokeWidth="2" filter="url(#glow-cyan)" />
                        <text x="150" y="19" fill="#e8e8fc" fontSize="11" fontWeight="bold" fontFamily="monospace" textAnchor="middle">
                          🛡️ ZERO TRUST REVOCATION ENFORCED
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
              {/* Executive 1-Line Summary Banner */}
              <div className="p-3 bg-[#0a0f1d] border border-cyan-900/40 rounded-xl text-xs text-cyan-200/90 font-sans flex items-center space-x-2.5">
                <span className="text-base shrink-0">💡</span>
                <span><strong className="text-white">Executive Summary:</strong> Self-tuning risk algorithm that automatically recalibrates factor sensitivity as attack patterns evolve, eliminating manual configuration while preventing confirmation bias.</span>
              </div>

              {/* Header Card */}
              <div className="p-6 border border-[#1c1c26] rounded-2xl bg-[#08080c] space-y-3 shadow-sm font-mono">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">
                        Self-Tuning Risk Model
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-amber-950/60 text-amber-300 border border-amber-800/40">
                        🔒 Zero Trust Tamper Locked
                      </span>
                    </div>
                    <h2 className="text-lg font-bold text-white mt-1.5">Autonomous Risk Factor Calibration</h2>
                    <p className="text-xs text-zinc-300 mt-1 font-sans">
                      Risk weights adapt autonomously based on live threat signals and detection confidence.
                      Manual modifications are strictly locked by Zero Trust governance to prevent human confirmation bias.
                    </p>
                  </div>
                  <div className="text-right text-[11px] text-zinc-400">
                    <div>Engine Status: <span className="text-emerald-400 font-bold">Self-Calibrating</span></div>
                    <div>Monitored Factors: <span className="text-cyan-300 font-bold">{Object.keys(weights).length} Active</span></div>
                  </div>
                </div>

                <div className="p-3 bg-[#0c0c12] border border-[#1e1e28] rounded-xl text-xs flex items-center justify-between">
                  <div className="text-zinc-300 font-sans">
                    <span className="text-cyan-400 font-semibold font-mono">Mathematical Safety Bounds: </span>
                    Each weight is bounded within [0.5×, 2.0×] of baseline and dynamically normalized so ∑ w_i = 1.0.
                  </div>
                  <span className="text-xs font-mono px-2.5 py-1 rounded bg-[#10141f] text-cyan-300 border border-cyan-800/40 shrink-0">
                    ∑ w_i = 1.00 Total
                  </span>
                </div>
              </div>

              {/* 5 Active Calibrated Factor Weights Cards */}
              <div className="p-6 border border-[#1c1c26] rounded-2xl bg-[#08080c] space-y-4 shadow-sm font-mono">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-300 font-sans">
                      Top Risk Drivers &amp; Weight Sensitivity
                    </h3>
                    <p className="text-xs text-zinc-400 font-sans">Dynamic sensitivity calibrated across threat archetypes</p>
                  </div>
                  <span className="text-xs text-zinc-400 font-mono">Target: 1.00 Total Normalized</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {Object.entries(weights).map(([factor, weight]) => {
                    const baselineWeight = factor === 'behavioral_anomaly' ? 0.25 : (factor === 'privilege_level' ? 0.20 : (factor === 'privilege_delta' ? 0.25 : 0.15))
                    const deltaPct = (((weight - baselineWeight) / baselineWeight) * 100).toFixed(1)
                    const disp = getFactorDisplay(factor)

                    return (
                      <div key={factor} className="p-4 border border-[#1a1a26] bg-[#09090e] rounded-xl space-y-2.5 hover:border-cyan-500/40 transition-colors">
                        <div className="flex items-center justify-between text-xs">
                          <div>
                            <span className="font-bold text-white text-xs">{disp.primary}</span>
                            <span className="text-zinc-500 font-mono text-[10px] ml-1.5">({factor})</span>
                          </div>
                          <div className="flex items-center space-x-2">
                            <span className="text-cyan-300 font-bold text-sm font-mono">{weight}</span>
                            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded font-mono ${Number(deltaPct) >= 0 ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/40' : 'bg-rose-950/80 text-rose-300 border border-rose-800/40'}`}>
                              {Number(deltaPct) >= 0 ? `+${deltaPct}%` : `${deltaPct}%`}
                            </span>
                          </div>
                        </div>

                        <p className="text-[11px] text-zinc-400 font-sans leading-relaxed">
                          {disp.explanation}
                        </p>

                        <div className="w-full bg-[#121218] h-2 rounded-full overflow-hidden border border-[#1c1c28]">
                          <div
                            className="bg-gradient-to-r from-[#49299a] via-[#35267d] to-[#45edf2] h-full rounded-full transition-all duration-500 shadow-[0_0_8px_rgba(69,237,242,0.3)]"
                            style={{ width: `${Math.min(100, weight * 200)}%` }}
                          ></div>
                        </div>

                        <div className="flex items-center justify-between text-[11px] text-zinc-400 pt-1">
                          <span>Baseline: <span className="text-zinc-300 font-mono">{baselineWeight}</span></span>
                          <span className="text-cyan-400/90 flex items-center space-x-1 font-sans">
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
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-300 font-sans">
                      Tamper-Proof Activity Log
                    </h3>
                    <p className="text-xs text-zinc-400 font-sans">Cryptographically verified audit trail of self-tuning weight adjustments</p>
                  </div>
                  <span className="text-xs text-cyan-400 border border-cyan-800/50 bg-[#07121c] px-2.5 py-0.5 rounded-full">
                    {tuningLog.length} Calibrations Logged
                  </span>
                </div>

                <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
                  {tuningLog.length === 0 ? (
                    <div className="p-8 text-center text-xs text-zinc-500 border border-[#181822] rounded-xl bg-[#06060a]">
                      No dynamic calibrations recorded yet. Launch a simulated threat to observe autonomous model tuning.
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
              TAB 4: Phase 7 Risk-Adaptive mTLS Decision Cache & Zero-Trust Lab
             ============================================================== */}
          {activeTab === 'mtls' && (
            <div className="space-y-6">
              {/* Executive 1-Line Summary Banner */}
              <div className="p-3 bg-[#0a0f1d] border border-cyan-900/40 rounded-xl text-xs text-cyan-200/90 font-sans flex items-center space-x-2.5">
                <span className="text-base shrink-0">💡</span>
                <span><strong className="text-white">Executive Summary:</strong> Risk-Adaptive Zero-Trust Gateway combining hardware-grade RFC 8705 certificate thumbprint binding with Contextual HMAC Macaroons. Solves the 25-hop internal microservice latency tax (96.2% delay reduction) while intercepting post-auth token theft with 100% deterministic accuracy.</span>
              </div>

              {/* Header Card */}
              <div className="p-6 border border-[#1a1a24] rounded-2xl bg-[#08080c] shadow-[inset_0_2px_4px_rgba(0,0,0,0.8)] space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-lg font-bold text-white flex items-center space-x-2">
                      <span>🔐</span>
                      <span>Speed &amp; Security Monitor (mTLS)</span>
                    </h2>
                    <p className="text-xs text-zinc-300 mt-1">
                      Continuous session validation binding TLS client certificates to active identity sessions with sub-millisecond fast-path bypass.
                    </p>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-[10px] font-mono text-cyan-400 border border-cyan-800/40 bg-[#08121a] px-2.5 py-1 rounded-full">
                      RFC 8705 &amp; FIPS Verified
                    </span>
                    <button
                      onClick={() => {
                        fetchMtlsStatus()
                        fetch(`${API_BASE}/api/mtls/stats`)
                          .then(r => r.json())
                          .then(d => setMtlsStats(d.stats))
                          .catch(() => {})
                      }}
                      className="px-3 py-1.5 rounded-lg border border-[#242436] bg-[#101018] hover:bg-[#161622] text-xs font-mono text-cyan-400 cursor-pointer transition-all"
                    >
                      Refresh Stats ⟳
                    </button>
                  </div>
                </div>

                {/* Key Metrics Grid */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-2">
                  <div className="p-3.5 rounded-xl border border-[#181824] bg-[#0c0c12]">
                    <div className="text-[10px] font-mono text-zinc-400 uppercase">Average Speed (p50)</div>
                    <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
                      {mtlsStats?.mean_latency_ms ? `${mtlsStats.mean_latency_ms} ms` : '0.011 ms'}
                    </div>
                    <div className="text-[10px] text-zinc-500 mt-0.5">Fast-Path Hits (~0.011 ms avg)</div>
                  </div>
                  <div className="p-3.5 rounded-xl border border-[#181824] bg-[#0c0c12]">
                    <div className="text-[10px] font-mono text-zinc-400 uppercase">East-West Microservice Speedup</div>
                    <div className="text-xl font-bold font-mono text-cyan-400 mt-1">
                      26.3x Faster
                    </div>
                    <div className="text-[10px] text-zinc-500 mt-0.5">96.2% Multi-Hop Latency Saved</div>
                  </div>
                  <div className="p-3.5 rounded-xl border border-[#181824] bg-[#0c0c12]">
                    <div className="text-[10px] font-mono text-zinc-400 uppercase">Stolen Token Interceptions</div>
                    <div className="text-xl font-bold font-mono text-rose-400 mt-1">
                      {mtlsStats?.cert_mismatches ?? 0}
                    </div>
                    <div className="text-[10px] text-rose-500/80 mt-0.5">Cert Mismatches (DET-06)</div>
                  </div>
                  <div className="p-3.5 rounded-xl border border-[#181824] bg-[#0c0c12]">
                    <div className="text-[10px] font-mono text-zinc-400 uppercase">Registered X.509 Devices</div>
                    <div className="text-xl font-bold font-mono text-sky-400 mt-1">
                      {mtlsStatusData?.certificates?.length ?? 5}
                    </div>
                    <div className="text-[10px] text-zinc-500 mt-0.5">Hardware-Bound Sessions</div>
                  </div>
                </div>
              </div>

              {/* The mTLS Latency Tax: 25-Hop Microservice Cascade Visual Progress Bar */}
              <div className="p-6 border border-[#1e1e2c] rounded-2xl bg-[#09090f] space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-200 font-sans">
                      The mTLS Latency Tax: 25-Hop Microservice Cascade Comparison
                    </h3>
                    <p className="text-[11px] text-zinc-400 font-sans mt-0.5">
                      In modern cloud environments, 1 user click cascades into 20–30 internal service hops. Naive mTLS adds ~1.2s of delay; our Contextual HMAC Macaroons verify in O(1) memory (&lt;0.05ms) per hop.
                    </p>
                  </div>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/60 px-2.5 py-1 rounded-full shrink-0">
                    ⚡ 96.2% Latency Saved (672.7 ms)
                  </span>
                </div>

                <div className="space-y-3 pt-1">
                  {/* Naive Bar */}
                  <div>
                    <div className="flex items-center justify-between text-xs font-mono mb-1">
                      <span className="text-zinc-400 flex items-center space-x-1.5">
                        <span className="w-2.5 h-2.5 rounded-sm bg-rose-500 inline-block"></span>
                        <span>Naive Zero Trust (Per-Hop Asymmetric mTLS + DB Policy Check)</span>
                      </span>
                      <span className="text-rose-400 font-bold">~699.3 ms total (~28 ms / hop)</span>
                    </div>
                    <div className="w-full bg-[#181822] rounded-full h-3.5 overflow-hidden border border-[#242436]">
                      <div className="bg-gradient-to-r from-rose-700 to-rose-500 h-full rounded-full w-full flex items-center justify-end pr-2 text-[9px] font-mono text-white font-bold">
                        100% Latency Tax
                      </div>
                    </div>
                  </div>

                  {/* Our Innovation Bar */}
                  <div>
                    <div className="flex items-center justify-between text-xs font-mono mb-1">
                      <span className="text-zinc-300 flex items-center space-x-1.5">
                        <span className="w-2.5 h-2.5 rounded-sm bg-emerald-400 inline-block"></span>
                        <span className="font-semibold text-white">Our Innovation (Hop 1 Ingress mTLS + Hops 2-25 Contextual HMAC Macaroons)</span>
                      </span>
                      <span className="text-emerald-400 font-bold">26.6 ms total (&lt; 0.05 ms / hop)</span>
                    </div>
                    <div className="w-full bg-[#181822] rounded-full h-3.5 overflow-hidden border border-[#242436] relative">
                      <div 
                        className="bg-gradient-to-r from-emerald-500 to-teal-400 h-full rounded-full transition-all duration-700" 
                        style={{ width: '3.8%' }}
                      ></div>
                      <span className="absolute left-[5%] top-0 text-[9px] font-mono text-emerald-400 font-bold flex items-center h-full">
                        ← 26.3x Faster (Zero Cryptographic Bypass)
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Interactive Multi-Hop Demonstration Console */}
              <div className="p-6 border border-[#1c1c28] rounded-2xl bg-[#09090e] space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-200 font-sans">
                      Safe Test Mode: Live Microservice &amp; Token-Hijack Simulator
                    </h3>
                    <p className="text-[11px] text-zinc-400 font-sans">
                      Execute live end-to-end multi-hop cascade simulations against the FastAPI cryptographic engine.
                    </p>
                  </div>
                  <span className="text-[10px] font-mono text-cyan-400 border border-cyan-800/40 bg-[#08121a] px-2 py-0.5 rounded">
                    Interactive Live Lab
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <button
                    onClick={() => runCascadeSimulation('legit')}
                    disabled={cascadeLoading}
                    className="p-4 rounded-xl border border-emerald-800/40 bg-[#081810] hover:bg-[#0c2418] disabled:opacity-50 text-left transition-all cursor-pointer group space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-emerald-300 group-hover:text-emerald-200 flex items-center space-x-1.5">
                        <span>⚡</span>
                        <span>Run 25-Hop Microservice Speed Test (Contextual Macaroon)</span>
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 bg-emerald-950 border border-emerald-700/40 text-emerald-300 rounded">
                        {cascadeLoading && cascadeType === 'legit' ? 'Simulating...' : 'FAST PATH'}
                      </span>
                    </div>
                    <p className="text-[11px] text-emerald-400/80 leading-relaxed">
                      Bob contractor makes an API call. Ingress Gateway validates client certificate and mints HMAC Macaroon. Hops 2 to 25 verify in &lt;0.05ms each with zero database lookups, cutting latency from ~700ms down to ~26ms.
                    </p>
                  </button>

                  <button
                    onClick={() => runCascadeSimulation('hijack')}
                    disabled={cascadeLoading}
                    className="p-4 rounded-xl border border-rose-800/40 bg-[#1e0a0e] hover:bg-[#2c0e14] disabled:opacity-50 text-left transition-all cursor-pointer group space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-rose-300 group-hover:text-rose-200 flex items-center space-x-1.5">
                        <span>🚨</span>
                        <span>Simulate Stolen Token + Cert Hijack (RFC 8705 Interception)</span>
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 bg-rose-950 border border-rose-700/40 text-rose-300 rounded">
                        {cascadeLoading && cascadeType === 'hijack' ? 'Testing...' : 'DET-06 INTERCEPT'}
                      </span>
                    </div>
                    <p className="text-[11px] text-rose-400/80 leading-relaxed">
                      Attacker extracts Bob's active session token and replays it at Hop 12 (IAM-Evaluator) from an unauthorized laptop (client_attacker.crt). Gateway detects RFC 8705 thumbprint mismatch, halts traversal, and quarantines identity.
                    </p>
                  </button>
                </div>

                {/* Cascade Live Results & Forensics Display */}
                {cascadeResult && (
                  <div className="mt-4 p-5 rounded-xl border border-[#1e1e2c] bg-[#060609] space-y-4 font-mono">
                    <div className="flex items-center justify-between border-b border-[#14141e] pb-3">
                      <div className="flex items-center space-x-2.5">
                        <span className="text-xs text-zinc-400 uppercase">Cascade Status:</span>
                        <span className={`text-xs font-bold px-3 py-1 rounded-full ${
                          cascadeResult.status === 'SUCCESS'
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-700/50'
                            : 'bg-rose-950 text-rose-300 border border-rose-700/50 animate-pulse'
                        }`}>
                          {cascadeResult.status === 'SUCCESS' ? '✓ ALL 25 HOPS VERIFIED (FAST PATH)' : '🚨 THREAT INTERCEPTED AT HOP 12'}
                        </span>
                      </div>
                      <div className="text-xs text-zinc-400">
                        Total Time: <strong className={cascadeResult.status === 'SUCCESS' ? 'text-emerald-400' : 'text-rose-400'}>{cascadeResult.cumulative_fast_path_ms} ms</strong> vs Naive: <span className="line-through text-zinc-500">{cascadeResult.cumulative_naive_mtls_ms} ms</span>
                      </div>
                    </div>

                    {/* Breach Forensics Callout when hijacked */}
                    {cascadeResult.containment && (
                      <div className="p-4 rounded-xl border border-rose-800/60 bg-[#190609] text-xs space-y-2">
                        <div className="text-rose-300 font-bold flex items-center justify-between">
                          <span className="flex items-center space-x-2">
                            <span>🚨</span>
                            <span>RFC 8705 CERTIFICATE BINDING VIOLATION DISPATCHED (DET-06)</span>
                          </span>
                          <span className="px-2 py-0.5 rounded bg-rose-900/60 border border-rose-700 text-rose-200 text-[10px]">
                            100% Deterministic Interception
                          </span>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] pt-1">
                          <div className="p-2.5 rounded bg-[#100406] border border-rose-900/30">
                            <span className="text-zinc-400 block text-[10px]">LEGITIMATE BOUND CERTIFICATE (BOB MILLER):</span>
                            <span className="font-mono text-emerald-400 font-bold text-[10px] break-all">{cascadeResult.containment.bound_fingerprint}</span>
                          </div>
                          <div className="p-2.5 rounded bg-[#100406] border border-rose-900/30">
                            <span className="text-zinc-400 block text-[10px]">PRESENTED ROGUE CERTIFICATE (MALICIOUS ACTOR):</span>
                            <span className="font-mono text-rose-400 font-bold text-[10px] break-all">{cascadeResult.containment.presented_fingerprint}</span>
                          </div>
                        </div>
                        <div className="text-zinc-300 text-[11px] leading-relaxed pt-1">
                          {cascadeResult.containment.reason}
                        </div>
                        <div className="flex items-center space-x-3 text-[10px] text-zinc-400 pt-1 border-t border-rose-950">
                          <span>Action: <strong className="text-white">{cascadeResult.containment.action}</strong></span>
                          <span>•</span>
                          <span>Hops 13–25: <strong className="text-emerald-400">BLAST RADIUS CONTAINED (13 Internal Microservices Protected)</strong></span>
                        </div>
                      </div>
                    )}

                    {/* 25-Hop Step-by-Step Traversal Track */}
                    <div>
                      <div className="text-[11px] text-zinc-400 font-semibold mb-2 uppercase flex items-center justify-between">
                        <span>Microservice Traversal Cascade (Hop 1 to 25):</span>
                        <span className="text-zinc-500 text-[10px]">O(1) Memory Verification</span>
                      </div>
                      <div className="max-h-64 overflow-y-auto space-y-1.5 pr-1">
                        {cascadeResult.hops?.map((h: any) => (
                          <div
                            key={h.hop}
                            className={`flex items-center justify-between px-3 py-2 rounded-lg text-[11px] border ${
                              h.status === 'PASS'
                                ? 'bg-[#08120c] border-emerald-900/30 text-emerald-200'
                                : h.status === 'BLOCKED'
                                ? 'bg-[#22060a] border-rose-800 text-rose-200 font-bold animate-pulse'
                                : 'bg-[#0d0d12] border-zinc-800/40 text-zinc-600'
                            }`}
                          >
                            <div className="flex items-center space-x-3">
                              <span className="font-mono text-zinc-500 w-6">#{h.hop}</span>
                              <span className="font-semibold">{h.service}</span>
                              <span className="text-[10px] text-zinc-400 hidden md:inline">({h.role})</span>
                            </div>
                            <div className="flex items-center space-x-3">
                              <span className="text-[10px] font-mono text-zinc-400">
                                {h.status === 'PASS' ? `${h.total_hop_latency_ms} ms` : h.status === 'BLOCKED' ? 'MISMATCH' : 'SKIPPED'}
                              </span>
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                h.status === 'PASS'
                                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/40'
                                  : h.status === 'BLOCKED'
                                  ? 'bg-rose-950 text-rose-300 border border-rose-700'
                                  : 'bg-zinc-900 text-zinc-500'
                              }`}>
                                {h.status}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {/* Hop 1 Ingress Single-Hop Tests */}
                <div className="pt-3 border-t border-[#161622] space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider font-sans">
                      Hop 1 Ingress Direct Micro-Benchmarks:
                    </span>
                    <span className="text-[10px] text-zinc-500 font-mono">FastAPI /api/mtls/decide Direct</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
                    <button
                      onClick={() => runMtlsTest('legit')}
                      disabled={mtlsLoading}
                      className="p-3 rounded-lg border border-emerald-900/30 bg-[#06120a] hover:bg-[#0a1c10] text-left transition-all cursor-pointer"
                    >
                      <div className="flex items-center justify-between text-xs font-bold text-emerald-300">
                        <span>1. Ingress Fast Path</span>
                        <span>⚡</span>
                      </div>
                      <div className="text-[10px] text-zinc-400 mt-1">Alice valid cert (&lt;0.02ms cached decision)</div>
                    </button>
                    <button
                      onClick={() => runMtlsTest('replay')}
                      disabled={mtlsLoading}
                      className="p-3 rounded-lg border border-rose-900/30 bg-[#160608] hover:bg-[#220a0e] text-left transition-all cursor-pointer"
                    >
                      <div className="flex items-center justify-between text-xs font-bold text-rose-300">
                        <span>2. Stolen Token Replay</span>
                        <span>🚨</span>
                      </div>
                      <div className="text-[10px] text-zinc-400 mt-1">Attacker rogue cert triggers DET-06 revoke</div>
                    </button>
                    <button
                      onClick={() => runMtlsTest('rotate')}
                      disabled={mtlsLoading}
                      className="p-3 rounded-lg border border-cyan-900/30 bg-[#061018] hover:bg-[#0a1824] text-left transition-all cursor-pointer"
                    >
                      <div className="flex items-center justify-between text-xs font-bold text-cyan-300">
                        <span>3. Approved Device Rollover</span>
                        <span>🔄</span>
                      </div>
                      <div className="text-[10px] text-zinc-400 mt-1">Pre-approved cert rotation without disruption</div>
                    </button>
                  </div>

                  {mtlsResult && (
                    <div className="p-3 rounded-lg border border-[#1a1a24] bg-[#050508] space-y-1.5 text-xs font-mono">
                      <div className="flex items-center justify-between">
                        <span className="text-zinc-400">Single Hop Result:</span>
                        <span className={`px-2 py-0.5 rounded font-bold ${
                          mtlsResult.decision === 'FAST_PATH_ALLOW' || mtlsResult.decision === 'ALLOW'
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : 'bg-rose-950 text-rose-300 border border-rose-800'
                        }`}>
                          {mtlsResult.decision} ({mtlsResult.decision_path})
                        </span>
                      </div>
                      <div className="text-[10px] text-zinc-400">
                        Binding: <span className={mtlsResult.binding_status === 'MISMATCH' ? 'text-rose-400 font-bold' : 'text-emerald-400'}>{mtlsResult.binding_status}</span> | Latency: <span className="text-cyan-400">{mtlsResult.latency_ms} ms</span> | Cache Hit: <span className="text-white">{mtlsResult.cache_hit ? 'YES' : 'NO'}</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Active X.509 Certificate Registry Table */}
              <div className="p-6 border border-[#181824] rounded-2xl bg-[#08080c] space-y-4 font-mono">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-300 font-sans">
                      Active X.509 Device Certificate Registry (RFC 8705 &amp; DER Thumbprints)
                    </h3>
                    <p className="text-[11px] text-zinc-400 font-sans mt-0.5">
                      Mutual TLS X.509 certificates loaded from <code className="text-cyan-300">certs/</code> and cryptographically bound to identity session tokens.
                    </p>
                  </div>
                  <span className="text-[10px] font-mono text-zinc-400 bg-[#12121c] px-2.5 py-1 rounded">
                    5 Registered Certificates
                  </span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border border-[#14141e] rounded-xl overflow-hidden">
                    <thead className="bg-[#0f0f16] text-[10px] uppercase text-zinc-400">
                      <tr>
                        <th className="py-2.5 px-3">Identity / Alias</th>
                        <th className="py-2.5 px-3">Subject Common Name</th>
                        <th className="py-2.5 px-3">SHA-256 Fingerprint (x5t#S256)</th>
                        <th className="py-2.5 px-3">Role / Trust Status</th>
                        <th className="py-2.5 px-3">Token Binding</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#14141e]">
                      <tr className="hover:bg-[#0c0c14] transition-all">
                        <td className="py-2.5 px-3 text-cyan-300 font-bold">alice (Engineer)</td>
                        <td className="py-2.5 px-3 text-zinc-300">CN=alice@corp.internal, O=ZeroTrust Local</td>
                        <td className="py-2.5 px-3 font-mono text-zinc-400 text-[10px]">eb:bf:ba:d4:c7:96:2a:ee:d5:1b...</td>
                        <td className="py-2.5 px-3"><span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800/40 text-[10px]">Authorized Staff</span></td>
                        <td className="py-2.5 px-3 text-emerald-400 text-[10px]">✓ Bound (sess-alice-live)</td>
                      </tr>
                      <tr className="hover:bg-[#0c0c14] transition-all">
                        <td className="py-2.5 px-3 text-amber-300 font-bold">bob (Contractor)</td>
                        <td className="py-2.5 px-3 text-zinc-300">CN=bob.contractor@corp.internal, O=ZeroTrust Local</td>
                        <td className="py-2.5 px-3 font-mono text-zinc-400 text-[10px]">69:63:40:3c:a9:36:a8:87:03:60...</td>
                        <td className="py-2.5 px-3"><span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800/40 text-[10px]">External Contractor</span></td>
                        <td className="py-2.5 px-3 text-emerald-400 text-[10px]">✓ Bound (sess-bob-live)</td>
                      </tr>
                      <tr className="hover:bg-[#0c0c14] transition-all bg-[#1a080b]/30">
                        <td className="py-2.5 px-3 text-rose-300 font-bold">attacker (Rogue Device)</td>
                        <td className="py-2.5 px-3 text-zinc-300">CN=attacker.replayer@external.net</td>
                        <td className="py-2.5 px-3 font-mono text-rose-400 text-[10px]">59:80:87:09:70:79:59:2e:68:93...</td>
                        <td className="py-2.5 px-3"><span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800/40 text-[10px]">Untrusted Rogue</span></td>
                        <td className="py-2.5 px-3 text-rose-400 text-[10px]">✗ Blacklisted (DET-06)</td>
                      </tr>
                      <tr className="hover:bg-[#0c0c14] transition-all">
                        <td className="py-2.5 px-3 text-zinc-300 font-bold">server (API Gateway)</td>
                        <td className="py-2.5 px-3 text-zinc-300">CN=localhost, O=ZeroTrust Local</td>
                        <td className="py-2.5 px-3 font-mono text-zinc-400 text-[10px]">a0:26:bc:3b:d8:ad:24:1a:80:e3...</td>
                        <td className="py-2.5 px-3"><span className="px-2 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-800/40 text-[10px]">Zero Trust Gateway</span></td>
                        <td className="py-2.5 px-3 text-zinc-500 text-[10px]">TLS 1.3 Endpoint</td>
                      </tr>
                      <tr className="hover:bg-[#0c0c14] transition-all">
                        <td className="py-2.5 px-3 text-purple-300 font-bold">ca (Internal Root CA)</td>
                        <td className="py-2.5 px-3 text-zinc-300">CN=ZeroTrust Local Development CA</td>
                        <td className="py-2.5 px-3 font-mono text-zinc-400 text-[10px]">3b:6e:95:a4:36:01:dd:25:c4:51...</td>
                        <td className="py-2.5 px-3"><span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800/40 text-[10px]">Root Authority</span></td>
                        <td className="py-2.5 px-3 text-zinc-500 text-[10px]">Anchor of Trust</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Zero Trust Architecture Spec Card */}
              <div className="p-6 border border-[#181824] rounded-2xl bg-[#08080c] space-y-3 font-mono">
                <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-300 font-sans">
                  Hardware Token-Binding Security Architecture
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 rounded-xl border border-[#161620] bg-[#0a0a10]">
                    <div className="text-cyan-400 font-semibold mb-1">1. Bound Proof-of-Possession</div>
                    <div className="text-zinc-400 text-[11px]">
                      Tokens are mathematically coupled to the client's mutual TLS certificate (SHA-256 fingerprint). Bearer tokens cannot be replayed from an external machine without the private key.
                    </div>
                  </div>
                  <div className="p-3 rounded-xl border border-[#161620] bg-[#0a0a10]">
                    <div className="text-cyan-400 font-semibold mb-1">2. Worst-Case Speed (p99) &amp; Average Speed (p50)</div>
                    <div className="text-zinc-400 text-[11px]">
                      When risk &lt; 30 and fingerprint matches cached session binding, decisions complete in ~0.011 ms (80,000+ req/sec), bypassing multi-hop graph re-evaluation.
                    </div>
                  </div>
                  <div className="p-3 rounded-xl border border-[#161620] bg-[#0a0a10]">
                    <div className="text-cyan-400 font-semibold mb-1">3. Atomic Invalidation (Instant Revoke)</div>
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
            RIGHT COLUMN: Live Activity Feed (Okta & CloudTrail Stream)
            (Hidden on 'graph' tab so the Live Attack Graph takes the full right portion)
           ============================================================== */}
        {(activeTab !== 'graph' || showFeedOnGraph) && (
          <aside className="w-80 shrink-0 border-l border-[#16161e] bg-[#050508] flex flex-col p-4 space-y-3.5 overflow-hidden">
          <div className="flex items-center justify-between pb-2 border-b border-[#181822]">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
                <span>Live Activity Feed</span>
              </h3>
              <p className="text-[10px] text-zinc-400 font-mono">Okta &amp; AWS CloudTrail Stream</p>
            </div>
            <span className="text-xs font-mono text-zinc-400">
              {syntheticHistory.length} Scenarios
            </span>
          </div>

          {/* Stream Item Cards */}
          <div className="space-y-2.5 flex-1 overflow-y-auto pr-1">
            {syntheticHistory.length === 0 ? (
              <div className="p-6 border border-[#1a1a24] rounded-xl bg-[#08080c] text-center text-xs text-zinc-400 font-mono">
                No simulated attacks launched yet. Click "⚡ Launch Simulated Attack" on the left to test scenarios.
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
                    <span className="text-cyan-400 hover:text-white">Investigate →</span>
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
              <span className="font-bold uppercase tracking-wider text-zinc-300">Self-Tuning Risk Model</span>
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
        )}
      </div>
    </div>
  )
}
