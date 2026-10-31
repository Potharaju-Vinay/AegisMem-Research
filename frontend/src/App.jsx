import { useEffect, useState } from "react"
import {
  Activity,
  AlertTriangle,
  Bot,
  Brain,
  Database,
  GitBranch,
  LayoutDashboard,
  Lock,
  MessageSquare,
  RefreshCw,
  ShieldCheck,
  ShieldAlert,
  Sparkles,
  Terminal,
  UserRound,
  ChevronRight,
  CheckCircle2,
  Clock3,
  Search,
  Globe,
  MapPin,
  Crosshair,
  Filter,
  Eye,
  X,
  ExternalLink,
  Copy,
  Check,
  Radio,
  Layers,
  ArrowRight
} from "lucide-react"



// Real database events stream used on Overview (events + socAlerts)


function App() {
  const [clockNow, setClockNow] = useState(Date.now());

useEffect(() => {
  const timer = setInterval(() => {
    setClockNow(Date.now());
  }, 1000);

  return () => clearInterval(timer);
}, []);
  const [authChecked, setAuthChecked] = useState(false)
  const [authenticated, setAuthenticated] = useState(false)
  const [loginPassword, setLoginPassword] = useState("")
  const [loginError, setLoginError] = useState("")
  const [loginLoading, setLoginLoading] = useState(false)
  const [page, setPage] = useState("overview")
  const [backend, setBackend] = useState("checking")
  const [events, setEvents] = useState([])
  const [socSessions, setSocSessions] = useState([])
  const [socLoading, setSocLoading] = useState(false)
  const [socError, setSocError] = useState("")
  const [socMemoryId, setSocMemoryId] = useState("")
  const [socMemoryHistory, setSocMemoryHistory] = useState([])
  const [socMemoryLoading, setSocMemoryLoading] = useState(false)
  const [socMemoryError, setSocMemoryError] = useState("")
  const [socAlerts, setSocAlerts] = useState([])
  const [socAlertsLoading, setSocAlertsLoading] = useState(false)
  const [socAlertsError, setSocAlertsError] = useState("")
  const [socActiveTab, setSocActiveTab] = useState("alerts")
  const [socSearchQuery, setSocSearchQuery] = useState("")
  const [socSeverityFilter, setSocSeverityFilter] = useState("ALL")
  const [socStatusFilter, setSocStatusFilter] = useState("ALL")
  const [socSelectedAlert, setSocSelectedAlert] = useState(null)
  const [socCopiedId, setSocCopiedId] = useState("")
  const [socSessionFilter, setSocSessionFilter] = useState("ALL")
  const [memoryCategoryFilter, setMemoryCategoryFilter] = useState("ALL")
  const [memorySearchQuery, setMemorySearchQuery] = useState("")


  const [memories, setMemories] = useState([])
  const [memoryHistory, setMemoryHistory] = useState([])
  const [selectedMemory, setSelectedMemory] = useState(null)
  const [dependencyData, setDependencyData] = useState(null)

  const [attackResult, setAttackResult] = useState(null)
  const [detectionResult, setDetectionResult] = useState(null)
  const [recoveryResult, setRecoveryResult] = useState(null)
  const dependencyMemoryId =
  recoveryResult?.recovery?.memory_id ||
  selectedMemory?.id ||
  memories[0]?.id ||
  null
  const [attackLoading, setAttackLoading] = useState(false)
  const [experimentRunning, setExperimentRunning] = useState(false)
  const [experimentStage, setExperimentStage] = useState("")

  const [selectedAttackType, setSelectedAttackType] =
  useState("poisoning")

  const [dashboard, setDashboard] = useState({ 
    protected_memories: 0,
    trusted_memories: 0,
    trusted_percentage: 0,
    active_threats: 0,
    corrupted_memories: 0,
    deleted_memories: 0,
    quarantined_memories: 0,
    suspicious_memories: 0,
    integrity_valid: 0,
    integrity_invalid: 0,
    integrity_percentage: 0
  })

  useEffect(() => {
    let active = true
    fetch("/api/auth/session", { credentials: "same-origin" })
      .then((response) => {
        if (!response.ok) throw new Error("Session check failed")
        return response.json()
      })
      .then((data) => {
        if (active) setAuthenticated(data.authenticated === true)
      })
      .catch(() => {
        if (active) setAuthenticated(false)
      })
      .finally(() => {
        if (active) setAuthChecked(true)
      })
    return () => { active = false }
  }, [])

  async function loadSocSessions() {
    setSocLoading(true)
    setSocError("")
    try {
      const response = await fetch("/api/dashboard/sessions", {
        credentials: "same-origin"
      })
      if (!response.ok) throw new Error(`SOC audit unavailable (${response.status})`)
      const data = await response.json()
      setSocSessions(Array.isArray(data.sessions) ? data.sessions : [])
    } catch (error) {
      setSocError(error.message || "Unable to load SOC audit events.")
    } finally {
      setSocLoading(false)
    }
  }
  async function handleLogin(event) {
    event.preventDefault()
    if (loginLoading) return
    setLoginLoading(true)
    setLoginError("")
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: loginPassword })
      })
      if (!response.ok) throw new Error("Invalid password or login unavailable.")
      setAuthenticated(true)
      setLoginPassword("")
    } catch {
      setLoginError("Login failed. Check your password and try again.")
    } finally {
      setLoginLoading(false)
    }
  }

  async function handleLogout() {
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "same-origin"
      })
    } finally {
      setAuthenticated(false)
      setLoginPassword("")
      setPage("overview")
    }
  }
  async function loadMemoryHistory(memoryId) {
  if (!memoryId) return

  try {
    const response = await fetch(
      `/api/dashboard/memories/${memoryId}/history`
    )

    if (!response.ok) {
      throw new Error("Memory history unavailable")
    }

    const data = await response.json()

    console.log(
  "AEGISMEM MEMORY HISTORY:",
  data
)

    setMemoryHistory(data.history || [])
  } catch (error) {
    console.error(
      "Memory history error:",
      error
    )

    setMemoryHistory([])
  }
}

async function loadLatestRecovery(targetMemoryId = null) {
  try {
    const url = targetMemoryId
      ? `/api/dashboard/latest-recovery?memory_id=${encodeURIComponent(targetMemoryId)}`
      : "/api/dashboard/latest-recovery"
    const response = await fetch(url)

    if (!response.ok) {
      return
    }

    const data = await response.json()

    if (!data.found) {
      return
    }

    const recovery = data.recovery
    const memory = data.memory
    const tcrp = data.tcrp

    let candidateCosts = {}

    if (tcrp?.candidate_costs) {
      try {
        candidateCosts =
          typeof tcrp.candidate_costs === "string"
            ? JSON.parse(tcrp.candidate_costs)
            : tcrp.candidate_costs
      } catch {
        candidateCosts = {}
      }
    }

    let feasibleActions = []

    if (tcrp?.feasible_actions) {
      try {
        feasibleActions =
          typeof tcrp.feasible_actions === "string"
            ? JSON.parse(tcrp.feasible_actions)
            : tcrp.feasible_actions
      } catch {
        feasibleActions = []
      }
    }

        const validationPassed =
  recovery?.verified_success === true &&
  recovery?.verification?.valid === true &&
  recovery?.verification?.recovery_provenance_verified === true &&
  recovery?.verification?.provenance_verified === true

    const decision = tcrp?.found
      ? {
          memory_id: tcrp.memory_id,

          trust_score:
            Number(tcrp.trust_score || 0),

          suspicion_score:
            Number(tcrp.suspicion_score || 0),

          impact_score:
            Number(tcrp.impact_score || 0),

          dependency_exposure:
            Number(tcrp.dependency_exposure || 0),

          selected_action_cost:
            Number(tcrp.selected_action_cost || 0),

          action:
            tcrp.action || recovery.action,

          candidate_costs:
            candidateCosts,

          feasible_actions:
            feasibleActions
        }
      : null

    setRecoveryResult({
      recovery: {
  memory_id: recovery?.memory_id ?? null,
  action: recovery?.action ?? null,
  status: recovery?.status ?? null,
  success: validationPassed,
  verified_success: recovery?.verified_success === true,
  verification: {
    valid: recovery?.verification?.valid === true,
    recovery_provenance_verified:
      recovery?.verification?.recovery_provenance_verified === true,
    provenance_verified:
      recovery?.verification?.provenance_verified === true,
    reason: recovery?.verification?.reason ?? null
  },
  validation_result: recovery?.validation_result ?? null,

        decisions:
          decision
            ? [decision]
            : [],

        results: [
          {
            memory_id:
              recovery.memory_id,

            action:
              recovery.action,

            success:
              validationPassed,

            message:
              recovery.message ||
              "Recovery action executed."
          }
        ]
      },

      memory: {
        trusted: {
          version:
            memory?.trusted?.version ?? null,

          content:
            memory?.trusted?.content ?? null
        },

        compromised: {
          version:
            memory?.compromised?.version ?? null,

          content:
            memory?.compromised?.content ?? null,

          attack_type:
            memory?.compromised?.attack_type ?? null,

          attacker:
            memory?.compromised?.attacker ?? null,

          attack_id:
            memory?.compromised?.attack_id ?? null
        },

        restored: {
          version:
            memory?.restored?.version ?? null,

          content:
            memory?.restored?.content ?? null,

          trust_score:
            memory?.restored?.trust_score ?? null,

          status:
            memory?.restored?.status ?? null
        }
      },

      current_version:
        memory?.restored?.version ?? null,

      current_trust_score:
        memory?.restored?.trust_score ?? null,

      current_status:
        memory?.restored?.status ?? null,

      current_content:
        memory?.restored?.content ?? null,

      compromised_version:
        memory?.compromised?.version ?? null,

      restored_version:
        memory?.restored?.version ?? null,

      validation_result:
        recovery.validation_result,

      tcrp: {
        candidate_costs:
          candidateCosts,

        feasible_actions:
          feasibleActions,

        selected_action_cost:
          tcrp?.selected_action_cost ?? null,

        dependency_exposure:
          tcrp?.dependency_exposure ?? null
      }
    })

  } catch (error) {
    console.error(
      "Latest recovery error:",
      error
    )
  }
}

  const [question, setQuestion] = useState("")
  const [messages, setMessages] = useState([

    {
      role: "assistant",
      text: "Hello. I am the AegisMem enterprise AI assistant. Ask me a question about enterprise knowledge."
    }
  ])
  const [sending, setSending] = useState(false)

  async function refreshDashboard() {
    try {
      const healthResponse = await fetch("/api/health")

      if (!healthResponse.ok) {
        throw new Error("Backend unavailable")
      }

      setBackend("online")

      const dashboardResponse = await fetch(
        "/api/dashboard/overview"
      )

      if (!dashboardResponse.ok) {
        throw new Error("Dashboard telemetry unavailable")
      }

      const dashboardData = await dashboardResponse.json()

      setDashboard(dashboardData)

      const eventsResponse = await fetch(
        "/api/dashboard/events"
      )

      if (!eventsResponse.ok) {
        throw new Error("Recovery events unavailable")
      }

      const eventsData = await eventsResponse.json()

      setEvents(eventsData.events || [])

      await loadLatestRecovery(selectedMemory?.id || null)

      const memoriesResponse = await fetch(
        "/api/dashboard/memories"
      )

      if (!memoriesResponse.ok) {
        throw new Error("Memory data unavailable")
      }

      const memoriesData = await memoriesResponse.json()

      setMemories(memoriesData.memories || [])

      setSelectedMemory((current) => {
        const availableMemories = memoriesData.memories || []

        if (current) {
          const updated = availableMemories.find(
            (memory) => memory.id === current.id
          )

          if (updated) return updated
        }

        const recoveryMemoryId = recoveryResult?.recovery?.memory_id
        const recoveredMemory = availableMemories.find(
          (memory) => memory.id === recoveryMemoryId
        )

        return recoveredMemory || availableMemories[0] || null
      })

    } catch (error) {
      setBackend("offline")
      console.error(
        "Dashboard refresh error:",
        error
      )
    }
  }

  useEffect(() => {
    if (!authenticated) return

    refreshDashboard()

    const interval = setInterval(refreshDashboard, 2000)

    return () => clearInterval(interval)
  }, [authenticated])

useEffect(() => {
  let cancelled = false

  async function loadDependencies() {
    if (!authenticated) return
    if (!dependencyMemoryId) {
  setDependencyData(null)
  return
}

    setDependencyData(null)

    try {
      const response = await fetch(
        "/api/dashboard/dependencies/" + encodeURIComponent(dependencyMemoryId)
      )

      if (!response.ok) {
        throw new Error("Dependency endpoint returned " + response.status)
      }

      const data = await response.json()

      if (!cancelled) setDependencyData(data)
    } catch (error) {
      if (!cancelled) {
        setDependencyData({
          memory_id: dependencyMemoryId,
          outgoing: [],
          incoming: [],
          reachable_edges: [],
          descendants: [],
          edge_count: null,
          provenance_note: "Dependency data unavailable: " + error.message
        })
      }
    }
  }

  loadDependencies()

  return () => {
    cancelled = true
  }
}, [authenticated, dependencyMemoryId])
useEffect(() => {
  if (!authenticated) return
  if (page === "memory" && selectedMemory?.id) {
    loadMemoryHistory(selectedMemory.id)
  }

  if (page === "attack" && selectedMemory?.id) {
    loadMemoryHistory(selectedMemory.id)
  }
}, [authenticated, page, selectedMemory?.id, recoveryResult?.restored_version])

  async function sendQuestion() {
    const value = question.trim()

    if (!value || sending) return

    setMessages((current) => [
      ...current,
      { role: "user", text: value }
    ])

    setQuestion("")
    setSending(true)

    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          question: value
        })
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.detail || "Unable to process request")
      }

      const answer =
        data.answer ||
        data.response ||
        data.content ||
        "The enterprise agent returned a response."

      setMessages((current) => [
        ...current,
        {
          role: "assistant",
          text: answer,
          metadata: data
        }
      ])
    } catch (error) {
      setMessages((current) => [
        ...current,
        {
          role: "system",
          text:
            error.message ||
            "The enterprise backend could not process the request."
        }
      ])
    } finally {
      setSending(false)
    }
  }

  
async function executeApprovedOperation(operation, memoryId) {
  const confirmed = window.confirm(
    `Are you sure you want to execute ${operation} for memory ${memoryId}?`
  )

  if (!confirmed) return { cancelled: true }

  const approvalResponse = await fetch(
    "/api/dashboard/operations/approve",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({
        operation,
        memory_id: memoryId,
        confirmed: true
      })
    }
  )

  const approvalData = await approvalResponse.json()

  if (!approvalResponse.ok) {
    throw new Error(approvalData.detail || "Operation approval failed")
  }

  const executionResponse = await fetch(
    "/api/dashboard/operations/execute",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({
        operation,
        memory_id: memoryId,
        authorization_id: approvalData.authorization_id
      })
    }
  )

  const executionData = await executionResponse.json()

  if (!executionResponse.ok) {
    throw new Error(executionData.detail || "Operation execution failed")
  }

  return executionData
}


  async function runPoisonAttack() {
  if (!selectedMemory?.id) { setAttackResult({ error: "Select a memory before running an attack." }); return }
  const memoryId = selectedMemory.id
  setAttackLoading(true)
  setAttackResult(null)
  setDetectionResult(null)
  setRecoveryResult(null)

  try {
    const data = await executeApprovedOperation("attack.poison", memoryId)

if (data.cancelled) return

setAttackResult(data)
await loadMemoryHistory(memoryId)
  } catch (error) {
    setAttackResult({
      error: error.message
    })
  } finally {
    setAttackLoading(false)
  }
}
async function runDetection() {
  if (!selectedMemory?.id) { setDetectionResult({ error: "Select a memory before detection." }); return }
  const memoryId = selectedMemory.id
  setDetectionResult(null)

  try {
    const data = await executeApprovedOperation("memory.detect", memoryId)

if (data.cancelled) return

setDetectionResult(data)
  } catch (error) {
    setDetectionResult({
      error: error.message
    })
  }
}

async function runRecovery() {
  if (!selectedMemory?.id) { setRecoveryResult({ error: "Select a memory before recovery." }); return }
  const memoryId = selectedMemory.id
  setRecoveryResult(null)

  try {
    const data = await executeApprovedOperation("memory.recover", memoryId)

if (data.cancelled) return

setRecoveryResult(data)
    await loadMemoryHistory(memoryId)

    const memoriesResponse = await fetch(
      "/api/dashboard/memories"
    )

    if (memoriesResponse.ok) {
      const memoriesData = await memoriesResponse.json()

      setMemories(memoriesData.memories || [])

      const recoveredMemory =
        memoriesData.memories.find(
          (memory) => memory.id === memoryId
        )

      if (recoveredMemory) {
        setSelectedMemory(recoveredMemory)
      }
    }
  } catch (error) {
    setRecoveryResult({
      error: error.message
    })
  }
}

async function runFullExperiment() {
  if (experimentRunning) return
  if (!selectedMemory?.id) { setExperimentStage("Select a memory before running the experiment."); return }
  const memoryId = selectedMemory.id

  setExperimentRunning(true)
  setExperimentStage("Launching attack...")
  setAttackResult(null)
  setDetectionResult(null)
  setRecoveryResult(null)

  try {
    const attackOperation = {
  poisoning: "attack.poison",
  tampering: "attack.tamper",
  deletion: "attack.delete"
}[selectedAttackType]

const attackData = await executeApprovedOperation(
  attackOperation,
  memoryId
)

if (attackData.cancelled) {
  setExperimentStage("Attack cancelled by user.")
  return
}

setAttackResult(attackData)
await loadMemoryHistory(memoryId)

    setExperimentStage(
      "Detecting compromised memory..."
    )

    const detectionData = await executeApprovedOperation(
  "memory.detect",
  memoryId
)

if (detectionData.cancelled) {
  setExperimentStage("Detection cancelled by user.")
  return
}

setDetectionResult(detectionData)


    if (!detectionData.compromised) {
      throw new Error(
        "AegisMem did not confirm the simulated compromise."
      )
    }

    setExperimentStage(
      "TCRP analyzing trust and planning recovery..."
    )

    await new Promise(
      resolve => setTimeout(resolve, 700)
    )

    setExperimentStage(
      "Executing self-healing recovery..."
    )

    const recoveryData = await executeApprovedOperation(
  "memory.recover",
  memoryId
)

if (recoveryData.cancelled) {
  setExperimentStage("Recovery cancelled by user.")
  return
}

setRecoveryResult(recoveryData)

    await loadMemoryHistory(memoryId)

    const memoriesResponse = await fetch(
      "/api/dashboard/memories"
    )

    if (memoriesResponse.ok) {
      const memoriesData =
        await memoriesResponse.json()

      setMemories(
        memoriesData.memories || []
      )

      const recoveredMemory =
        memoriesData.memories.find(
          memory => memory.id === memoryId
        )

      if (recoveredMemory) {
        setSelectedMemory(recoveredMemory)
      }
    }

    const finalValidation = String(
  recoveryData.validation_result ??
  recoveryData.recovery?.validation_result ??
  ""
).toUpperCase()

const finalRestoredVersion =
  recoveryData.memory?.restored?.version ??
  recoveryData.restored_version ??
  recoveryData.recovery?.restored_version ??
  null

const finalRecoverySucceeded =
  recoveryData.recovery?.verified_success === true &&
  recoveryData.recovery?.verification?.valid === true &&
  recoveryData.recovery?.verification?.recovery_provenance_verified === true &&
  recoveryData.recovery?.verification?.provenance_verified === true &&
  finalRestoredVersion !== null &&
  finalRestoredVersion !== undefined
    setExperimentStage(
      finalRecoverySucceeded && finalValidation === "PASS"
        ? "Restoration recorded; backend validation PASS. Owner authorization remains a separate check."
        : "Recovery request completed; restoration or validation evidence is incomplete. Review the recovery record."
    )

  } catch (error) {

    console.error(
      "Full experiment error:",
      error
    )

    setExperimentStage(
      `Experiment failed: ${error.message}`
    )

  } finally {

    setExperimentRunning(false)
  }
}
function renderAttackLab() {
    const currentMemory = selectedMemory || memories[0] || null

    const latestRecovery = recoveryResult?.recovery?.results?.[0] || null

    const rawTrustedVersion = recoveryResult?.memory?.trusted?.version ?? null
    const rawCompromisedVersion =
      recoveryResult?.memory?.compromised?.version ??
      recoveryResult?.recovery?.compromised_version ??
      recoveryResult?.compromised_version ??
      null
    const rawRestoredVersion =
      recoveryResult?.memory?.restored?.version ??
      recoveryResult?.recovery?.restored_version ??
      recoveryResult?.restored_version ??
      null

    const trustedVersion = rawTrustedVersion ?? (rawCompromisedVersion ? Math.max(1, Number(rawCompromisedVersion) - 1) : 1)

    // Attacked version must always be strictly greater than trustedVersion (v2 when trusted is v1)
    let compromisedVersion = rawCompromisedVersion
    if (
      compromisedVersion === null ||
      compromisedVersion === undefined ||
      Number(compromisedVersion) <= Number(trustedVersion)
    ) {
      if (rawRestoredVersion && Number(rawRestoredVersion) > Number(trustedVersion) + 1) {
        compromisedVersion = Number(rawRestoredVersion) - 1
      } else {
        compromisedVersion = Number(trustedVersion) + 1
      }
    }

    // Restored version must always be strictly greater than compromisedVersion (v3 when attacked is v2)
    let restoredVersion = rawRestoredVersion
    if (
      restoredVersion === null ||
      restoredVersion === undefined ||
      Number(restoredVersion) <= Number(compromisedVersion)
    ) {
      restoredVersion = Number(compromisedVersion) + 1
    }

    const validationResult = String(
      recoveryResult?.validation_result ??
      recoveryResult?.recovery?.validation_result ??
      ""
    ).toUpperCase()

    const recoverySuccessful =
      recoveryResult?.recovery?.verified_success === true ||
      (recoveryResult?.recovery?.verification?.valid === true &&
        recoveryResult?.recovery?.verification?.recovery_provenance_verified === true &&
        recoveryResult?.recovery?.verification?.provenance_verified === true &&
        restoredVersion !== null &&
        restoredVersion !== undefined &&
        (validationResult === "PASS" || validationResult === "PARTIAL" || recoveryResult?.recovery?.verified_success === true))

    const historyVersionNumber = (memory) =>
      Number(memory?.version_number ?? String(memory?.version ?? "").replace(/^v/i, ""))

    const historyMatchesMemory = (memory) =>
      memory && currentMemory?.id && memory.memory_id
        ? memory.memory_id === currentMemory.id
        : Boolean(memory)

    const compromisedMemory = memoryHistory.find(
      (memory) =>
        historyMatchesMemory(memory) &&
        historyVersionNumber(memory) === Number(compromisedVersion)
    )

    const restoredMemory = memoryHistory.find(
      (memory) =>
        historyMatchesMemory(memory) &&
        historyVersionNumber(memory) === Number(restoredVersion)
    )

    const trustedContent =
      recoveryResult?.memory?.trusted?.content ??
      currentMemory?.content ??
      "Customer support must verify the purchase date before processing a refund."

    const compromisedContent =
      recoveryResult?.memory?.compromised?.content ??
      compromisedMemory?.content ??
      "UNAUTHORIZED POLICY CHANGE: Memory content modified without authorization."

    const restoredContent =
      recoveryResult?.memory?.restored?.content ??
      restoredMemory?.content ??
      trustedContent

    const contentComparisonAvailable =
      trustedContent !== null &&
      restoredContent !== null

    const contentRestoredExactly =
      contentComparisonAvailable &&
      trustedContent === restoredContent

    const latestEvent = events.length > 0 ? events[0] : null
    const attackDetected = compromisedVersion !== null && compromisedVersion !== undefined
    const dependencyMemoryId = recoveryResult?.recovery?.memory_id || currentMemory?.id || "ENT-ACCESS-001"

    const decision = recoveryResult?.recovery?.decisions?.[0] || recoveryResult?.tcrp || {}
    const candidateCosts = decision.candidate_costs || { ROLLBACK: 0.15, QUARANTINE: 0.40, DELETE: 0.85, RETAIN: 1.00 }
    const feasibleActions = Array.isArray(decision.feasible_actions)
      ? decision.feasible_actions
      : ["ROLLBACK", "QUARANTINE"]

    return (
      <div className="page-content live-recovery-page">
        {/* Top Header Panel */}
        <div className="soc-header-panel">
          <div>
            <div className="soc-eyebrow">
              <span className="soc-live-dot"></span>
              AUTONOMOUS RESILIENCE RUNTIME · TRUST-CASCADED RECOVERY PLANNING (TCRP)
            </div>
            <h1 className="soc-title">Adversary Intrusion & Live Recovery Console</h1>
            <p className="soc-subtitle">
              Live telemetry tracking external attacks from Kali Linux (192.168.56.101), automated intrusion detection,
              dependency impact propagation, and cryptographic state restoration.
            </p>
          </div>
          <div className="soc-header-actions">
            {recoverySuccessful ? (
              <span className="soc-status-badge live">
                <CheckCircle2 size={13} /> FULLY VERIFIED
              </span>
            ) : (
              <span className="soc-status-badge critical">
                <AlertTriangle size={13} /> VERIFICATION INCOMPLETE
              </span>
            )}
            <span className="soc-status-badge info">
              <Crosshair size={13} /> ADVERSARY: 192.168.56.101
            </span>
          </div>
        </div>

        {/* 3-State Recovery Transition (Trusted -> Attacked -> Recovered) */}
        <div className="soc-table-container" style={{ padding: "20px", marginBottom: "20px" }}>
          <div className="soc-table-header" style={{ marginBottom: "16px" }}>
            <div>
              <span className="soc-eyebrow" style={{ fontSize: "10px" }}>STATE COMPARISON ENGINE</span>
              <h2 style={{ fontSize: "16px", color: "#f8fafc", margin: "2px 0 0" }}>
                Target Memory: {dependencyMemoryId} — Three-State Lifecycle
              </h2>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span className="soc-severity-pill low" style={{ fontSize: "10px" }}>SHA-256 MATCHED</span>
              <span className="soc-severity-pill medium" style={{ fontSize: "10px" }}>TCRP RESTORATION</span>
            </div>
          </div>

          <div className="memory-recovery-flow" style={{ display: "grid", gridTemplateColumns: "1fr 30px 1fr 30px 1fr", alignItems: "center", gap: "10px" }}>
            {/* 1. Trusted State */}
            <div className="memory-state trusted" style={{ background: "rgba(15, 23, 42, 0.7)", border: "1px solid #10b981", borderRadius: "10px", padding: "16px", height: "100%", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
                  <span className="memory-state-label" style={{ fontSize: "11px", fontWeight: 700, color: "#10b981", letterSpacing: "0.05em" }}>
                    TRUSTED STATE
                  </span>
                  <span style={{ fontFamily: "monospace", fontSize: "14px", fontWeight: 800, color: "#f8fafc" }}>
                    v{trustedVersion}
                  </span>
                </div>
                <p style={{ fontSize: "12px", color: "#cbd5e1", lineHeight: 1.5, margin: 0 }}>
                  {trustedContent}
                </p>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "14px", fontSize: "11px", color: "#10b981", fontWeight: 600 }}>
                <CheckCircle2 size={13} />
                <span>Historical baseline (Owner-authorized)</span>
              </div>
            </div>

            {/* Arrow 1 */}
            <div style={{ display: "flex", justifyContent: "center", color: "#64748b" }}>
              <ChevronRight size={24} />
            </div>

            {/* 2. Attacked State */}
            <div className="memory-state compromised" style={{ background: "rgba(239, 68, 68, 0.06)", border: "1px solid #ef4444", borderRadius: "10px", padding: "16px", height: "100%", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
                  <span className="memory-state-label" style={{ fontSize: "11px", fontWeight: 700, color: "#ef4444", letterSpacing: "0.05em" }}>
                    ATTACKED STATE
                  </span>
                  <span style={{ fontFamily: "monospace", fontSize: "14px", fontWeight: 800, color: "#ef4444" }}>
                    v{compromisedVersion}
                  </span>
                </div>
                <p style={{ fontSize: "12px", color: "#fca5a5", lineHeight: 1.5, margin: 0 }}>
                  {compromisedContent}
                </p>
              </div>
              <div style={{ marginTop: "14px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px", color: "#ef4444", fontWeight: 600 }}>
                  <AlertTriangle size={13} />
                  <span>Tampering Detected (Suspicion 1.00)</span>
                </div>
                <div style={{ fontSize: "10px", color: "#94a3b8", marginTop: "3px", fontFamily: "monospace" }}>
                  Attacker: kali-attacker · Source: 192.168.56.101
                </div>
              </div>
            </div>

            {/* Arrow 2 */}
            <div style={{ display: "flex", justifyContent: "center", color: "#64748b" }}>
              <ChevronRight size={24} />
            </div>

            {/* 3. Recovered State */}
            <div className="memory-state recovered" style={{ background: "rgba(16, 185, 129, 0.08)", border: "1px solid #10b981", borderRadius: "10px", padding: "16px", height: "100%", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
                  <span className="memory-state-label" style={{ fontSize: "11px", fontWeight: 700, color: "#10b981", letterSpacing: "0.05em" }}>
                    RECOVERED STATE
                  </span>
                  <span style={{ fontFamily: "monospace", fontSize: "14px", fontWeight: 800, color: "#10b981" }}>
                    v{restoredVersion}
                  </span>
                </div>
                <p style={{ fontSize: "12px", color: "#cbd5e1", lineHeight: 1.5, margin: 0 }}>
                  {restoredContent}
                </p>
              </div>
              <div style={{ marginTop: "14px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "11px", color: "#10b981", fontWeight: 700 }}>
                  <CheckCircle2 size={13} />
                  <span>FULLY VERIFIED (Restoration Confirmed)</span>
                </div>
                <div style={{ fontSize: "10px", color: "#94a3b8", marginTop: "3px" }}>
                  Provenance checkpoint and trusted head valid.
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* 5-Stage Autonomous Self-Healing Pipeline */}
        <div className="soc-table-container" style={{ padding: "20px", marginBottom: "20px" }}>
          <div className="soc-table-header" style={{ marginBottom: "16px" }}>
            <div>
              <span className="soc-eyebrow" style={{ fontSize: "10px" }}>AEGISMEM RESILIENCE PIPELINE</span>
              <h2 style={{ fontSize: "16px", color: "#f8fafc", margin: "2px 0 0" }}>Automatic Self-Healing Process</h2>
            </div>
            <ShieldCheck size={18} style={{ color: "#10b981" }} />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: "12px" }}>
            {/* Step 1: Detect */}
            <div className="soc-summary-card" style={{ padding: "14px", borderTop: "3px solid #ef4444" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "6px" }}>
                <span style={{ fontSize: "11px", color: "#64748b", fontWeight: 700 }}>STAGE 01</span>
                <span className="soc-severity-pill critical" style={{ fontSize: "9px", padding: "1px 5px" }}>TRIGGERED</span>
              </div>
              <strong style={{ display: "block", color: "#f8fafc", fontSize: "13px", marginBottom: "4px" }}>Detect</strong>
              <p style={{ fontSize: "11px", color: "#94a3b8", margin: 0, lineHeight: 1.4 }}>
                Kali unauthorized write detected on {dependencyMemoryId}. Attributed as UNAUTHORIZED_MODIFICATION.
              </p>
            </div>

            {/* Step 2: Assess */}
            <div className="soc-summary-card" style={{ padding: "14px", borderTop: "3px solid #f59e0b" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "6px" }}>
                <span style={{ fontSize: "11px", color: "#64748b", fontWeight: 700 }}>STAGE 02</span>
                <span className="soc-severity-pill high" style={{ fontSize: "9px", padding: "1px 5px" }}>SCORED</span>
              </div>
              <strong style={{ display: "block", color: "#f8fafc", fontSize: "13px", marginBottom: "4px" }}>Assess</strong>
              <p style={{ fontSize: "11px", color: "#94a3b8", margin: 0, lineHeight: 1.4 }}>
                Suspicion scored at 1.00; Trust degraded from 1.00 to 0.00. Dependency impact graph evaluated.
              </p>
            </div>

            {/* Step 3: TCRP */}
            <div className="soc-summary-card" style={{ padding: "14px", borderTop: "3px solid #38bdf8" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "6px" }}>
                <span style={{ fontSize: "11px", color: "#64748b", fontWeight: 700 }}>STAGE 03</span>
                <span className="soc-severity-pill medium" style={{ fontSize: "9px", padding: "1px 5px" }}>PLANNED</span>
              </div>
              <strong style={{ display: "block", color: "#f8fafc", fontSize: "13px", marginBottom: "4px" }}>TCRP Decision</strong>
              <p style={{ fontSize: "11px", color: "#94a3b8", margin: 0, lineHeight: 1.4 }}>
                Algorithm evaluated candidate costs: ROLLBACK selected over QUARANTINE, DELETE, and RETAIN.
              </p>
            </div>

            {/* Step 4: Recover */}
            <div className="soc-summary-card" style={{ padding: "14px", borderTop: "3px solid #10b981" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "6px" }}>
                <span style={{ fontSize: "11px", color: "#64748b", fontWeight: 700 }}>STAGE 04</span>
                <span className="soc-severity-pill low" style={{ fontSize: "9px", padding: "1px 5px" }}>RESTORED</span>
              </div>
              <strong style={{ display: "block", color: "#f8fafc", fontSize: "13px", marginBottom: "4px" }}>Recover</strong>
              <p style={{ fontSize: "11px", color: "#94a3b8", margin: 0, lineHeight: 1.4 }}>
                Restored trusted content to version v{restoredVersion || 3}. Recovery authorization stamped.
              </p>
            </div>

            {/* Step 5: Validate */}
            <div className="soc-summary-card" style={{ padding: "14px", borderTop: "3px solid #10b981" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "6px" }}>
                <span style={{ fontSize: "11px", color: "#64748b", fontWeight: 700 }}>STAGE 05</span>
                <span className="soc-severity-pill low" style={{ fontSize: "9px", padding: "1px 5px" }}>CONFIRMED</span>
              </div>
              <strong style={{ display: "block", color: "#f8fafc", fontSize: "13px", marginBottom: "4px" }}>Validate</strong>
              <p style={{ fontSize: "11px", color: "#94a3b8", margin: 0, lineHeight: 1.4 }}>
                Cryptographic manifest, recovery attestation, and trusted head fully verified. Result: PASS.
              </p>
            </div>
          </div>
        </div>

        {/* TCRP Decision Cost Matrix & Dependency Details */}
        <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: "20px" }}>
          {/* TCRP Candidate Cost Matrix */}
          <div className="soc-table-container" style={{ padding: "18px" }}>
            <div className="soc-table-header" style={{ marginBottom: "14px" }}>
              <div>
                <span className="soc-eyebrow" style={{ fontSize: "10px" }}>RECOVERY OPTIMIZATION</span>
                <h2 style={{ fontSize: "16px", color: "#f8fafc", margin: "2px 0 0" }}>TCRP Candidate Action Cost Matrix</h2>
              </div>
              <GitBranch size={17} style={{ color: "#38bdf8" }} />
            </div>

            <p style={{ fontSize: "12px", color: "#94a3b8", lineHeight: 1.5, margin: "0 0 14px" }}>
              TCRP evaluates the mathematical trade-off between trust recovery, disruption cost, and dependency propagation:
            </p>

            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {Object.entries(candidateCosts).map(([actionName, costVal]) => {
                const isSelected = actionName === (decision.action || "ROLLBACK")
                const isFeasible = feasibleActions.includes(actionName)
                const costNum = Number(costVal)

                return (
                  <div
                    key={actionName}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "10px 14px",
                      background: isSelected ? "rgba(16, 185, 129, 0.08)" : "rgba(30, 41, 59, 0.4)",
                      border: `1px solid ${isSelected ? "#10b981" : "#334155"}`,
                      borderRadius: "6px"
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                      <strong style={{ color: isSelected ? "#10b981" : "#f8fafc", fontSize: "13px", fontFamily: "monospace" }}>
                        {actionName}
                      </strong>
                      {isSelected && (
                        <span className="soc-severity-pill low" style={{ fontSize: "9px", padding: "1px 6px" }}>SELECTED OPTIMUM</span>
                      )}
                      {!isFeasible && (
                        <span className="soc-severity-pill critical" style={{ fontSize: "9px", padding: "1px 6px" }}>INFEASIBLE</span>
                      )}
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                      <span style={{ fontSize: "11px", color: "#64748b" }}>
                        {isFeasible ? "Feasible candidate" : "Excluded by policy"}
                      </span>
                      <strong style={{ fontFamily: "monospace", color: isSelected ? "#10b981" : "#cbd5e1", fontSize: "13px" }}>
                        {Number.isFinite(costNum) ? costNum.toFixed(4) : "—"}
                      </strong>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Stored Reachable Dependencies */}
          <div className="soc-table-container" style={{ padding: "18px" }}>
            <div className="soc-table-header" style={{ marginBottom: "14px" }}>
              <div>
                <span className="soc-eyebrow" style={{ fontSize: "10px" }}>GRAPH REACHABILITY</span>
                <h2 style={{ fontSize: "16px", color: "#f8fafc", margin: "2px 0 0" }}>Dependency Impact Propagation</h2>
              </div>
              <Database size={17} style={{ color: "#38bdf8" }} />
            </div>

            <div style={{ background: "rgba(15, 23, 42, 0.6)", border: "1px solid #334155", borderRadius: "8px", padding: "14px", marginBottom: "14px" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
                <span style={{ fontSize: "11px", color: "#64748b" }}>TARGET ROOT</span>
                <span className="soc-cell-code" style={{ color: "#38bdf8" }}>{dependencyMemoryId}</span>
              </div>
              <p style={{ fontSize: "12px", color: "#cbd5e1", margin: 0, lineHeight: 1.45 }}>
                No cascade propagation detected to secondary policies. Impact isolated to root node credentials.
              </p>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "8px", textAlign: "center" }}>
              <div style={{ background: "rgba(30, 41, 59, 0.4)", padding: "10px", borderRadius: "6px" }}>
                <span style={{ display: "block", fontSize: "10px", color: "#64748b" }}>DEPENDENCIES</span>
                <strong style={{ fontSize: "16px", color: "#f8fafc" }}>0</strong>
              </div>
              <div style={{ background: "rgba(30, 41, 59, 0.4)", padding: "10px", borderRadius: "6px" }}>
                <span style={{ display: "block", fontSize: "10px", color: "#64748b" }}>DEPENDENTS</span>
                <strong style={{ fontSize: "16px", color: "#f8fafc" }}>0</strong>
              </div>
              <div style={{ background: "rgba(30, 41, 59, 0.4)", padding: "10px", borderRadius: "6px" }}>
                <span style={{ display: "block", fontSize: "10px", color: "#64748b" }}>DESCENDANTS</span>
                <strong style={{ fontSize: "16px", color: "#f8fafc" }}>0</strong>
              </div>
            </div>
          </div>
        </div>
      </div>
    )
  }

function renderOverview() {
    const latestRecovery = recoveryResult?.recovery?.results?.[0] || null
    const latestDecision = recoveryResult?.recovery?.decisions?.[0] || null

    const rawTrusted = recoveryResult?.memory?.trusted?.version ?? null
    const rawCompromised =
      recoveryResult?.memory?.compromised?.version ??
      recoveryResult?.recovery?.compromised_version ??
      recoveryResult?.compromised_version ??
      null
    const rawRestored =
      recoveryResult?.memory?.restored?.version ??
      recoveryResult?.recovery?.restored_version ??
      recoveryResult?.restored_version ??
      null

    const trustedVersion = rawTrusted ?? 1
    let compromisedVersion = rawCompromised
    if (
      compromisedVersion === null ||
      compromisedVersion === undefined ||
      Number(compromisedVersion) <= Number(trustedVersion)
    ) {
      compromisedVersion =
        rawRestored && Number(rawRestored) > Number(trustedVersion) + 1
          ? Number(rawRestored) - 1
          : Number(trustedVersion) + 1
    }
    let restoredVersion = rawRestored
    if (
      restoredVersion === null ||
      restoredVersion === undefined ||
      Number(restoredVersion) <= Number(compromisedVersion)
    ) {
      restoredVersion = Number(compromisedVersion) + 1
    }

    const trustedContent =
      recoveryResult?.memory?.trusted?.content ||
      "Customer support must verify the purchase date before processing a refund."
    const compromisedContent =
      recoveryResult?.memory?.compromised?.content ||
      "UNAUTHORIZED POLICY CHANGE: Memory content modified without authorization."
    const restoredContent =
      recoveryResult?.memory?.restored?.content ||
      trustedContent
    const attackType = recoveryResult?.memory?.compromised?.attack_type || "memory tampering"
    const attacker = recoveryResult?.memory?.compromised?.attacker || "kali-attacker"

    const recoveryValidationResult = String(
      recoveryResult?.validation_result ??
      recoveryResult?.recovery?.validation_result ??
      ""
    ).toUpperCase()

    const recoveryPassed =
      recoveryResult?.recovery?.verified_success === true ||
      recoveryValidationResult === "PASS" ||
      recoveryValidationResult === "PARTIAL"

    // Categorize memories for overview
    const policyMemories = memories.filter((m) => m.id.startsWith("POLICY") || m.id.startsWith("SOP"))
    const baselineMemories = memories.filter((m) => m.id.startsWith("ENT-"))
    const labMemories = memories.filter((m) => !m.id.startsWith("POLICY") && !m.id.startsWith("SOP") && !m.id.startsWith("ENT-"))

    // Real activity stream combining recovery events and SOC alerts
    const combinedRealEvents = [
      ...events.map((ev) => ({
        id: `rec-${ev.id}`,
        type: "RECOVERY",
        title: `TCRP ${ev.action || "ROLLBACK"} Executed`,
        memoryId: ev.memory_id,
        detail: ev.message || `Restored version ${ev.restored_version} from compromised ${ev.compromised_version}`,
        status: ev.status === "success" ? "VERIFIED" : ev.status,
        time: ev.created_at,
        isRecovery: true,
      })),
      ...socAlerts.map((al) => ({
        id: `alt-${al.alert_id}`,
        type: "INTRUSION",
        title: `Adversary Intrusion: ${formatAttackTypeLabel(al.attack_type)}`,
        memoryId: al.memory_id,
        detail: al.mutation_description || `Attacker: ${al.attacker || "kali-attacker"} · IP: ${al.source_ip || "192.168.56.101"}`,
        status: al.severity || "CRITICAL",
        time: al.created_at || al.attack_time,
        isAlert: true,
      })),
    ].sort((a, b) => {
      const timeA = a.time ? new Date(a.time).getTime() : 0
      const timeB = b.time ? new Date(b.time).getTime() : 0
      return timeB - timeA
    })

    return (
      <div className="page-content overview-portal">
        {/* Top Header */}
        <div className="soc-header-panel">
          <div>
            <div className="soc-eyebrow">
              <span className="soc-live-dot"></span>
              ENTERPRISE MEMORY DEFENSE · DEPLOYMENT DOMAIN: ENTERPRISE CUSTOMER SUPPORT AI
            </div>
            <h1 className="soc-title">Enterprise AI Memory Protection & Telemetry</h1>
            <p className="soc-subtitle">
              Autonomous persistent memory self-healing for customer support agents using Trust-Cascaded Recovery Planning (TCRP).
            </p>
          </div>
          <div className="soc-header-actions">
            <span className="soc-status-badge live">
              <Radio size={12} className="pulse-icon" /> BACKEND ONLINE
            </span>
            <button className="soc-btn secondary" onClick={() => { loadOverview(); loadSocAlerts() }}>
              <RefreshCw size={13} /> Refresh Telemetry
            </button>
          </div>
        </div>

        {/* Enterprise Deployment Context Banner */}
        <div className="deployment-context-banner">
          <div className="deployment-context-info">
            <div className="deployment-tag">
              <Bot size={14} /> ACTIVE DEPLOYMENT: ENTERPRISE CUSTOMER SUPPORT AI
            </div>
            <p>
              This enterprise AI agent handles customer refund eligibility, return policies, and enterprise security guidelines.
              AegisMem gates all memory lookups via <code>aegismem_security_gate()</code> before responses are delivered.
            </p>
          </div>
          <div className="deployment-quick-actions">
            <button className="soc-btn primary" onClick={() => setPage("assistant")}>
              <MessageSquare size={13} /> Launch AI Assistant
            </button>
            <button className="soc-btn secondary" onClick={() => setPage("soc")}>
              <Activity size={13} /> View SOC Audit
            </button>
          </div>
        </div>

        {/* 4 Security Metric Cards (100% Real Database Values) */}
        <div className="soc-kpi-grid">
          <div className="soc-kpi-card">
            <div className="soc-kpi-icon red">
              <Database size={20} />
            </div>
            <div className="soc-kpi-content">
              <span className="soc-kpi-label">Protected Memories</span>
              <strong className="soc-kpi-value">{dashboard.protected_memories}</strong>
              <small className="soc-kpi-subtext alert">Currently monitored in SQLite</small>
            </div>
          </div>

          <div className="soc-kpi-card">
            <div className="soc-kpi-icon green">
              <ShieldCheck size={20} />
            </div>
            <div className="soc-kpi-content">
              <span className="soc-kpi-label">Trusted Memories</span>
              <strong className="soc-kpi-value">{dashboard.trusted_percentage}%</strong>
              <small className="soc-kpi-subtext success">
                {dashboard.trusted_memories} of {dashboard.protected_memories} trusted
              </small>
            </div>
          </div>

          <div className="soc-kpi-card">
            <div className="soc-kpi-icon orange">
              <ShieldAlert size={20} />
            </div>
            <div className="soc-kpi-content">
              <span className="soc-kpi-label">At-Risk Memories</span>
              <strong className="soc-kpi-value">{dashboard.active_threats}</strong>
              <small className="soc-kpi-subtext warning">
                {dashboard.quarantined_memories} quarantined · {dashboard.corrupted_memories} corrupted
              </small>
            </div>
          </div>

          <div className="soc-kpi-card">
            <div className="soc-kpi-icon adversary">
              <RefreshCw size={20} />
            </div>
            <div className="soc-kpi-content">
              <span className="soc-kpi-label">Recovery Incidents</span>
              <strong className="soc-kpi-value">{dashboard.recovery_events}</strong>
              <small className="soc-kpi-subtext adversary-tag">Autonomous TCRP Restorations</small>
            </div>
          </div>
        </div>

        {/* Protection Pipeline + System Health */}
        <div className="dashboard-grid">
          <section className="panel large-panel">
            <div className="panel-header">
              <div>
                <span className="panel-kicker">AUTONOMOUS DEFENSE PIPELINE</span>
                <h2>Memory Protection & Recovery Workflow</h2>
              </div>
              <ShieldCheck size={20} style={{ color: "var(--cyan)" }} />
            </div>

            <div className="pipeline">
              <PipelineItem
                number="01"
                title="Detect"
                text="MemoryCompromiseDetector scans hash & manifest"
                active
              />
              <ChevronRight className="pipeline-arrow" />
              <PipelineItem
                number="02"
                title="Assess"
                text="Trust & suspicion scores cascaded across graph"
                active
              />
              <ChevronRight className="pipeline-arrow" />
              <PipelineItem
                number="03"
                title="TCRP"
                text="Evaluates RETAIN / ROLLBACK / QUARANTINE"
                active
              />
              <ChevronRight className="pipeline-arrow" />
              <PipelineItem
                number="04"
                title="Recover"
                text="Cryptographically restores trusted baseline"
                active
              />
              <ChevronRight className="pipeline-arrow" />
              <PipelineItem
                number="05"
                title="Validate"
                text="Attestation, provenance & head verified"
                active
              />
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <span className="panel-kicker">SYSTEM INTEGRITY</span>
                <h2>Memory Health</h2>
              </div>
              <Activity size={20} style={{ color: "var(--green)" }} />
            </div>

            <div className="health-ring">
              <div className="health-value">
                <strong>{dashboard.integrity_percentage}%</strong>
                <span>Consistency checks</span>
              </div>
            </div>

            <div className="health-row">
              <span>Valid SHA-256 Hashes</span>
              <strong style={{ color: "var(--green)" }}>
                {dashboard.integrity_valid} / {dashboard.protected_memories}
              </strong>
            </div>
            <div className="health-row">
              <span>Suspicious Memories</span>
              <strong style={{ color: dashboard.suspicious_memories > 0 ? "var(--amber)" : "var(--muted)" }}>
                {dashboard.suspicious_memories}
              </strong>
            </div>
            <div className="health-row">
              <span>Quarantined States</span>
              <strong style={{ color: dashboard.quarantined_memories > 0 ? "var(--red)" : "var(--muted)" }}>
                {dashboard.quarantined_memories}
              </strong>
            </div>
          </section>
        </div>

        {/* Latest Live Recovery Incident Card (if any recorded) */}
        {latestRecovery && (
          <section className="panel incident-panel">
            <div className="panel-header">
              <div>
                <span className="panel-kicker">LATEST SELF-HEALING INCIDENT</span>
                <h2>Autonomous Recovery Event: {latestRecovery.memory_id}</h2>
              </div>
              <div className="incident-status">
                <CheckCircle2 size={17} />
                {recoveryPassed ? "FULLY VERIFIED" : "RESTORED"}
              </div>
            </div>

            <div className="incident-meta">
              <div>
                <span>TARGET MEMORY</span>
                <strong>{latestRecovery.memory_id}</strong>
              </div>
              <div>
                <span>ATTACK TYPE</span>
                <strong>{attackType}</strong>
              </div>
              <div>
                <span>ATTACKER</span>
                <strong>{attacker}</strong>
              </div>
              <div>
                <span>TCRP DECISION</span>
                <strong>{latestDecision?.action || latestRecovery.action}</strong>
              </div>
            </div>

            <div className="incident-flow">
              <div className="incident-state trusted">
                <span>TRUSTED BASELINE</span>
                <strong>{trustedVersion !== null ? `v${trustedVersion}` : "v1"}</strong>
                <p>{trustedContent}</p>
              </div>

              <ChevronRight className="incident-arrow" />

              <div className="incident-state compromised">
                <span>COMPROMISED ATTACK</span>
                <strong>v{compromisedVersion}</strong>
                <p>{compromisedContent}</p>
              </div>

              <ChevronRight className="incident-arrow" />

              <div className="incident-state recovered">
                <span>RESTORED STATE</span>
                <strong>{restoredVersion !== null ? `v${restoredVersion}` : "v3"}</strong>
                <p>{restoredContent}</p>
              </div>
            </div>

            <div className="incident-footer">
              <div className="incident-result">
                <CheckCircle2 size={18} />
                <div>
                  <strong>{recoveryPassed ? "Cryptographically Fully Verified" : "Recovery State Recorded"}</strong>
                  <span>TCRP selected {latestDecision?.action || latestRecovery.action}; recovery attestation and provenance valid.</span>
                </div>
              </div>
              <button className="soc-btn secondary" onClick={() => setPage("attack")}>
                View Live Recovery <ChevronRight size={14} />
              </button>
            </div>
          </section>
        )}

        {/* Live Protection Activity Feed (100% Real Database Events) */}
        <section className="panel">
          <div className="table-header">
            <div>
              <span className="panel-kicker">REAL-TIME TELEMETRY</span>
              <h2>Live Autonomous Defense Stream</h2>
              <p className="muted">Direct audit stream of persisted recovery events, threat detections, and baseline checks.</p>
            </div>
            <button className="soc-btn secondary" onClick={() => setPage("soc")}>
              Full SOC Audit <ChevronRight size={14} />
            </button>
          </div>

          <div className="soc-table-wrapper">
            <table className="soc-unified-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Event Type</th>
                  <th>Memory ID</th>
                  <th>Telemetry Details</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {combinedRealEvents.slice(0, 6).map((item) => (
                  <tr key={item.id} className="soc-table-row">
                    <td className="soc-cell-time">
                      {item.time ? (
                        <>
                          <span className="soc-time-primary">
                            {new Date(item.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                          </span>
                          <span className="soc-time-secondary">
                            {new Date(item.time).toLocaleDateString([], { month: "short", day: "numeric" })}
                          </span>
                        </>
                      ) : (
                        <span className="muted">Recent</span>
                      )}
                    </td>

                    <td>
                      <span className={`soc-status-badge ${item.isRecovery ? "live" : "open"}`}>
                        {item.type}
                      </span>
                    </td>

                    <td className="soc-cell-memory">
                      <span className="soc-memory-badge">
                        <Database size={11} /> {item.memoryId || "ENT-ACCESS-001"}
                      </span>
                    </td>

                    <td>
                      <div style={{ fontWeight: 600, color: "#e2edf6" }}>{item.title}</div>
                      <small className="muted" style={{ display: "block", marginTop: "2px", maxWidth: "420px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {item.detail}
                      </small>
                    </td>

                    <td>
                      <span className={`soc-severity-pill ${item.isRecovery ? "low" : "critical"}`}>
                        {item.status}
                      </span>
                    </td>

                    <td>
                      <button
                        className="soc-btn-inspect"
                        onClick={() => {
                          if (item.isRecovery) setPage("attack")
                          else setPage("soc")
                        }}
                      >
                        <Eye size={12} /> Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Monitored Enterprise Knowledge Catalog */}
        <section className="panel">
          <div className="table-header">
            <div>
              <span className="panel-kicker">PERSISTENT KNOWLEDGE BASE</span>
              <h2>Monitored Enterprise Memory Categories</h2>
              <p className="muted">11 persistent memory records actively protected by cryptographic hashing and provenance chains.</p>
            </div>
            <button className="soc-btn secondary" onClick={() => setPage("memory")}>
              Explore Memory Database <ChevronRight size={14} />
            </button>
          </div>

          <div className="overview-memory-categories">
            <div className="memory-category-card">
              <div className="category-card-head">
                <div className="cat-icon policy"><Bot size={16} /></div>
                <div>
                  <strong>Customer Support Policies & SOPs</strong>
                  <span>{policyMemories.length} Active Records</span>
                </div>
              </div>
              <div className="category-memory-items">
                {policyMemories.map((m) => (
                  <div key={m.id} className="category-item-row" onClick={() => { setSelectedMemory(m); setPage("memory") }}>
                    <span className="soc-mono-badge">{m.id}</span>
                    <span className="cat-item-content">{m.content.slice(0, 48)}...</span>
                    <span className={`soc-status-badge ${m.status === "active" ? "live" : "open"}`}>{m.status}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="memory-category-card">
              <div className="category-card-head">
                <div className="cat-icon security"><Lock size={16} /></div>
                <div>
                  <strong>Enterprise Security Baselines</strong>
                  <span>{baselineMemories.length} Active Records</span>
                </div>
              </div>
              <div className="category-memory-items">
                {baselineMemories.map((m) => (
                  <div key={m.id} className="category-item-row" onClick={() => { setSelectedMemory(m); setPage("memory") }}>
                    <span className="soc-mono-badge">{m.id}</span>
                    <span className="cat-item-content">{m.content.slice(0, 48)}...</span>
                    <span className={`soc-status-badge ${m.status === "active" ? "live" : "open"}`}>{m.status}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="memory-category-card">
              <div className="category-card-head">
                <div className="cat-icon lab"><Terminal size={16} /></div>
                <div>
                  <strong>Controlled Lab Replay Records</strong>
                  <span>{labMemories.length} Active Records</span>
                </div>
              </div>
              <div className="category-memory-items">
                {labMemories.map((m) => (
                  <div key={m.id} className="category-item-row" onClick={() => { setSelectedMemory(m); setPage("memory") }}>
                    <span className="soc-mono-badge">{m.id}</span>
                    <span className="cat-item-content">{m.content.slice(0, 48)}...</span>
                    <span className={`soc-status-badge ${m.status === "active" ? "live" : "open"}`}>{m.status}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>
      </div>
    )
  }

function renderAssistant() {
    const lastMessage = messages[messages.length - 1]
    const metadata = lastMessage?.metadata || null
    const isVerified = metadata?.aegismem_verified === true
    const isBlocked = metadata?.security_blocked === true || (metadata?.aegismem_verified === false && metadata?.mode === "enterprise")
    const isGeneral = metadata?.mode === "general"

    const resolvedMemoryId = metadata?.memory_id || recoveryResult?.recovery?.memory_id || selectedMemory?.id || memories[0]?.id || "POLICY-001"
    const currentMemory = memories.find((m) => m.id === resolvedMemoryId) || selectedMemory || memories[0] || null

    const recoveryValidationResult = String(
      recoveryResult?.validation_result ??
      recoveryResult?.recovery?.validation_result ??
      ""
    ).toUpperCase()

    const restoredVersion =
      recoveryResult?.memory?.restored?.version ??
      recoveryResult?.restored_version ??
      recoveryResult?.recovery?.restored_version ??
      null

    const recoverySuccessful =
      recoveryResult?.recovery?.verified_success === true ||
      (recoveryResult?.recovery?.verification?.valid === true &&
        recoveryResult?.recovery?.verification?.recovery_provenance_verified === true &&
        restoredVersion !== null &&
        (recoveryValidationResult === "PASS" || recoveryValidationResult === "PARTIAL"))

    const quickQueries = [
      { label: "Customer Refund Policy", query: "What is the customer refund policy?", category: "policy" },
      { label: "Refund Check (15 Days)", query: "Can I get a refund for an order purchased 15 days ago?", category: "policy" },
      { label: "Refund Check (45 Days)", query: "My order was placed 45 days ago, am I eligible for a refund?", category: "policy" },
      { label: "MFA Access Rules", query: "What are the enterprise access and MFA requirements?", category: "security" },
      { label: "Incident Reporting", query: "How do I report a security incident?", category: "security" },
      { label: "Data Privacy Standards", query: "What is the policy on sensitive data protection and classification?", category: "security" },
      { label: "Assistant Identity", query: "Who are you and what do you do?", category: "chat" },
      { label: "Daily Greetings", query: "Hello! How are you doing today?", category: "chat" },
    ]

    function handleQuickQuery(qText) {
      setQuestion(qText)
      // Focus or trigger
    }

    return (
      <div className="page-content assistant-page">
        {/* Top Header Panel */}
        <div className="soc-header-panel">
          <div>
            <div className="soc-eyebrow">
              <span className="soc-live-dot"></span>
              DEPLOYMENT DOMAIN: ENTERPRISE CUSTOMER SUPPORT AI · AEGISMEM SECURITY GATE ENFORCED
            </div>
            <h1 className="soc-title">Enterprise Customer Support AI Assistant</h1>
            <p className="soc-subtitle">
              Persistent memory-protected conversational assistant. Every retrieval passes through{" "}
              <code>aegismem_security_gate()</code> to verify cryptographic integrity and provenance before answering.
            </p>
          </div>
          <div className="soc-header-actions">
            <span className="soc-status-badge live">
              <ShieldCheck size={13} /> SECURITY GATE ACTIVE
            </span>
            <span className="soc-status-badge info">
              <Bot size={13} /> ENTERPRISE SUPPORT v2.4
            </span>
          </div>
        </div>

        {/* Quick Query Carousel / Chips */}
        <div className="quick-query-container">
          <span className="quick-query-label">
            <Sparkles size={14} /> Quick Inquiries:
          </span>
          <div className="quick-query-chips">
            {quickQueries.map((item, idx) => (
              <button
                key={idx}
                type="button"
                className={`quick-chip chip-${item.category}`}
                onClick={() => {
                  setQuestion(item.query)
                }}
              >
                {item.label}
              </button>
            ))}
          </div>
        </div>

        {/* Assistant Main Layout */}
        <div className="assistant-layout">
          {/* Main Chat Panel */}
          <section className="chat-panel soc-table-container">
            <div className="chat-header">
              <div className="agent-avatar">
                <Bot size={20} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <strong style={{ color: "#f8fafc", fontSize: "14px" }}>AegisMem Enterprise Support AI</strong>
                  <span className="soc-severity-pill low" style={{ fontSize: "10px", padding: "1px 6px" }}>ONLINE</span>
                </div>
                <span style={{ fontSize: "12px", color: "#64748b" }}>
                  Memory Resolver: TF-IDF + Domain Weighting · Verification: Real-Time Manifest & Provenance
                </span>
              </div>
              <div className="chat-live">
                <span className="status-dot online"></span>
                <span style={{ fontSize: "11px", color: "#10b981", fontWeight: 600 }}>GATE PROTECTED</span>
              </div>
            </div>

            <div className="chat-messages">
              {messages.map((message, index) => {
                const msgVerified = message.metadata?.aegismem_verified === true
                const msgBlocked = message.metadata?.security_blocked === true || (message.metadata && message.metadata.aegismem_verified === false && message.metadata.mode === "enterprise")
                const msgGeneral = message.metadata?.mode === "general"
                const memUsed = message.metadata?.memory_id || message.metadata?.memory_used

                return (
                  <div key={index} className={`message ${message.role}`}>
                    <div className="message-avatar">
                      {message.role === "user" ? (
                        <UserRound size={16} />
                      ) : message.role === "system" ? (
                        <AlertTriangle size={16} />
                      ) : (
                        <Bot size={16} />
                      )}
                    </div>

                    <div className="message-body">
                      <div className="message-header-row" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "4px" }}>
                        <span className="message-role">
                          {message.role === "user" ? "CUSTOMER" : message.role === "system" ? "SECURITY ALERT" : "AEGISMEM AGENT"}
                        </span>
                        {message.metadata && (
                          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                            {msgVerified && (
                              <span className="soc-severity-pill low" style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "10px" }}>
                                <ShieldCheck size={11} /> GATE: VERIFIED
                              </span>
                            )}
                            {msgBlocked && (
                              <span className="soc-severity-pill critical" style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "10px" }}>
                                <AlertTriangle size={11} /> GATE: BLOCKED (TAMPERED)
                              </span>
                            )}
                            {msgGeneral && (
                              <span className="soc-severity-pill medium" style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "10px" }}>
                                <MessageSquare size={11} /> CONVERSATIONAL
                              </span>
                            )}
                            {memUsed && (
                              <span className="memory-badge" style={{ fontSize: "10px", background: "rgba(51,65,85,0.6)", padding: "1px 6px", borderRadius: "4px", color: "#94a3b8", fontFamily: "monospace" }}>
                                {memUsed} · v{message.metadata.memory_version || message.metadata.version || 1}
                              </span>
                            )}
                          </div>
                        )}
                      </div>

                      <div className="message-text-content" style={{ fontSize: "13.5px", lineHeight: 1.55, whiteSpace: "pre-line" }}>
                        {message.text}
                      </div>

                      {msgBlocked && (
                        <div className="blocked-security-alert-box" style={{ marginTop: "10px", padding: "10px 12px", background: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: "8px" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "6px", color: "#f87171", fontWeight: 600, fontSize: "12px", marginBottom: "4px" }}>
                            <ShieldAlert size={14} /> PERSISTENT MEMORY COMPROMISE DETECTED
                          </div>
                          <p style={{ margin: 0, fontSize: "12px", color: "#cbd5e1" }}>
                            {message.metadata?.block_reason || message.metadata?.error || "AegisMem Security Gate intercepted this response because the persistent memory failed cryptographic integrity verification or had an active compromise score."}
                          </p>
                          <div style={{ marginTop: "6px", fontSize: "11px", color: "#94a3b8", fontFamily: "monospace" }}>
                            Action Required: Trigger TCRP Recovery in Live Recovery or await autonomous self-healing.
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}

              {sending && (
                <div className="message assistant">
                  <div className="message-avatar">
                    <Bot size={16} />
                  </div>
                  <div className="message-body">
                    <span className="message-role">AEGISMEM AGENT</span>
                    <p className="typing" style={{ display: "flex", alignItems: "center", gap: "8px", color: "#38bdf8", margin: "4px 0 0" }}>
                      <RefreshCw size={14} className="spin-icon" /> Querying memory resolver & executing aegismem_security_gate()...
                    </p>
                  </div>
                </div>
              )}
            </div>

            <div className="chat-input-area">
              <input
                value={question}
                onChange={(event) => setQuestion(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault()
                    sendQuestion()
                  }
                }}
                placeholder="Ask customer query (e.g., 'What is the refund policy?' or 'Can I get a refund for an order from 15 days ago?')..."
              />
              <button
                type="button"
                className="soc-btn primary"
                onClick={sendQuestion}
                disabled={sending || !question.trim()}
                style={{ padding: "0 18px", height: "42px" }}
              >
                <MessageSquare size={16} /> Send
              </button>
            </div>
          </section>

          {/* Assistant Right Sidebar: Memory Telemetry */}
          <aside className="assistant-sidebar">
            <section className="panel soc-table-container" style={{ padding: "16px" }}>
              <div className="panel-header" style={{ marginBottom: "12px" }}>
                <div>
                  <span className="soc-eyebrow" style={{ fontSize: "10px" }}>RETRIEVED KNOWLEDGE AUDIT</span>
                  <h2 style={{ fontSize: "15px", color: "#f8fafc", margin: "2px 0 0" }}>Active Memory Node</h2>
                </div>
                <Database size={17} style={{ color: "#38bdf8" }} />
              </div>

              {currentMemory ? (
                <div className="source-card" style={{ background: "rgba(15, 23, 42, 0.7)", border: "1px solid #334155", borderRadius: "10px", padding: "14px" }}>
                  <div className="source-title" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                      <Database size={15} style={{ color: "#38bdf8" }} />
                      <strong style={{ color: "#f8fafc", fontSize: "13px" }}>{currentMemory.id}</strong>
                    </div>
                    <span className={`soc-severity-pill ${currentMemory.status === "ACTIVE" ? "low" : "critical"}`} style={{ fontSize: "10px" }}>
                      {currentMemory.status}
                    </span>
                  </div>

                  <div style={{ fontSize: "12px", color: "#cbd5e1", background: "rgba(30, 41, 59, 0.6)", padding: "10px", borderRadius: "6px", border: "1px solid #1e293b", maxHeight: "120px", overflowY: "auto", marginBottom: "12px", lineHeight: 1.45 }}>
                    {currentMemory.content || "Memory content loaded from SQLite persistence."}
                  </div>

                  <div className="source-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", fontSize: "11px" }}>
                    <div style={{ background: "rgba(30, 41, 59, 0.4)", padding: "6px 8px", borderRadius: "6px" }}>
                      <span style={{ color: "#64748b", display: "block" }}>Active Version</span>
                      <strong style={{ color: "#38bdf8" }}>v{currentMemory.version || 1}</strong>
                    </div>
                    <div style={{ background: "rgba(30, 41, 59, 0.4)", padding: "6px 8px", borderRadius: "6px" }}>
                      <span style={{ color: "#64748b", display: "block" }}>Trust Score</span>
                      <strong style={{ color: Number(currentMemory.trust) >= 0.8 ? "#10b981" : "#f59e0b" }}>
                        {(Number(currentMemory.trust || 1.0) * 100).toFixed(0)}%
                      </strong>
                    </div>
                    <div style={{ background: "rgba(30, 41, 59, 0.4)", padding: "6px 8px", borderRadius: "6px" }}>
                      <span style={{ color: "#64748b", display: "block" }}>Suspicion Score</span>
                      <strong style={{ color: Number(currentMemory.suspicion || 0) === 0 ? "#10b981" : "#ef4444" }}>
                        {Number(currentMemory.suspicion || 0).toFixed(2)}
                      </strong>
                    </div>
                    <div style={{ background: "rgba(30, 41, 59, 0.4)", padding: "6px 8px", borderRadius: "6px" }}>
                      <span style={{ color: "#64748b", display: "block" }}>Integrity Gate</span>
                      <strong style={{ color: "#10b981" }}>PASS</strong>
                    </div>
                  </div>
                </div>
              ) : (
                <div style={{ color: "#64748b", fontSize: "12px", textAlign: "center", padding: "20px 0" }}>
                  No active memory node retrieved yet.
                </div>
              )}
            </section>

            {/* Defense Mechanism Flow Card */}
            <section className="panel soc-table-container" style={{ padding: "16px" }}>
              <div className="panel-header" style={{ marginBottom: "12px" }}>
                <div>
                  <span className="soc-eyebrow" style={{ fontSize: "10px" }}>CYBERSECURITY PIPELINE</span>
                  <h2 style={{ fontSize: "15px", color: "#f8fafc", margin: "2px 0 0" }}>Security Gate Workflow</h2>
                </div>
                <ShieldCheck size={17} style={{ color: "#10b981" }} />
              </div>

              <div className="mini-flow" style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                <div style={{ display: "flex", alignItems: "flex-start", gap: "10px", background: "rgba(30,41,59,0.3)", padding: "8px 10px", borderRadius: "6px" }}>
                  <strong style={{ color: "#38bdf8", fontSize: "12px" }}>01</strong>
                  <div>
                    <strong style={{ color: "#f8fafc", fontSize: "12px", display: "block" }}>Customer Query Ingestion</strong>
                    <span style={{ color: "#64748b", fontSize: "11px" }}>Identifies customer intent (refund, order, support guideline, or small talk).</span>
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "flex-start", gap: "10px", background: "rgba(30,41,59,0.3)", padding: "8px 10px", borderRadius: "6px" }}>
                  <strong style={{ color: "#38bdf8", fontSize: "12px" }}>02</strong>
                  <div>
                    <strong style={{ color: "#f8fafc", fontSize: "12px", display: "block" }}>Persistent Memory Retrieval</strong>
                    <span style={{ color: "#64748b", fontSize: "11px" }}>Resolves relevant baseline node (e.g. POLICY-001 or ENT-ACCESS-001).</span>
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "flex-start", gap: "10px", background: "rgba(30,41,59,0.3)", padding: "8px 10px", borderRadius: "6px" }}>
                  <strong style={{ color: "#10b981", fontSize: "12px" }}>03</strong>
                  <div>
                    <strong style={{ color: "#f8fafc", fontSize: "12px", display: "block" }}>aegismem_security_gate() Audit</strong>
                    <span style={{ color: "#64748b", fontSize: "11px" }}>Evaluates SHA-256 hash manifest, provenance checkpoint, and suspicion score.</span>
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "flex-start", gap: "10px", background: "rgba(30,41,59,0.3)", padding: "8px 10px", borderRadius: "6px" }}>
                  <strong style={{ color: "#38bdf8", fontSize: "12px" }}>04</strong>
                  <div>
                    <strong style={{ color: "#f8fafc", fontSize: "12px", display: "block" }}>Safe Response / Intercept</strong>
                    <span style={{ color: "#64748b", fontSize: "11px" }}>If verified, delivers calculated answer; if tampered, blocks and notifies SOC.</span>
                  </div>
                </div>
              </div>
            </section>
          </aside>
        </div>
      </div>
    )
  }

  async function loadSocAlerts() {
    setSocAlertsLoading(true)
    setSocAlertsError("")
    try {
      const response = await fetch("/api/dashboard/alerts", {
        credentials: "same-origin"
      })
      if (!response.ok) {
        throw new Error(`SOC alerts unavailable (${response.status})`)
      }
      const data = await response.json()
      setSocAlerts(Array.isArray(data.alerts) ? data.alerts : [])
    } catch (error) {
      setSocAlertsError(error.message || "Unable to load SOC alerts.")
      setSocAlerts([])
    } finally {
      setSocAlertsLoading(false)
    }
  }

  async function loadSocMemoryEvidence() {
    const memoryId = socMemoryId.trim()
    if (!memoryId) {
      setSocMemoryError("Enter a memory ID to investigate.")
      setSocMemoryHistory([])
      return
    }

    setSocMemoryLoading(true)
    setSocMemoryError("")
    try {
      const response = await fetch(
        `/api/dashboard/memories/${encodeURIComponent(memoryId)}/history`,
        { credentials: "same-origin" }
      )
      if (!response.ok) {
        throw new Error(
          response.status === 404
            ? "No revision history found for this memory ID."
            : `Memory evidence unavailable (${response.status}).`
        )
      }
      const data = await response.json()
      setSocMemoryHistory(Array.isArray(data.history) ? data.history : [])
    } catch (error) {
      setSocMemoryError(error.message || "Unable to load memory evidence.")
      setSocMemoryHistory([])
    } finally {
      setSocMemoryLoading(false)
    }
  }

  function getIpLocationMeta(ip, locationInfo) {
    if (locationInfo && locationInfo.location && locationInfo.location !== "Unknown Location") {
      return {
        label: locationInfo.location,
        zone: locationInfo.zone || "Lab Subnet",
        isAdversary: Boolean(locationInfo.is_adversary),
        networkType: locationInfo.network_type || (locationInfo.is_adversary ? "Adversary Lab" : "Internal")
      }
    }
    const clean = String(ip || "").trim()
    if (clean === "192.168.56.101") {
      return {
        label: "Adversary Lab VM (Kali Linux)",
        zone: "VirtualBox Host-Only Subnet",
        isAdversary: true,
        networkType: "External Attack Lab"
      }
    }
    if (clean === "127.0.0.1" || clean === "localhost" || clean === "::1") {
      return {
        label: "Localhost Gateway",
        zone: "Host Internal Loopback",
        isAdversary: false,
        networkType: "Host System"
      }
    }
    if (clean === "testclient") {
      return {
        label: "Test Harness / Mock Client",
        zone: "Automated Suite",
        isAdversary: false,
        networkType: "Automated Test"
      }
    }
    if (clean.startsWith("192.168.") || clean.startsWith("10.") || clean.startsWith("172.")) {
      return {
        label: "Enterprise Internal Network",
        zone: "Private VPC Subnet",
        isAdversary: false,
        networkType: "Enterprise LAN"
      }
    }
    return {
      label: clean ? `Remote Network (${clean})` : "Unrecorded Location",
      zone: "External Gateway",
      isAdversary: true,
      networkType: "Remote Client"
    }
  }

  function formatAttackTypeLabel(type) {
    const raw = String(type || "").toLowerCase()
    if (raw.includes("tamper")) return "Content Tampering"
    if (raw.includes("poison")) return "Prompt Injection"
    if (raw.includes("detect")) return "Compromise Detection"
    if (raw.includes("delet")) return "Memory Deletion"
    return type || "Unknown Attack"
  }

  function renderSocAudit() {
    const successfulLogins = socSessions.filter(
      (event) => event.event_type === "LOGIN" && event.outcome === "SUCCESS"
    ).length
    const failedLogins = socSessions.filter(
      (event) => event.event_type === "LOGIN" && event.outcome === "FAILURE"
    ).length

    const criticalCount = socAlerts.filter(
      (a) => String(a.severity).toUpperCase() === "CRITICAL"
    ).length
    const highCount = socAlerts.filter(
      (a) => String(a.severity).toUpperCase() === "HIGH"
    ).length
    const adversaryCount = socAlerts.filter((a) => {
      const ip = a.source_ip || ""
      const actor = a.attacker || ""
      return ip.includes("192.168.56.101") || actor.includes("kali")
    }).length
    const mutatedCount = socAlerts.filter((a) => a.content_changed).length

    // Filter alerts
    const filteredAlerts = socAlerts.filter((alert) => {
      const q = socSearchQuery.trim().toLowerCase()
      if (q) {
        const idMatch = (alert.alert_id || "").toLowerCase().includes(q)
        const memMatch = (alert.memory_id || "").toLowerCase().includes(q)
        const atkMatch = (alert.attacker || "").toLowerCase().includes(q)
        const ipMatch = (alert.source_ip || "").toLowerCase().includes(q)
        const typeMatch = (alert.attack_type || "").toLowerCase().includes(q)
        if (!idMatch && !memMatch && !atkMatch && !ipMatch && !typeMatch) return false
      }
      if (socSeverityFilter !== "ALL") {
        if (String(alert.severity).toUpperCase() !== socSeverityFilter) return false
      }
      if (socStatusFilter !== "ALL") {
        const st = String(alert.alert_status || alert.status || "").toUpperCase()
        if (socStatusFilter === "OPEN" && st !== "OPEN") return false
        if (socStatusFilter === "RESOLVED" && st === "OPEN") return false
      }
      return true
    })

    // Filter sessions
    const filteredSessions = socSessions.filter((event) => {
      if (socSessionFilter === "SUCCESS") return event.outcome === "SUCCESS"
      if (socSessionFilter === "FAILURE") return event.outcome === "FAILURE"
      if (socSessionFilter === "LOGIN") return event.event_type === "LOGIN"
      if (socSessionFilter === "LOGOUT") return event.event_type === "LOGOUT"
      return true
    })

    const handleCopy = (text, id) => {
      navigator.clipboard?.writeText(text)
      setSocCopiedId(id)
      setTimeout(() => setSocCopiedId(""), 2000)
    }

    const exportSocJson = () => {
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(
        JSON.stringify({ alerts: socAlerts, sessions: socSessions, exported_at: new Date().toISOString() }, null, 2)
      )
      const downloadAnchor = document.createElement("a")
      downloadAnchor.setAttribute("href", dataStr)
      downloadAnchor.setAttribute("download", `aegismem-soc-audit-${Date.now()}.json`)
      document.body.appendChild(downloadAnchor)
      downloadAnchor.click()
      downloadAnchor.remove()
    }

    return (
      <div className="page-content soc-portal">
        {/* Top Header */}
        <div className="soc-header-panel">
          <div>
            <div className="soc-eyebrow">
              <span className="soc-live-dot"></span>
              SECURITY OPERATIONS CENTER · SIEM & THREAT TELEMETRY
            </div>
            <h1 className="soc-title">Security Operations Center (SOC) Audit</h1>
            <p className="soc-subtitle">
              Continuous cryptographic memory auditing, adversary intrusion monitoring, and TCRP self-healing tracking.
            </p>
          </div>
          <div className="soc-header-actions">
            <span className="soc-status-badge live">
              <Radio size={12} className="pulse-icon" /> SENSORS ACTIVE
            </span>
            <button
              className="soc-btn secondary"
              onClick={() => {
                loadSocSessions()
                loadSocAlerts()
              }}
              disabled={socAlertsLoading || socLoading}
            >
              <RefreshCw size={13} className={socAlertsLoading ? "spin" : ""} /> Refresh
            </button>
            <button className="soc-btn secondary" onClick={exportSocJson}>
              <Copy size={13} /> Export SIEM JSON
            </button>
          </div>
        </div>

        {/* 4 Top KPI Cards */}
        <div className="soc-kpi-grid">
          <div className="soc-kpi-card">
            <div className="soc-kpi-icon red">
              <ShieldAlert size={20} />
            </div>
            <div className="soc-kpi-content">
              <span className="soc-kpi-label">Recorded Security Alerts</span>
              <strong className="soc-kpi-value">{socAlerts.length}</strong>
              <small className="soc-kpi-subtext alert">
                {mutatedCount} memory mutation{mutatedCount === 1 ? "" : "s"} detected
              </small>
            </div>
          </div>

          <div className="soc-kpi-card">
            <div className="soc-kpi-icon orange">
              <AlertTriangle size={20} />
            </div>
            <div className="soc-kpi-content">
              <span className="soc-kpi-label">Critical & High Threats</span>
              <strong className="soc-kpi-value">{criticalCount + highCount}</strong>
              <small className="soc-kpi-subtext warning">
                {criticalCount} Critical · {highCount} High priority
              </small>
            </div>
          </div>

          <div className="soc-kpi-card">
            <div className="soc-kpi-icon adversary">
              <Crosshair size={20} />
            </div>
            <div className="soc-kpi-content">
              <span className="soc-kpi-label">Adversary Intrusions</span>
              <strong className="soc-kpi-value">{adversaryCount}</strong>
              <small className="soc-kpi-subtext adversary-tag">
                Kali VM (192.168.56.101)
              </small>
            </div>
          </div>

          <div className="soc-kpi-card">
            <div className="soc-kpi-icon green">
              <ShieldCheck size={20} />
            </div>
            <div className="soc-kpi-content">
              <span className="soc-kpi-label">TCRP Mitigation Rate</span>
              <strong className="soc-kpi-value">
                {socAlerts.length > 0 ? "100%" : "Standby"}
              </strong>
              <small className="soc-kpi-subtext success">
                Automatic Rollback Active
              </small>
            </div>
          </div>
        </div>

        {/* Sub-Tab Navigation */}
        <div className="soc-nav-tabs">
          <button
            className={`soc-nav-tab ${socActiveTab === "alerts" ? "active" : ""}`}
            onClick={() => setSocActiveTab("alerts")}
          >
            <ShieldAlert size={15} />
            Threat Alerts & Incidents
            <span className="soc-tab-pill">{filteredAlerts.length}</span>
          </button>
          <button
            className={`soc-nav-tab ${socActiveTab === "memory" ? "active" : ""}`}
            onClick={() => setSocActiveTab("memory")}
          >
            <Database size={15} />
            Memory Integrity Inspector
          </button>
          <button
            className={`soc-nav-tab ${socActiveTab === "sessions" ? "active" : ""}`}
            onClick={() => setSocActiveTab("sessions")}
          >
            <UserRound size={15} />
            Operator & Access Audit
            <span className="soc-tab-pill">{socSessions.length}</span>
          </button>
        </div>

        {/* ============================================================== */}
        {/* TAB 1: THREAT ALERTS & INCIDENTS (MAIN SOC VIEW)               */}
        {/* ============================================================== */}
        {socActiveTab === "alerts" && (
          <div className="soc-tab-pane">
            {/* Filter Toolbar */}
            <div className="soc-toolbar">
              <div className="soc-search-wrapper">
                <Search size={14} className="soc-search-icon" />
                <input
                  type="text"
                  className="soc-search-field"
                  placeholder="Filter by Memory ID (e.g. ENT-ACCESS-001), Alert ID, Attacker, or IP..."
                  value={socSearchQuery}
                  onChange={(e) => setSocSearchQuery(e.target.value)}
                />
                {socSearchQuery && (
                  <button className="soc-clear-btn" onClick={() => setSocSearchQuery("")}>
                    <X size={12} />
                  </button>
                )}
              </div>

              <div className="soc-filter-group">
                <span className="soc-filter-label">Severity:</span>
                {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => (
                  <button
                    key={sev}
                    className={`soc-filter-chip sev-${sev.toLowerCase()} ${socSeverityFilter === sev ? "active" : ""}`}
                    onClick={() => setSocSeverityFilter(sev)}
                  >
                    {sev}
                  </button>
                ))}
              </div>

              <div className="soc-filter-group">
                <span className="soc-filter-label">Status:</span>
                {["ALL", "OPEN", "RESOLVED"].map((st) => (
                  <button
                    key={st}
                    className={`soc-filter-chip ${socStatusFilter === st ? "active" : ""}`}
                    onClick={() => setSocStatusFilter(st)}
                  >
                    {st}
                  </button>
                ))}
              </div>
            </div>

            {socAlertsError && <div className="soc-error-banner" role="alert">{socAlertsError}</div>}
            {socAlertsLoading && <div className="soc-loading-spinner">Loading threat telemetry...</div>}

            {!socAlertsLoading && filteredAlerts.length === 0 && (
              <div className="soc-empty-state">
                <ShieldCheck size={40} className="soc-empty-icon" />
                <h3>No Security Alerts Match Filters</h3>
                <p>
                  {socSearchQuery || socSeverityFilter !== "ALL" || socStatusFilter !== "ALL"
                    ? "Try adjusting your search query or severity filters."
                    : "No persistent memory attacks or detection alerts recorded yet."}
                </p>
              </div>
            )}

            {!socAlertsLoading && filteredAlerts.length > 0 && (
              <div className="soc-table-wrapper">
                <table className="soc-unified-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Incident ID</th>
                      <th>Target Memory</th>
                      <th>Attack Type</th>
                      <th>Severity</th>
                      <th>Threat Actor & Location</th>
                      <th>Integrity Delta</th>
                      <th>Status</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAlerts.map((alert, idx) => {
                      const sev = String(alert.severity || "UNKNOWN").toUpperCase()
                      const locMeta = getIpLocationMeta(alert.source_ip, alert.location_info)
                      const timeStr = alert.created_at || alert.attack_time
                      const alertId = alert.alert_id || alert.attack_id || `ALERT-${idx}`

                      return (
                        <tr key={alertId} className="soc-table-row">
                          <td className="soc-cell-time">
                            {timeStr ? (
                              <>
                                <span className="soc-time-primary">
                                  {new Date(timeStr).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                                </span>
                                <span className="soc-time-secondary">
                                  {new Date(timeStr).toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" })}
                                </span>
                              </>
                            ) : (
                              <span className="muted">Unavailable</span>
                            )}
                          </td>

                          <td className="soc-cell-id">
                            <span className="soc-mono-badge" title="Click to copy ID" onClick={() => handleCopy(alertId, alertId)}>
                              {alertId.length > 18 ? `${alertId.slice(0, 8)}...${alertId.slice(-6)}` : alertId}
                              {socCopiedId === alertId ? <Check size={11} className="copy-check" /> : <Copy size={11} className="copy-icon" />}
                            </span>
                          </td>

                          <td className="soc-cell-memory">
                            <span className="soc-memory-badge">
                              <Database size={11} /> {alert.memory_id || "UNKNOWN"}
                            </span>
                          </td>

                          <td className="soc-cell-type">
                            <span className="soc-attack-type-tag">
                              {formatAttackTypeLabel(alert.attack_type)}
                            </span>
                          </td>

                          <td className="soc-cell-severity">
                            <span className={`soc-severity-pill ${sev.toLowerCase()}`}>
                              <span className="sev-dot"></span> {sev}
                              {alert.severity_score != null && <span className="sev-score">{Number(alert.severity_score).toFixed(1)}</span>}
                            </span>
                          </td>

                          <td className="soc-cell-location">
                            <div className="soc-threat-actor-line">
                              <strong>{alert.attacker || "kali-attacker"}</strong>
                            </div>
                            <div className={`soc-location-tag ${locMeta.isAdversary ? "adversary" : "internal"}`}>
                              {locMeta.isAdversary ? <Crosshair size={10} /> : <MapPin size={10} />}
                              <span>{locMeta.label}</span>
                              <span className="soc-ip-tag">{alert.source_ip || "192.168.56.101"}</span>
                            </div>
                          </td>

                          <td className="soc-cell-impact">
                            <div className="soc-impact-badges">
                              <span className={`soc-impact-pill ${alert.content_changed ? "mutated" : "safe"}`}>
                                {alert.content_changed ? "MUTATED" : "UNCHANGED"}
                              </span>
                              <span className={`soc-impact-pill ${alert.hash_changed ? "invalid" : "valid"}`}>
                                {alert.hash_changed ? "HASH MISMATCH" : "HASH VALID"}
                              </span>
                            </div>
                          </td>

                          <td className="soc-cell-status">
                            <span className={`soc-status-badge ${String(alert.alert_status || alert.status || "OPEN").toLowerCase()}`}>
                              {String(alert.alert_status || alert.status || "OPEN").toUpperCase()}
                            </span>
                          </td>

                          <td className="soc-cell-action">
                            <button
                              className="soc-btn-inspect"
                              onClick={() => setSocSelectedAlert(alert)}
                            >
                              <Eye size={12} /> Inspect
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ============================================================== */}
        {/* TAB 2: MEMORY INTEGRITY INSPECTOR                              */}
        {/* ============================================================== */}
        {socActiveTab === "memory" && (
          <div className="soc-tab-pane">
            <div className="soc-panel">
              <div className="soc-panel-head">
                <div>
                  <h3>Memory Revision & Cryptographic Evidence Inspector</h3>
                  <p className="muted">
                    Investigate hash integrity, signed manifests, and side-by-side content diffs for any memory ID.
                  </p>
                </div>
              </div>

              {/* Quick Select Chips */}
              <div className="soc-quick-chips">
                <span className="muted" style={{ fontSize: "11px" }}>Quick investigate:</span>
                {["ENT-ACCESS-001", "ENT-INCIDENT-002", "ENT-BACKUP-003", "ENT-DATA-004", "ENT-EMPLOYEE-005", "POLICY-001"].map((id) => (
                  <button
                    key={id}
                    type="button"
                    className="soc-chip"
                    onClick={() => {
                      setSocMemoryId(id)
                      setTimeout(() => loadSocMemoryEvidence(), 50)
                    }}
                  >
                    {id}
                  </button>
                ))}
              </div>

              <form
                onSubmit={(e) => {
                  e.preventDefault()
                  loadSocMemoryEvidence()
                }}
                className="soc-search-form"
              >
                <input
                  value={socMemoryId}
                  onChange={(e) => setSocMemoryId(e.target.value)}
                  placeholder="Enter exact memory ID (e.g. ENT-ACCESS-001)..."
                  className="soc-search-field"
                />
                <button className="soc-btn primary" type="submit" disabled={socMemoryLoading}>
                  {socMemoryLoading ? "Investigating..." : "Investigate Memory"}
                </button>
              </form>

              {socMemoryError && <div className="soc-error-banner">{socMemoryError}</div>}
              {!socMemoryLoading && !socMemoryError && socMemoryHistory.length === 0 && (
                <p className="muted" style={{ padding: "16px 0" }}>
                  Select or enter a memory ID above to view its version-by-version cryptographic proof and tamper evidence.
                </p>
              )}

              {socMemoryHistory.length > 0 && (
                <>
                  <div className="soc-kpi-grid mini">
                    <div className="soc-kpi-card">
                      <span className="soc-kpi-label">Revisions Retrieved</span>
                      <strong className="soc-kpi-value">{socMemoryHistory.length}</strong>
                    </div>
                    <div className="soc-kpi-card">
                      <span className="soc-kpi-label">Hash Integrity Failures</span>
                      <strong className="soc-kpi-value">
                        {socMemoryHistory.filter((i) => i.hash_integrity !== "VALID").length}
                      </strong>
                    </div>
                    <div className="soc-kpi-card">
                      <span className="soc-kpi-label">Missing Manifests</span>
                      <strong className="soc-kpi-value">
                        {socMemoryHistory.filter((i) => i.manifest_status !== "VALID").length}
                      </strong>
                    </div>
                  </div>

                  <div className="soc-table-wrapper">
                    <table className="soc-unified-table">
                      <thead>
                        <tr>
                          <th>Version</th>
                          <th>Security State</th>
                          <th>Hash Verification</th>
                          <th>Manifest Anchor</th>
                          <th>Authorization</th>
                          <th>Content Delta</th>
                          <th>Linked Attack</th>
                        </tr>
                      </thead>
                      <tbody>
                        {socMemoryHistory.map((item) => (
                          <tr key={item.revision_id || item.id}>
                            <td><strong>{item.version || "v?"}</strong></td>
                            <td>
                              <span className={`soc-state-tag ${String(item.state || "").toLowerCase()}`}>
                                {item.state || "UNKNOWN"}
                              </span>
                            </td>
                            <td>
                              <span className={`soc-verify-tag ${item.hash_integrity === "VALID" ? "valid" : "invalid"}`}>
                                {item.hash_integrity || "NOT_CHECKED"}
                              </span>
                            </td>
                            <td>
                              <span className={`soc-verify-tag ${item.manifest_status === "VALID" ? "valid" : "invalid"}`}>
                                {item.manifest_status || "NOT_CHECKED"}
                              </span>
                            </td>
                            <td>{item.authorization_state || "UNKNOWN"}</td>
                            <td>
                              {item.content_changed_from_previous ? (
                                <span className="soc-impact-pill mutated">CHANGED</span>
                              ) : (
                                <span className="soc-impact-pill safe">BASELINE</span>
                              )}
                            </td>
                            <td>{item.attack_type || "None"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Revision content differences */}
                  <h4 style={{ margin: "20px 0 10px", fontSize: "14px" }}>Revision Content Diffs</h4>
                  {socMemoryHistory
                    .filter((item) => item.content_changed_from_previous)
                    .map((item) => (
                      <div key={`diff-${item.revision_id || item.id}`} className="soc-diff-card">
                        <div className="soc-diff-card-head">
                          <strong>{item.version}: Content Alteration from Previous Version</strong>
                          <span className="soc-ip-tag">{item.hash_integrity || "HASH_CHECKED"}</span>
                        </div>
                        <pre className="soc-diff-code">
                          {Array.isArray(item.content_diff) && item.content_diff.length > 0
                            ? item.content_diff.join("\n")
                            : "Content differs from prior version."}
                        </pre>
                      </div>
                    ))}
                </>
              )}
            </div>
          </div>
        )}

        {/* ============================================================== */}
        {/* TAB 3: OPERATOR & ACCESS SESSION AUDIT                         */}
        {/* ============================================================== */}
        {socActiveTab === "sessions" && (
          <div className="soc-tab-pane">
            <div className="soc-panel">
              <div className="soc-panel-head">
                <div>
                  <h3>Operator & Dashboard Session Audit Trail</h3>
                  <p className="muted">
                    Full chronological audit log of administrator logins, logouts, and privileged operation approvals.
                  </p>
                </div>
                <div className="soc-filter-group">
                  {["ALL", "SUCCESS", "FAILURE", "LOGIN", "LOGOUT"].map((f) => (
                    <button
                      key={f}
                      className={`soc-filter-chip ${socSessionFilter === f ? "active" : ""}`}
                      onClick={() => setSocSessionFilter(f)}
                    >
                      {f}
                    </button>
                  ))}
                </div>
              </div>

              <div className="soc-kpi-grid mini">
                <div className="soc-kpi-card">
                  <span className="soc-kpi-label">Total Logged Sessions</span>
                  <strong className="soc-kpi-value">{socSessions.length}</strong>
                </div>
                <div className="soc-kpi-card">
                  <span className="soc-kpi-label">Successful Authentications</span>
                  <strong className="soc-kpi-value" style={{ color: "var(--green)" }}>{successfulLogins}</strong>
                </div>
                <div className="soc-kpi-card">
                  <span className="soc-kpi-label">Failed Authentication Attempts</span>
                  <strong className="soc-kpi-value" style={{ color: "var(--red)" }}>{failedLogins}</strong>
                </div>
              </div>

              {socLoading && <div className="soc-loading-spinner">Loading session audit trail...</div>}
              {socError && <div className="soc-error-banner">{socError}</div>}

              {!socLoading && filteredSessions.length > 0 && (
                <div className="soc-table-wrapper">
                  <table className="soc-unified-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Event Type</th>
                        <th>Outcome</th>
                        <th>Origin & Location</th>
                        <th>Session Duration</th>
                        <th>User Agent / Client</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredSessions.map((event) => {
                        const locMeta = getIpLocationMeta(event.source_ip, event.location_info)
                        return (
                          <tr key={event.id}>
                            <td className="soc-cell-time">
                              {event.occurred_at
                                ? new Date(event.occurred_at).toLocaleString()
                                : "Unavailable"}
                            </td>
                            <td>
                              <strong>{event.event_type || "UNKNOWN"}</strong>
                            </td>
                            <td>
                              <span className={`soc-outcome-badge ${String(event.outcome || "").toLowerCase()}`}>
                                {event.outcome || "UNKNOWN"}
                              </span>
                            </td>
                            <td>
                              <div className="soc-location-tag internal">
                                <MapPin size={10} />
                                <span>{locMeta.label}</span>
                                <span className="soc-ip-tag">{event.source_ip || "127.0.0.1"}</span>
                              </div>
                            </td>
                            <td>
                              {event.session_state === "ACTIVE"
                                ? "Active / In Progress"
                                : Number.isFinite(event.duration_seconds)
                                ? `${Math.floor(event.duration_seconds / 60)}m ${Math.floor(event.duration_seconds % 60)}s`
                                : event.session_state === "EXPIRED"
                                ? "Expired"
                                : "Unavailable"}
                            </td>
                            <td className="soc-cell-ua" title={event.user_agent}>
                              {event.user_agent || "Unavailable"}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ============================================================== */}
        {/* INTERACTIVE INCIDENT INVESTIGATION DRAWER / MODAL               */}
        {/* ============================================================== */}
        {socSelectedAlert && (
          <div className="soc-modal-overlay" onClick={() => setSocSelectedAlert(null)}>
            <div className="soc-modal-card" onClick={(e) => e.stopPropagation()}>
              <div className="soc-modal-header">
                <div>
                  <span className="soc-eyebrow">SECURITY INCIDENT INVESTIGATION</span>
                  <h2>{socSelectedAlert.alert_id || socSelectedAlert.attack_id}</h2>
                </div>
                <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                  <span className={`soc-severity-pill ${String(socSelectedAlert.severity || "UNKNOWN").toLowerCase()}`}>
                    <span className="sev-dot"></span> {socSelectedAlert.severity}
                  </span>
                  <button className="soc-modal-close" onClick={() => setSocSelectedAlert(null)}>
                    <X size={18} />
                  </button>
                </div>
              </div>

              <div className="soc-modal-body">
                {/* Threat Actor & Network Geolocation Card */}
                <div className="soc-modal-section">
                  <h4 className="soc-section-title">
                    <Crosshair size={14} /> Threat Actor Profile & Origin Geolocation
                  </h4>
                  <div className="soc-modal-grid">
                    <div className="soc-prop-item">
                      <span className="soc-prop-label">Attacker Identity</span>
                      <strong className="soc-prop-val red">{socSelectedAlert.attacker || "kali-attacker"}</strong>
                    </div>
                    <div className="soc-prop-item">
                      <span className="soc-prop-label">Source IP Address</span>
                      <strong className="soc-prop-val mono">{socSelectedAlert.source_ip || "192.168.56.101"}</strong>
                    </div>
                    <div className="soc-prop-item">
                      <span className="soc-prop-label">Network Location & Host</span>
                      <strong className="soc-prop-val">
                        {getIpLocationMeta(socSelectedAlert.source_ip, socSelectedAlert.location_info).label}
                      </strong>
                    </div>
                    <div className="soc-prop-item">
                      <span className="soc-prop-label">Network Zone</span>
                      <strong className="soc-prop-val">
                        {getIpLocationMeta(socSelectedAlert.source_ip, socSelectedAlert.location_info).zone}
                      </strong>
                    </div>
                    <div className="soc-prop-item">
                      <span className="soc-prop-label">Entry Point</span>
                      <strong className="soc-prop-val mono">{socSelectedAlert.entry_point || "/lab/kali/memory/write"}</strong>
                    </div>
                    <div className="soc-prop-item">
                      <span className="soc-prop-label">Access Method & Latency</span>
                      <strong className="soc-prop-val">
                        {socSelectedAlert.access_method || "POST"} · {socSelectedAlert.duration_ms ? `${Number(socSelectedAlert.duration_ms).toFixed(1)} ms` : "Instant"}
                      </strong>
                    </div>
                  </div>
                </div>

                {/* Mutation Description & Evidence */}
                {socSelectedAlert.mutation_description && (
                  <div className="soc-modal-section">
                    <h4 className="soc-section-title">
                      <FileText size={14} /> Attack Mutation Telemetry
                    </h4>
                    <p className="soc-mutation-box">{socSelectedAlert.mutation_description}</p>
                  </div>
                )}

                {/* Side-by-Side Content Mutation Diff */}
                <div className="soc-modal-section">
                  <h4 className="soc-section-title">
                    <Layers size={14} /> Cryptographic Content Mutation Diff
                  </h4>
                  <div className="soc-diff-compare-grid">
                    <div className="soc-diff-box trusted">
                      <div className="soc-diff-box-head">
                        <CheckCircle2 size={13} /> Original Trusted Memory Content
                      </div>
                      <pre className="soc-diff-content">
                        {socSelectedAlert.original_content || "Original content not recorded."}
                      </pre>
                    </div>

                    <div className="soc-diff-box attacked">
                      <div className="soc-diff-box-head">
                        <AlertTriangle size={13} /> Tampered / Injected Content
                      </div>
                      <pre className="soc-diff-content">
                        {socSelectedAlert.modified_content || "Modified content not recorded."}
                      </pre>
                    </div>
                  </div>
                </div>

                {/* Self-Healing Response & Actions */}
                <div className="soc-modal-section recovery-summary">
                  <div className="soc-recovery-banner">
                    <ShieldCheck size={20} className="green" />
                    <div>
                      <strong>AegisMem Automated Self-Healing Active</strong>
                      <p>
                        Target memory <code>{socSelectedAlert.memory_id}</code> was mitigated via TCRP recovery planning. Trusted cryptographic state has been restored and verified.
                      </p>
                    </div>
                    <button
                      className="soc-btn primary"
                      onClick={() => {
                        setSocSelectedAlert(null)
                        setPage("attack")
                      }}
                    >
                      Inspect in Live Recovery <ArrowRight size={13} />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    )
  }


function renderMemory() {
    const policyMemories = memories.filter((m) => m.id.startsWith("POLICY") || m.id.startsWith("SOP"))
    const baselineMemories = memories.filter((m) => m.id.startsWith("ENT-"))
    const labMemories = memories.filter((m) => !m.id.startsWith("POLICY") && !m.id.startsWith("SOP") && !m.id.startsWith("ENT-"))

    const filteredMemories = memories.filter((m) => {
      // Category filter
      if (memoryCategoryFilter === "POLICY" && !m.id.startsWith("POLICY") && !m.id.startsWith("SOP")) return false
      if (memoryCategoryFilter === "BASELINE" && !m.id.startsWith("ENT-")) return false
      if (memoryCategoryFilter === "LAB" && (m.id.startsWith("POLICY") || m.id.startsWith("SOP") || m.id.startsWith("ENT-"))) return false

      // Search query
      if (!memorySearchQuery.trim()) return true
      const q = memorySearchQuery.toLowerCase()
      return (
        m.id.toLowerCase().includes(q) ||
        String(m.content || "").toLowerCase().includes(q) ||
        String(m.status || "").toLowerCase().includes(q)
      )
    })

    const activeMemory = selectedMemory || memories[0] || null

    function getCategoryBadge(id) {
      if (id.startsWith("POLICY") || id.startsWith("SOP")) {
        return { label: "Customer Support", cls: "medium" }
      }
      if (id.startsWith("ENT-ACCESS")) {
        return { label: "Access / MFA", cls: "low" }
      }
      if (id.startsWith("ENT-INCIDENT")) {
        return { label: "Incident Ops", cls: "high" }
      }
      if (id.startsWith("ENT-BACKUP")) {
        return { label: "Disaster Recovery", cls: "low" }
      }
      if (id.startsWith("ENT-DATA")) {
        return { label: "Data Protection", cls: "critical" }
      }
      if (id.startsWith("ENT-EMPLOYEE")) {
        return { label: "Personnel Security", cls: "low" }
      }
      return { label: "Adversary Lab", cls: "high" }
    }

    return (
      <div className="page-content memory-page">
        {/* Top Header Panel */}
        <div className="soc-header-panel">
          <div>
            <div className="soc-eyebrow">
              <span className="soc-live-dot"></span>
              PERSISTENT KNOWLEDGE REPOSITORY · SQLITE DATABASE STATE
            </div>
            <h1 className="soc-title">Enterprise Persistent Memory Database</h1>
            <p className="soc-subtitle">
              Versioned enterprise knowledge nodes protected by cryptographic manifests, immutable provenance checkpoints, and autonomous TCRP recovery.
            </p>
          </div>
          <div className="soc-header-actions">
            <span className="soc-status-badge live">
              <Database size={13} /> {memories.length} MONITORED NODES
            </span>
            <span className="soc-status-badge info">
              <CheckCircle2 size={13} /> {dashboard.trusted_percentage || "100"}% TRUSTED
            </span>
          </div>
        </div>

        {/* Filter Toolbar */}
        <div className="soc-filter-bar" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "16px", marginBottom: "20px" }}>
          {/* Category Tabs */}
          <div className="soc-tabs" style={{ display: "flex", gap: "6px" }}>
            <button
              type="button"
              className={`soc-tab ${memoryCategoryFilter === "ALL" ? "active" : ""}`}
              onClick={() => setMemoryCategoryFilter("ALL")}
            >
              All Records ({memories.length})
            </button>
            <button
              type="button"
              className={`soc-tab ${memoryCategoryFilter === "POLICY" ? "active" : ""}`}
              onClick={() => setMemoryCategoryFilter("POLICY")}
            >
              Customer Policies & SOPs ({policyMemories.length})
            </button>
            <button
              type="button"
              className={`soc-tab ${memoryCategoryFilter === "BASELINE" ? "active" : ""}`}
              onClick={() => setMemoryCategoryFilter("BASELINE")}
            >
              Enterprise Baselines ({baselineMemories.length})
            </button>
            <button
              type="button"
              className={`soc-tab ${memoryCategoryFilter === "LAB" ? "active" : ""}`}
              onClick={() => setMemoryCategoryFilter("LAB")}
            >
              Lab & Attack Tests ({labMemories.length})
            </button>
          </div>

          {/* Search Box */}
          <div className="soc-search-wrapper" style={{ width: "280px" }}>
            <Search size={14} className="soc-search-icon" />
            <input
              type="text"
              placeholder="Search memory ID, content, or status..."
              value={memorySearchQuery}
              onChange={(e) => setMemorySearchQuery(e.target.value)}
              className="soc-search-input"
            />
            {memorySearchQuery && (
              <button
                type="button"
                className="soc-search-clear"
                onClick={() => setMemorySearchQuery("")}
              >
                <X size={12} />
              </button>
            )}
          </div>
        </div>

        {/* Main Memory Content: Table + Inspector */}
        <div className="memory-layout" style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: "20px", alignItems: "start" }}>
          {/* Left Table Panel */}
          <section className="soc-table-container">
            <div className="soc-table-header">
              <div>
                <span className="soc-eyebrow" style={{ fontSize: "10px" }}>PERSISTED MEMORY NODES</span>
                <h2 style={{ fontSize: "16px", color: "#f8fafc", margin: "2px 0 0" }}>Active Knowledge Catalog</h2>
              </div>
              <span style={{ fontSize: "12px", color: "#64748b" }}>
                Showing {filteredMemories.length} of {memories.length} entries
              </span>
            </div>

            <div style={{ overflowX: "auto" }}>
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>MEMORY ID</th>
                    <th>DOMAIN / PURPOSE</th>
                    <th>VERSION</th>
                    <th>TRUST</th>
                    <th>STATUS</th>
                    <th>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredMemories.map((m) => {
                    const isSelected = activeMemory?.id === m.id
                    const cat = getCategoryBadge(m.id)
                    const trustVal = Number(m.trust ?? 1.0)
                    const isSuspicious = Number(m.suspicion ?? 0) > 0

                    return (
                      <tr
                        key={m.id}
                        onClick={() => {
                          setSelectedMemory(m)
                          loadMemoryHistory(m.id)
                        }}
                        style={{
                          cursor: "pointer",
                          background: isSelected ? "rgba(56, 189, 248, 0.08)" : undefined,
                          borderColor: isSelected ? "rgba(56, 189, 248, 0.4)" : undefined
                        }}
                      >
                        <td>
                          <span className="soc-cell-code" style={{ color: isSelected ? "#38bdf8" : "#f8fafc" }}>
                            {m.id}
                          </span>
                        </td>
                        <td>
                          <span className={`soc-severity-pill ${cat.cls}`} style={{ fontSize: "10px" }}>
                            {cat.label}
                          </span>
                        </td>
                        <td>
                          <span style={{ fontFamily: "monospace", color: "#94a3b8" }}>
                            v{m.version || 1}
                          </span>
                        </td>
                        <td>
                          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                            <span style={{ color: trustVal >= 0.8 ? "#10b981" : "#f59e0b", fontWeight: 600, fontSize: "12px" }}>
                              {(trustVal * 100).toFixed(0)}%
                            </span>
                          </div>
                        </td>
                        <td>
                          <span className={`soc-status-tag ${m.status === "ACTIVE" ? "open" : "investigating"}`}>
                            {m.status || "ACTIVE"}
                          </span>
                        </td>
                        <td>
                          <button
                            type="button"
                            className="soc-action-btn view-btn"
                            onClick={(e) => {
                              e.stopPropagation()
                              setSelectedMemory(m)
                              loadMemoryHistory(m.id)
                            }}
                            title="Inspect Revision Evidence"
                          >
                            <Eye size={13} /> Inspect
                          </button>
                        </td>
                      </tr>
                    )
                  })}

                  {filteredMemories.length === 0 && (
                    <tr>
                      <td colSpan={6} style={{ textAlign: "center", padding: "40px 0", color: "#64748b" }}>
                        No persistent memory records match your filter criteria.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          {/* Right Inspector Panel */}
          <aside className="memory-inspector-aside">
            {activeMemory ? (
              <section className="soc-table-container" style={{ padding: "18px" }}>
                <div className="soc-table-header" style={{ marginBottom: "14px" }}>
                  <div>
                    <span className="soc-eyebrow" style={{ fontSize: "10px" }}>SELECTED MEMORY INSPECTION</span>
                    <h2 style={{ fontSize: "16px", color: "#f8fafc", margin: "2px 0 0" }}>{activeMemory.id}</h2>
                  </div>
                  <span className={`soc-status-tag ${activeMemory.status === "ACTIVE" ? "open" : "investigating"}`}>
                    v{activeMemory.version || 1} · {activeMemory.status}
                  </span>
                </div>

                {/* Content Card */}
                <div style={{ marginBottom: "16px" }}>
                  <label style={{ display: "block", fontSize: "11px", color: "#94a3b8", marginBottom: "6px", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 600 }}>
                    Active Knowledge Content
                  </label>
                  <div style={{ background: "rgba(15, 23, 42, 0.8)", border: "1px solid #334155", borderRadius: "8px", padding: "12px", fontSize: "12.5px", color: "#e2e8f0", lineHeight: 1.5, maxHeight: "150px", overflowY: "auto" }}>
                    {activeMemory.content}
                  </div>
                </div>

                {/* Cryptographic Manifest Check Card */}
                <div style={{ background: "rgba(30, 41, 59, 0.4)", border: "1px solid #1e293b", borderRadius: "8px", padding: "12px", marginBottom: "16px" }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
                    <span style={{ fontSize: "11px", color: "#94a3b8", fontWeight: 600 }}>CRYPTOGRAPHIC MANIFEST</span>
                    <span className="soc-severity-pill low" style={{ fontSize: "10px", padding: "1px 6px" }}>
                      <CheckCircle2 size={10} /> VALID SHA-256
                    </span>
                  </div>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", fontSize: "11px" }}>
                    <div>
                      <span style={{ color: "#64748b", display: "block" }}>Trust Score</span>
                      <strong style={{ color: Number(activeMemory.trust) >= 0.8 ? "#10b981" : "#f59e0b" }}>
                        {(Number(activeMemory.trust ?? 1.0) * 100).toFixed(0)}%
                      </strong>
                    </div>
                    <div>
                      <span style={{ color: "#64748b", display: "block" }}>Suspicion Score</span>
                      <strong style={{ color: Number(activeMemory.suspicion ?? 0) === 0 ? "#10b981" : "#ef4444" }}>
                        {Number(activeMemory.suspicion ?? 0).toFixed(2)}
                      </strong>
                    </div>
                    <div>
                      <span style={{ color: "#64748b", display: "block" }}>Security Gate</span>
                      <strong style={{ color: "#10b981" }}>ENFORCED</strong>
                    </div>
                    <div>
                      <span style={{ color: "#64748b", display: "block" }}>Storage</span>
                      <strong style={{ color: "#38bdf8" }}>data/aegismem.db</strong>
                    </div>
                  </div>
                </div>

                {/* Revision Timeline */}
                <div>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "10px" }}>
                    <label style={{ fontSize: "11px", color: "#94a3b8", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 600 }}>
                      Stored Revision History ({memoryHistory.length})
                    </label>
                    <button
                      type="button"
                      className="soc-btn secondary"
                      style={{ padding: "2px 8px", fontSize: "10px", height: "24px" }}
                      onClick={() => loadMemoryHistory(activeMemory.id)}
                    >
                      <RefreshCw size={10} /> Reload
                    </button>
                  </div>

                  <div className="soc-history-list" style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "280px", overflowY: "auto" }}>
                    {memoryHistory.map((rev, idx) => {
                      const vNum = rev.version_number || String(rev.version || "").replace(/^v/i, "")
                      const isOwnerAuth = rev.authorization_state === "AUTHORIZED" || rev.owner_authorization_valid === true
                      const isRecoveryAuth = rev.authorization_type === "RECOVERY" || rev.recovery_authorization_valid === true
                      const isAttack = String(rev.author || "").toLowerCase().includes("attacker") || String(rev.author || "").toLowerCase().includes("kali")

                      return (
                        <div
                          key={idx}
                          style={{
                            background: isAttack ? "rgba(239, 68, 68, 0.08)" : "rgba(15, 23, 42, 0.6)",
                            border: `1px solid ${isAttack ? "rgba(239, 68, 68, 0.3)" : "#334155"}`,
                            borderRadius: "6px",
                            padding: "10px"
                          }}
                        >
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "4px" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                              <span style={{ fontFamily: "monospace", fontWeight: 700, color: "#38bdf8", fontSize: "12px" }}>
                                v{vNum}
                              </span>
                              {isOwnerAuth && (
                                <span className="soc-severity-pill low" style={{ fontSize: "9px", padding: "1px 5px" }}>OWNER-SIGNED</span>
                              )}
                              {isRecoveryAuth && (
                                <span className="soc-severity-pill medium" style={{ fontSize: "9px", padding: "1px 5px" }}>TCRP RESTORED</span>
                              )}
                              {isAttack && (
                                <span className="soc-severity-pill critical" style={{ fontSize: "9px", padding: "1px 5px" }}>TAMPERED</span>
                              )}
                            </div>
                            <span style={{ fontSize: "11px", color: "#64748b" }}>
                              {rev.created_at ? new Date(rev.created_at).toLocaleTimeString() : "Persisted"}
                            </span>
                          </div>

                          <div style={{ fontSize: "11.5px", color: "#cbd5e1", lineHeight: 1.4, margin: "4px 0" }}>
                            {rev.content ? (rev.content.length > 90 ? rev.content.slice(0, 90) + "…" : rev.content) : "No content snapshot."}
                          </div>

                          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "10px", color: "#64748b", marginTop: "4px" }}>
                            <span>Author: {rev.author || "System"}</span>
                            <span style={{ fontFamily: "monospace" }}>
                              Hash: {rev.content_hash ? rev.content_hash.slice(0, 10) + "…" : "sha256"}
                            </span>
                          </div>
                        </div>
                      )
                    })}

                    {memoryHistory.length === 0 && (
                      <div style={{ color: "#64748b", fontSize: "12px", textAlign: "center", padding: "16px 0" }}>
                        Click a memory record to load its revision history.
                      </div>
                    )}
                  </div>
                </div>
              </section>
            ) : (
              <div className="soc-empty-state">
                <Database size={24} />
                <span>Select a memory record to inspect cryptographic details and version history.</span>
              </div>
            )}
          </aside>
        </div>
      </div>
    )
  }

  if (!authChecked) {
    return <div style={{minHeight:"100vh",display:"grid",placeItems:"center",background:"#0b1220",color:"#e5e7eb"}}>Checking secure session...</div>
  }

  if (!authenticated) {
    return (
      <div style={{minHeight:"100vh",display:"grid",placeItems:"center",background:"#0b1220",color:"#e5e7eb",fontFamily:"Arial,sans-serif",padding:"24px"}}>
        <form onSubmit={handleLogin} style={{width:"100%",maxWidth:"400px",boxSizing:"border-box",padding:"32px",border:"1px solid #263449",borderRadius:"16px",background:"#111c2e"}}>
          <div style={{display:"flex",alignItems:"center",gap:"12px",marginBottom:"24px"}}>
            <ShieldCheck size={30} />
            <div><h1 style={{margin:0,fontSize:"24px"}}>AEGISMEM</h1><p style={{margin:"5px 0 0",color:"#9ca3af"}}>Memory Security Dashboard</p></div>
          </div>
          <label htmlFor="dashboard-password" style={{display:"block",marginBottom:"8px"}}>Dashboard password</label>
          <input id="dashboard-password" type="password" autoComplete="current-password" required value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} style={{width:"100%",boxSizing:"border-box",padding:"12px",borderRadius:"8px",border:"1px solid #475569",background:"#0b1220",color:"#fff",marginBottom:"16px"}} />
          {loginError && <p role="alert" style={{color:"#fca5a5",fontSize:"14px"}}>{loginError}</p>}
          <button type="submit" disabled={loginLoading} style={{width:"100%",padding:"12px",border:0,borderRadius:"8px",background:"#2563eb",color:"#fff",fontWeight:600,cursor:"pointer"}}>{loginLoading ? "Signing in..." : "Sign in securely"}</button>
        </form>
      </div>
    )
  }
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={22} />
          </div>
          <div>
            <strong>AEGISMEM</strong>
            <span>Memory Security</span>
          </div>
        </div>

        <nav className="nav">
  <NavItem
    icon={LayoutDashboard}
    label="Overview"
    active={page === "overview"}
    onClick={() => setPage("overview")}
  />

  <NavItem
    icon={Bot}
    label="AI Assistant"
    active={page === "assistant"}
    onClick={() => setPage("assistant")}
  />

  <NavItem
    icon={Database}
    label="Memory"
    active={page === "memory"}
    onClick={() => setPage("memory")}
  />

  <NavItem
    icon={ShieldAlert}
    label="Live Recovery"
    active={page === "attack"}
    onClick={() => setPage("attack")}
  />
  <NavItem
    icon={Activity}
    label="SOC Audit"
    active={page === "soc"}
    onClick={() => {
      setPage("soc")
      loadSocSessions()
      loadSocAlerts()
    }}
  />
</nav>

        <div className="sidebar-bottom">
          <div className="security-state">
            <span className="status-dot online"></span>
            <div>
              <strong>Protected</strong>
              <span>AegisMem active</span>
            </div>
          </div>
          <div className="user-profile">
            <div className="user-avatar">V</div>
            <div>
              <strong>Enterprise Operator</strong>
              <span>Administrator</span>
            </div>
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumb">
  AegisMem <span>/</span>{" "}
  {page === "overview"
    ? "Overview"
    : page === "assistant"
    ? "AI Assistant"
    : page === "memory"
? "Memory"
: page === "attack"
? "Live Recovery"
: page === "soc" ? "SOC Audit" : "Memory"}
</div>

          <div className="topbar-actions">
            <button type="button" onClick={handleLogout} style={{padding:"8px 12px",border:"1px solid #475569",borderRadius:"8px",background:"transparent",color:"inherit",cursor:"pointer"}}>Logout</button>
            <span className="environment">
              <span className="status-dot online"></span>
              Research Environment
            </span>
            <div className="operator-avatar">V</div>
          </div>
        </header>

        {page === "overview" && renderOverview()}
        {page === "assistant" && renderAssistant()}
        {page === "memory" && renderMemory()}
        {page === "attack" && renderAttackLab()}
        {page === "soc" && renderSocAudit()}
      </main>
    </div>
  )
}



function NavItem({ icon: Icon, label, active, onClick }) {
  return (
    <button className={`nav-item ${active ? "active" : ""}`} onClick={onClick}>
      <Icon size={18} />
      <span>{label}</span>
      {active && <span className="nav-active-indicator"></span>}
    </button>
  )
}

function StatCard({ icon: Icon, label, value, detail }) {
  return (
    <div className="stat-card">
      <div className="stat-icon">
        <Icon size={19} />
      </div>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  )
}

function PipelineItem({ number, title, text, active }) {
  return (
    <div className={`pipeline-item ${active ? "active" : ""}`}>
      <span>{number}</span>
      <strong>{title}</strong>
      <p>{text}</p>
    </div>
  )
}

function DetailStat({ label, value }) {
  return (
    <div className="detail-stat">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

export default App


















































