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
  Search
} from "lucide-react"



const activities = [
  {
    icon: CheckCircle2,
    title: "Memory integrity verified",
    detail: "POLICY-001 · v3",
    time: "Just now",
    type: "success"
  },
  {
    icon: ShieldCheck,
    title: "Enterprise memory protected",
    detail: "Trust verification active",
    time: "1 min ago",
    type: "success"
  },
  {
    icon: Activity,
    title: "Dependency graph synchronized",
    detail: "3 memory nodes monitored",
    time: "2 min ago",
    type: "info"
  },
  {
    icon: Clock3,
    title: "Recovery engine ready",
    detail: "TCRP available",
    time: "3 min ago",
    type: "info"
  }
]

function App() {
  const [page, setPage] = useState("overview")
  const [backend, setBackend] = useState("checking")
  const [events, setEvents] = useState([])
  const [memories, setMemories] = useState([])
  const [memoryHistory, setMemoryHistory] = useState([])
  const [selectedMemory, setSelectedMemory] = useState(null)

  const [attackResult, setAttackResult] = useState(null)
  const [detectionResult, setDetectionResult] = useState(null)
  const [recoveryResult, setRecoveryResult] = useState(null)
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

async function loadLatestRecovery() {
  try {
    const response = await fetch(
      "/api/dashboard/latest-recovery"
    )

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
      String(
        recovery?.validation_result || ""
      ).toUpperCase() === "PASS"

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
        success: validationPassed,

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

  useEffect(() => {
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

      await loadLatestRecovery()

      const memoriesResponse = await fetch(
  "/api/dashboard/memories"
)

if (!memoriesResponse.ok) {
  throw new Error("Memory data unavailable")
}

const memoriesData = await memoriesResponse.json()

setMemories(memoriesData.memories || [])

setSelectedMemory((current) => {
  if (current) {
    const updated = memoriesData.memories.find(
      (memory) => memory.id === current.id
    )

    return updated || memoriesData.memories[0] || null
  }

  return memoriesData.memories[0] || null
})



    } catch (error) {
      setBackend("offline")
      console.error(
        "Dashboard refresh error:",
        error
      )
    }
  }

  refreshDashboard()

  const interval = setInterval(
    refreshDashboard,
    2000
  )

  return () => clearInterval(interval)
}, [])

useEffect(() => {
  if (page === "memory" && selectedMemory?.id) {
    loadMemoryHistory(selectedMemory.id)
  }

  if (page === "attack") {
    loadMemoryHistory("POLICY-001")
  }
}, [page, selectedMemory?.id, recoveryResult?.restored_version])

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

  async function runPoisonAttack() {
  setAttackLoading(true)
  setAttackResult(null)
  setDetectionResult(null)
  setRecoveryResult(null)

  try {
    const response = await fetch("/api/attack/poison", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        memory_id: "POLICY-001"
      })
    })

    const data = await response.json()

    if (!response.ok) {
      throw new Error(
        data.detail || "Memory poisoning attack failed"
      )
    }

    setAttackResult(data)

    await loadMemoryHistory("POLICY-001")
  } catch (error) {
    setAttackResult({
      error: error.message
    })
  } finally {
    setAttackLoading(false)
  }
}
async function runDetection() {
  setDetectionResult(null)

  try {
    const response = await fetch(
      "/api/aegismem/detect/POLICY-001"
    )

    const data = await response.json()

    if (!response.ok) {
      throw new Error(
        data.detail || "Detection failed"
      )
    }

    setDetectionResult(data)
  } catch (error) {
    setDetectionResult({
      error: error.message
    })
  }
}

async function runRecovery() {
  setRecoveryResult(null)

  try {
    const response = await fetch(
      "/api/aegismem/recover/POLICY-001",
      {
        method: "POST"
      }
    )

    const data = await response.json()

    if (!response.ok) {
      throw new Error(
        data.detail || "Recovery failed"
      )
    }

    setRecoveryResult(data)

    await loadMemoryHistory("POLICY-001")

    const memoriesResponse = await fetch(
      "/api/dashboard/memories"
    )

    if (memoriesResponse.ok) {
      const memoriesData = await memoriesResponse.json()

      setMemories(memoriesData.memories || [])

      const recoveredMemory =
        memoriesData.memories.find(
          (memory) => memory.id === "POLICY-001"
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

  setExperimentRunning(true)
  setExperimentStage("Launching attack...")
  setAttackResult(null)
  setDetectionResult(null)
  setRecoveryResult(null)

  try {
    const attackEndpoint = {
      poisoning: "/api/attack/poison",
      tampering: "/api/attack/tamper",
      deletion: "/api/attack/delete"
    }[selectedAttackType]

    const attackResponse = await fetch(attackEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        memory_id: "POLICY-001"
      })
    })

    const attackData = await attackResponse.json()

    if (!attackResponse.ok) {
      throw new Error(
        attackData.detail || "Attack execution failed"
      )
    }

    setAttackResult(attackData)

    await loadMemoryHistory("POLICY-001")

    setExperimentStage(
      "Detecting compromised memory..."
    )

    const detectionResponse = await fetch(
      "/api/aegismem/detect/POLICY-001"
    )

    const detectionData = await detectionResponse.json()

    if (!detectionResponse.ok) {
      throw new Error(
        detectionData.detail || "Detection failed"
      )
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

    const recoveryResponse = await fetch(
      "/api/aegismem/recover/POLICY-001",
      {
        method: "POST"
      }
    )

    const recoveryData = await recoveryResponse.json()

    if (!recoveryResponse.ok) {
      throw new Error(
        recoveryData.detail || "Recovery failed"
      )
    }

    setRecoveryResult(recoveryData)

    await loadMemoryHistory("POLICY-001")

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
          memory => memory.id === "POLICY-001"
        )

      if (recoveredMemory) {
        setSelectedMemory(recoveredMemory)
      }
    }

    setExperimentStage(
      "Recovery validated — trusted state restored."
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
  const currentMemory =
    memories.find(
      (memory) => memory.id === "POLICY-001"
    ) || selectedMemory

  const latestRecovery =
    recoveryResult?.recovery?.results?.[0] || null

  const recoverySuccessful =
    recoveryResult?.recovery?.success === true

  const compromisedVersion =
  recoveryResult?.memory?.compromised?.version ??
  recoveryResult?.compromised_version ??
  null

const restoredVersion =
  recoveryResult?.memory?.restored?.version ??
  recoveryResult?.restored_version ??
  null

const compromisedMemory =
  memoryHistory.find(
    (memory) =>
      Number(memory.version) ===
      Number(compromisedVersion)
  )

const restoredMemory =
  memoryHistory.find(
    (memory) =>
      Number(memory.version) ===
      Number(restoredVersion)
  )

const trustedBefore =
  memoryHistory.find(
    (memory) =>
      Number(memory.version) ===
      Number(compromisedVersion) - 1
  )

const trustedVersion =
  recoveryResult?.memory?.trusted?.version ??
  trustedBefore?.version ??
  null

const trustedContent =
  recoveryResult?.memory?.trusted?.content ??
  trustedBefore?.content ??
  restoredMemory?.content ??
  currentMemory?.content ??
  "Trusted memory state unavailable."

const compromisedContent =
  recoveryResult?.memory?.compromised?.content ??
  compromisedMemory?.content ??
  "No compromised content recorded."

  const latestEvent =
    events.length > 0 ? events[0] : null

  const attackDetected =
    Boolean(
      compromisedVersion &&
      restoredVersion
    )

  return (
    <div className="page-content">

      {/* HEADER */}

      <div className="page-heading">

        <div>

          <div className="eyebrow">
            LIVE SECURITY MONITOR
          </div>

          <h1>
            AegisMem Live Recovery
          </h1>

          <p>
            Observe how AegisMem detects a compromised
            memory, selects a recovery action, restores
            trusted knowledge, and validates the result.
          </p>

        </div>

        <div className="system-pill">
          <span
            className={`status-dot ${backend}`}
          ></span>

          AegisMem{" "}
          {backend === "online"
            ? "Operational"
            : "Offline"}
        </div>

      </div>


      {/* SECURITY STATUS */}

      <section className="panel">

        <div className="panel-header">

          <div>

            <span className="panel-kicker">
              SECURITY STATUS
            </span>

            <h2>
              {recoverySuccessful
                ? "Threat Contained"
                : attackDetected
                ? "Security Event Detected"
                : "Memory Protection Active"}
            </h2>

          </div>

          {recoverySuccessful ? (
            <CheckCircle2 size={22} />
          ) : attackDetected ? (
            <AlertTriangle size={22} />
          ) : (
            <ShieldCheck size={22} />
          )}

        </div>


        <div className="live-status-card">

          <div className="live-status-icon">

            {recoverySuccessful ? (
              <CheckCircle2 size={26} />
            ) : attackDetected ? (
              <AlertTriangle size={26} />
            ) : (
              <ShieldCheck size={26} />
            )}

          </div>

          <div>

            <strong>
              {recoverySuccessful
                ? "Compromised memory recovered"
                : attackDetected
                ? "Unauthorized memory change detected"
                : "AegisMem is monitoring persistent memory"}
            </strong>

            <span>
              {recoverySuccessful
                ? "The trusted memory state was restored and validation passed."
                : attackDetected
                ? "AegisMem is analyzing the affected memory and determining recovery."
                : "Waiting for an external attack from the controlled security environment."}
            </span>

          </div>

        </div>

      </section>


      {/* MEMORY RECOVERY STORY */}

      <section className="panel">

        <div className="panel-header">

          <div>

            <span className="panel-kicker">
              MEMORY INTEGRITY
            </span>

            <h2>
              Trusted → Compromised → Recovered
            </h2>

          </div>

          <Database size={20} />

        </div>


        <div className="memory-recovery-flow">

          {/* TRUSTED */}

          <div className="memory-state trusted">

            <span className="memory-state-label">
              TRUSTED STATE
            </span>

            <strong>
  {trustedVersion !== null
    ? `v${trustedVersion}`
    : "-"}
</strong>

            <p>
              {trustedContent}
            </p>

            <div className="memory-state-status">
              <CheckCircle2 size={15} />
              Trusted
            </div>

          </div>


          <div className="recovery-arrow">
            <ChevronRight size={22} />
          </div>


          {/* COMPROMISED */}

          <div className="memory-state compromised">

            <span className="memory-state-label">
              ATTACKED STATE
            </span>

            <strong>
  {compromisedVersion !== null
    ? `v${compromisedVersion}`
    : "-"}
</strong>

            <p>
              {compromisedContent}
            </p>

            <div className="memory-state-status">
  <AlertTriangle size={15} />
  Compromised
</div>

{recoveryResult?.memory?.compromised?.attack_type && (
  <small>
    {recoveryResult.memory.compromised.attack_type}
    {recoveryResult.memory.compromised.attacker
      ? ` · ${recoveryResult.memory.compromised.attacker}`
      : ""}
  </small>
)}

          </div>


          <div className="recovery-arrow">
            <ChevronRight size={22} />
          </div>


          {/* RECOVERED */}

          <div className="memory-state recovered">

            <span className="memory-state-label">
              RECOVERED STATE
            </span>

            <strong>
  {restoredVersion !== null
    ? `v${restoredVersion}`
    : currentMemory?.version
    ? `v${currentMemory.version}`
    : "-"}
</strong>

            <p>
  {recoveryResult?.memory?.restored?.content ||
    restoredMemory?.content ||
    trustedContent}
</p>

            <div className="memory-state-status">
              <CheckCircle2 size={15} />
              Restored
            </div>

          </div>

        </div>

      </section>


      {/* AEGISMEM RESPONSE */}

      <section className="panel">

        <div className="panel-header">

          <div>

            <span className="panel-kicker">
              AEGISMEM RESPONSE
            </span>

            <h2>
              Automatic Self-Healing Process
            </h2>

          </div>

          <ShieldCheck size={20} />

        </div>


        <div className="recovery-steps">

          <div className="recovery-step completed">

            <div className="recovery-step-number">
              01
            </div>

            <div>

              <strong>
                Detect
              </strong>

              <span>
                Unauthorized memory change detected
              </span>

            </div>

            <CheckCircle2 size={18} />

          </div>


          <div className="recovery-step completed">

            <div className="recovery-step-number">
              02
            </div>

            <div>

              <strong>
                Diagnose
              </strong>

              <span>
                Compromise evidence analyzed
              </span>

            </div>

            <CheckCircle2 size={18} />

          </div>


          <div className="recovery-step completed">

            <div className="recovery-step-number">
              03
            </div>

            <div>

              <strong>
                TCRP
              </strong>

              <span>
                Recovery action:{" "}
                <b>
                  {recoveryResult?.recovery?.decisions?.[0]?.action ||
                    "ROLLBACK"}
                </b>
              </span>

            </div>

            <CheckCircle2 size={18} />

          </div>


          <div className="recovery-step completed">

            <div className="recovery-step-number">
              04
            </div>

            <div>

              <strong>
                Recover
              </strong>

              <span>
                Trusted historical memory restored
              </span>

            </div>

            <CheckCircle2 size={18} />

          </div>


          <div className="recovery-step completed">

            <div className="recovery-step-number">
              05
            </div>

            <div>

              <strong>
                Validate
              </strong>

              <span>
                Memory integrity and trust verified
              </span>

            </div>

            <CheckCircle2 size={18} />

          </div>

        </div>

      </section>


      {/* TCRP DECISION */}

      <section className="panel">

        <div className="panel-header">

          <div>

            <span className="panel-kicker">
              TCRP DECISION
            </span>

            <h2>
              Why was the memory rolled back?
            </h2>

          </div>

          <GitBranch size={20} />

        </div>


        <div className="decision-summary">

          <div className="decision-action">

            <span>
              SELECTED RECOVERY ACTION
            </span>

            <strong>
              {recoveryResult?.recovery?.decisions?.[0]?.action ||
                "ROLLBACK"}
            </strong>

          </div>


          <div className="decision-explanation">

            <strong>
              Trusted historical state available
            </strong>

            <p>
              AegisMem determined that the compromised
              memory should not be retained and restored
              the previously trusted version.
            </p>

          </div>

        </div>


        <details className="technical-details">

          <summary>
            View technical TCRP evidence
          </summary>

          <div className="technical-grid">

            <div>
              <span>
                Trust
              </span>

              <strong>
                {Number(
                  recoveryResult?.recovery?.decisions?.[0]
                    ?.trust_score || 0
                ).toFixed(2)}
              </strong>
            </div>

            <div>
              <span>
                Suspicion
              </span>

              <strong>
                {Number(
                  recoveryResult?.recovery?.decisions?.[0]
                    ?.suspicion_score || 0
                ).toFixed(2)}
              </strong>
            </div>

            <div>
              <span>
                Impact
              </span>

              <strong>
                {Number(
                  recoveryResult?.recovery?.decisions?.[0]
                    ?.impact_score || 0
                ).toFixed(2)}
              </strong>
            </div>

            <div>
              <span>
                Selected Cost
              </span>

              <strong>
                {Number(
                  recoveryResult?.recovery?.decisions?.[0]
                    ?.selected_action_cost || 0
                ).toFixed(4)}
              </strong>
            </div>

          </div>

        </details>

      </section>


      {/* VALIDATION */}

      <section className="panel">

        <div className="panel-header">

          <div>

            <span className="panel-kicker">
              VALIDATION
            </span>

            <h2>
              Recovery Verification
            </h2>

          </div>

          <CheckCircle2 size={20} />

        </div>


        <div className="recovery-banner success">

          <CheckCircle2 size={22} />

          <div>

            <strong>
              {recoverySuccessful
                ? "Recovery validated successfully"
                : "AegisMem monitoring"}
            </strong>

            <span>
              {recoverySuccessful
                ? "The trusted memory state was restored and is active again."
                : "Validation results will appear automatically after recovery."}
            </span>

          </div>

        </div>

      </section>


      {/* DEPENDENCY IMPACT */}

      <section className="panel">

        <div className="panel-header">

          <div>

            <span className="panel-kicker">
              DEPENDENCY IMPACT
            </span>

            <h2>
              Protected Memory Relationships
            </h2>

          </div>

          <GitBranch size={20} />

        </div>


        <div className="dependency-flow">

          <div className="dependency-node root">

            <strong>
              POLICY-001
            </strong>

            <span>
              Directly protected
            </span>

          </div>


          <div className="dependency-line">
            ↓
          </div>


          <div className="dependency-node">

            <strong>
              POLICY-002
            </strong>

            <span>
              Dependent memory
            </span>

          </div>


          <div className="dependency-line">
            ↓
          </div>


          <div className="dependency-node">

            <strong>
              SOP-003
            </strong>

            <span>
              Dependent memory
            </span>

          </div>

        </div>

        <p className="dependency-explanation">
          AegisMem evaluates the dependency chain so that
          compromised knowledge does not silently propagate
          to dependent memories.
        </p>

      </section>


      {/* RECOVERY RECORD */}

{recoveryResult?.recovery?.results?.length > 0 && (

  <section className="panel">

    <div className="panel-header">

      <div>

        <span className="panel-kicker">
          RECOVERY RECORD
        </span>

        <h2>
          Latest Recovery
        </h2>

      </div>

      <Activity size={20} />

    </div>


    <div className="recovery-record-card">

      <div className="recovery-record-main">

        <div className="recovery-record-action">

          <CheckCircle2 size={22} />

          <div>

            <strong>
              {recoveryResult.recovery.results[0].action}
            </strong>

            <span>
              {recoveryResult.recovery.results[0].memory_id}
            </span>

          </div>

        </div>


        <div className="recovery-record-message">

          <strong>
            Recovery completed
          </strong>

          <span>
            {recoveryResult.recovery.results[0].message ||
              "Memory rollback executed successfully."}
          </span>

        </div>

      </div>


      <div className="recovery-record-flow">

        <div>

          <span>
            COMPROMISED
          </span>

          <strong>
            v{recoveryResult.compromised_version}
          </strong>

        </div>


        <ChevronRight size={20} />


        <div>

          <span>
            RESTORED
          </span>

          <strong>
            v{recoveryResult.restored_version}
          </strong>

        </div>


        <div className="recovery-record-status">

          <CheckCircle2 size={17} />

          <span>
            {recoveryResult.validation_result === "PASS"
              ? "VALIDATED"
              : "PENDING"}
          </span>

        </div>

      </div>

    </div>

  </section>

)}

    </div>
  )
}

  function renderOverview() {
  const latestRecovery = recoveryResult?.recovery?.results?.[0] || null
  const latestDecision =
    recoveryResult?.recovery?.decisions?.[0] || null

  const trustedVersion =
    recoveryResult?.memory?.trusted?.version ?? null

  const compromisedVersion =
    recoveryResult?.memory?.compromised?.version ?? null

  const restoredVersion =
    recoveryResult?.memory?.restored?.version ?? null

  const trustedContent =
    recoveryResult?.memory?.trusted?.content ||
    "No trusted baseline recorded."

  const compromisedContent =
    recoveryResult?.memory?.compromised?.content ||
    "No compromised state recorded."

  const restoredContent =
    recoveryResult?.memory?.restored?.content ||
    "No restored state recorded."

  const attackType =
    recoveryResult?.memory?.compromised?.attack_type ||
    "memory tampering"

  const attacker =
    recoveryResult?.memory?.compromised?.attacker ||
    "external actor"

  const recoveryPassed =
    recoveryResult?.validation_result === "PASS"

  return (
    <div className="page-content">

      <div className="page-heading">

        <div>
          <div className="eyebrow">
            SECURITY CONTROL CENTER
          </div>

          <h1>
            Enterprise AI Memory Protection
          </h1>

          <p>
            Monitor persistent memory integrity, trust,
            dependencies and autonomous self-healing.
          </p>
        </div>

        <div className="system-pill">
          <span className={`status-dot ${backend}`}></span>
          Backend{" "}
          {backend === "online"
            ? "Online"
            : backend === "offline"
            ? "Offline"
            : "Checking"}
        </div>

      </div>


      {/* SECURITY METRICS */}

      <div className="stat-grid">

        <StatCard
  icon={Database}
  label="Protected Memories"
  value={dashboard.protected_memories}
  detail="Currently monitored"
/>
        <StatCard
          icon={ShieldCheck}
          label="Trusted Memories"
          value={`${dashboard.trusted_percentage}%`}
          detail={`${dashboard.trusted_memories} of ${dashboard.protected_memories} trusted`}
        />

        <StatCard
          icon={ShieldAlert}
          label="Security Events"
          value={dashboard.active_threats}
          detail={`${dashboard.quarantined_memories} quarantined`}
        />

        <StatCard
  icon={RefreshCw}
  label="Recovery Incidents"
  value={dashboard.recovery_events}
  detail="Successful recovery incidents"
/>

      </div>


      {/* PROTECTION PIPELINE + INTEGRITY */}

      <div className="dashboard-grid">

        <section className="panel large-panel">

          <div className="panel-header">

            <div>
              <span className="panel-kicker">
                MEMORY SECURITY
              </span>

              <h2>
                Protection Pipeline
              </h2>
            </div>

            <ShieldCheck size={20} />

          </div>

          <div className="pipeline">

            <PipelineItem
              number="01"
              title="Detect"
              text="Identify suspicious memory state"
              active
            />

            <ChevronRight className="pipeline-arrow" />

            <PipelineItem
              number="02"
              title="Assess"
              text="Evaluate integrity and trust"
            />

            <ChevronRight className="pipeline-arrow" />

            <PipelineItem
              number="03"
              title="TCRP"
              text="Plan dependency-aware recovery"
            />

            <ChevronRight className="pipeline-arrow" />

            <PipelineItem
              number="04"
              title="Recover"
              text="Restore trusted historical state"
            />

            <ChevronRight className="pipeline-arrow" />

            <PipelineItem
              number="05"
              title="Validate"
              text="Confirm restored memory"
            />

          </div>

        </section>


        <section className="panel">

          <div className="panel-header">

            <div>
              <span className="panel-kicker">
                SYSTEM HEALTH
              </span>

              <h2>
                Memory Integrity
              </h2>
            </div>

            <Activity size={20} />

          </div>

          <div className="health-ring">

            <div className="health-value">

              <strong>
                {dashboard.integrity_percentage}%
              </strong>

              <span>
                Integrity verified
              </span>

            </div>

          </div>

          <div className="health-row">
            <span>
              Integrity checks
            </span>

            <strong>
              {dashboard.integrity_valid} /{" "}
              {dashboard.integrity_valid +
                dashboard.integrity_invalid}
            </strong>
          </div>

          <div className="health-row">
            <span>
              Suspicious memories
            </span>

            <strong>
              {dashboard.suspicious_memories}
            </strong>
          </div>

          <div className="health-row">
            <span>
              Quarantined
            </span>

            <strong>
              {dashboard.quarantined_memories}
            </strong>
          </div>

        </section>

      </div>


      {/* LATEST REAL INCIDENT */}

      {latestRecovery && (

        <section className="panel incident-panel">

          <div className="panel-header">

            <div>
              <span className="panel-kicker">
                LATEST RECOVERY INCIDENT
              </span>

              <h2>
                Compromised Memory Contained
              </h2>
            </div>

            <div className="incident-status">
              <CheckCircle2 size={17} />
              {recoveryPassed
                ? "VALIDATED"
                : "RECOVERY RECORDED"}
            </div>

          </div>


          <div className="incident-meta">

            <div>
              <span>
                MEMORY
              </span>

              <strong>
                {latestRecovery.memory_id}
              </strong>
            </div>

            <div>
              <span>
                ATTACK
              </span>

              <strong>
                {attackType}
              </strong>
            </div>

            <div>
              <span>
                SOURCE
              </span>

              <strong>
                {attacker}
              </strong>
            </div>

            <div>
              <span>
                ACTION
              </span>

              <strong>
                {latestDecision?.action ||
                  latestRecovery.action}
              </strong>
            </div>

          </div>


          <div className="incident-flow">

            <div className="incident-state trusted">

              <span>
                TRUSTED
              </span>

              <strong>
                {trustedVersion !== null
                  ? `v${trustedVersion}`
                  : "-"}
              </strong>

              <p>
                {trustedContent}
              </p>

            </div>


            <ChevronRight className="incident-arrow" />


            <div className="incident-state compromised">

              <span>
                COMPROMISED
              </span>

              <strong>
                {compromisedVersion !== null
                  ? `v${compromisedVersion}`
                  : "-"}
              </strong>

              <p>
                {compromisedContent}
              </p>

            </div>


            <ChevronRight className="incident-arrow" />


            <div className="incident-state recovered">

              <span>
                RESTORED
              </span>

              <strong>
                {restoredVersion !== null
                  ? `v${restoredVersion}`
                  : "-"}
              </strong>

              <p>
                {restoredContent}
              </p>

            </div>

          </div>


          <div className="incident-footer">

            <div className="incident-result">

              <CheckCircle2 size={18} />

              <div>
                <strong>
                  Autonomous recovery completed
                </strong>

                <span>
                  TCRP selected{" "}
                  {latestDecision?.action ||
                    latestRecovery.action}{" "}
                  and the restored memory passed validation.
                </span>
              </div>

            </div>

            <button
              className="text-button"
              onClick={() => setPage("attack")}
            >
              View Live Recovery
              <ChevronRight size={15} />
            </button>

          </div>

        </section>

      )}


      {/* PROTECTED KNOWLEDGE */}

      <section className="panel">

        <div className="panel-header">

          <div>
            <span className="panel-kicker">
              ENTERPRISE MEMORY
            </span>

            <h2>
              Protected Knowledge
            </h2>
          </div>

          <button
            className="text-button"
            onClick={() => setPage("memory")}
          >
            View all
            <ChevronRight size={15} />
          </button>

        </div>


        <div className="memory-list">

          {memories.map((memory) => (

            <button
              className="memory-row"
              key={memory.id}
              onClick={() => {
                setSelectedMemory(memory)
                setPage("memory")
                loadMemoryHistory(memory.id)
              }}
            >

              <div className="memory-icon">
                <Database size={17} />
              </div>

              <div className="memory-main">

                <strong>
                  {memory.id}
                </strong>

                <span>
                  {memory.source_type}
                </span>

              </div>

              <div className="memory-trust">

                <strong>
                  {memory.trust.toFixed(2)}
                </strong>

                <span>
                  Trust
                </span>

              </div>

              <span className="badge active">
                {memory.status}
              </span>

            </button>

          ))}

        </div>

      </section>

    </div>
  )
}

  function renderAssistant() {
  const lastMessage =
    messages[messages.length - 1]

  const metadata =
    lastMessage?.metadata || null

  const isVerified =
    metadata?.aegismem_verified === true

  const currentMemory =
    memories.find(
      (memory) => memory.id === "POLICY-001"
    ) || selectedMemory

  const recoverySuccessful =
    recoveryResult?.recovery?.success === true

  return (
    <div className="page-content assistant-page">

      <div className="page-heading">
        <div>
          <div className="eyebrow">
            PROTECTED AI ASSISTANT
          </div>

          <h1>
            AegisMem AI Assistant
          </h1>

          <p>
            Ask the enterprise agent a question. AegisMem
            verifies persistent memory before it is used.
          </p>
        </div>

        <div className="system-pill">
          <span className="status-dot online"></span>
          Memory Protection Active
        </div>
      </div>

      <div className="assistant-layout">

        <section className="chat-panel">

          <div className="chat-header">
            <div className="agent-avatar">
              <Bot size={22} />
            </div>

            <div>
              <strong>
                Enterprise AI Agent
              </strong>

              <span>
                Protected by AegisMem
              </span>
            </div>

            <div className="chat-live">
              <span className="status-dot online"></span>
              Protected
            </div>
          </div>

          <div className="chat-messages">

            {messages.map((message, index) => {

              const verified =
                message.metadata?.aegismem_verified === true

              return (
                <div
                  key={index}
                  className={`message ${message.role}`}
                >

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

                    <span className="message-role">
                      {message.role === "user"
                        ? "YOU"
                        : message.role === "system"
                        ? "SYSTEM"
                        : "AEGISMEM AGENT"}
                    </span>

                    <p>
                      {message.text}
                    </p>

                    {message.metadata && (
                      <div className="response-metadata">

                        {message.metadata.memory_used && (
                          <span>
                            POLICY-001 · v
                            {message.metadata.memory_version}
                          </span>
                        )}

                        {verified && (
                          <span>
                            ✓ Memory Verified
                          </span>
                        )}

                        {message.metadata.status && (
                          <span>
                            {message.metadata.status}
                          </span>
                        )}

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

                  <span className="message-role">
                    AEGISMEM AGENT
                  </span>

                  <p className="typing">
                    Verifying trusted memory...
                  </p>

                </div>

              </div>
            )}

          </div>

          <div className="chat-input-area">

            <input
              value={question}
              onChange={(event) =>
                setQuestion(event.target.value)
              }
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  sendQuestion()
                }
              }}
              placeholder="Ask: What is the refund policy?"
            />

            <button
              onClick={sendQuestion}
              disabled={sending}
            >
              <MessageSquare size={18} />
            </button>

          </div>

        </section>


        <aside className="assistant-sidebar">

          <section className="panel">

            <div className="panel-header">

              <div>
                <span className="panel-kicker">
                  MEMORY STATUS
                </span>

                <h2>
                  Protected Knowledge
                </h2>
              </div>

              <ShieldCheck size={19} />

            </div>


            <div className="source-card">

              <div className="source-title">

                <Database size={17} />

                <strong>
                  Customer Refund Policy
                </strong>

              </div>

              <p>
                {currentMemory?.content ||
                  "Waiting for memory telemetry..."}
              </p>

              <div className="source-grid">

                <span>
                  Memory
                </span>

                <strong>
                  POLICY-001
                </strong>

                <span>
                  Version
                </span>

                <strong>
                  v{currentMemory?.version || "-"}
                </strong>

                <span>
                  Trust
                </span>

                <strong>
                  {currentMemory
                    ? Number(
                        currentMemory.trust
                      ).toFixed(2)
                    : "-"}
                </strong>

                <span>
                  Status
                </span>

                <strong>
                  {currentMemory?.status || "-"}
                </strong>

              </div>

            </div>


            <div className="verified-box">

              {isVerified || recoverySuccessful ? (
                <>
                  <CheckCircle2 size={18} />

                  <div>

                    <strong>
                      Trusted memory
                    </strong>

                    <span>
                      AegisMem verified this memory
                      before the response.
                    </span>

                  </div>
                </>
              ) : (
                <>
                  <Lock size={18} />

                  <div>

                    <strong>
                      Memory protection active
                    </strong>

                    <span>
                      Enterprise memory is verified
                      before use.
                    </span>

                  </div>
                </>
              )}

            </div>

          </section>


          <section className="panel">

            <div className="panel-header">

              <div>
                <span className="panel-kicker">
                  DEMO FLOW
                </span>

                <h2>
                  How AegisMem Protects the Agent
                </h2>
              </div>

              <ShieldCheck size={19} />

            </div>


            <div className="mini-flow">

              <div>
                <strong>
                  01
                </strong>

                <span>
                  User asks a question
                </span>
              </div>

              <div>
                <strong>
                  02
                </strong>

                <span>
                  Agent retrieves memory
                </span>
              </div>

              <div>
                <strong>
                  03
                </strong>

                <span>
                  AegisMem verifies memory
                </span>
              </div>

              <div>
                <strong>
                  04
                </strong>

                <span>
                  Agent generates answer
                </span>
              </div>

            </div>

          </section>


          {recoverySuccessful && (
            <section className="panel">

              <div className="panel-header">

                <div>
                  <span className="panel-kicker">
                    RECOVERY COMPLETE
                  </span>

                  <h2>
                    Trusted State Restored
                  </h2>
                </div>

                <CheckCircle2 size={19} />

              </div>

              <div className="recovery-banner success">

                <CheckCircle2 size={21} />

                <div>

                  <strong>
                    Memory is safe again
                  </strong>

                  <span>
                    AegisMem restored and validated
                    the trusted memory state.
                  </span>

                </div>

              </div>

            </section>
          )}

        </aside>

      </div>

    </div>
  )
}

  function renderMemory() {
    return (
      <div className="page-content">
        <div className="page-heading">
          <div>
            <div className="eyebrow">PERSISTENT MEMORY</div>
            <h1>Enterprise Memory Database</h1>
            <p>
              Versioned enterprise knowledge protected by integrity and trust
              controls.
            </p>
          </div>

          <div className="search-box">
            <Search size={17} />
            <input placeholder="Search memory..." />
          </div>
        </div>

        <div className="memory-layout">
          <section className="panel">
  <div className="table-header">
    <div>
      <span className="panel-kicker">MEMORY RECORDS</span>
      <h2>Protected Knowledge</h2>
    </div>

    <span className="record-count">
      {memories.length} monitored records
    </span>
  </div>

  <div className="memory-table">
    <div className="table-row table-head">
      <span>Memory</span>
      <span>Type</span>
      <span>Version</span>
      <span>Trust</span>
      <span>Status</span>
    </div>

    {memories.map((memory) => (
      <button
        className={`table-row table-data ${
          selectedMemory?.id === memory.id ? "selected" : ""
        }`}
        key={memory.id}
        onClick={() => {
          setSelectedMemory(memory)
          loadMemoryHistory(memory.id)
        }}
      >
        <span>
          <strong>{memory.id}</strong>
        </span>

        <span>{memory.source_type}</span>

        <span>{memory.version}</span>

        <span className="trust-value">
          {Number(memory.trust).toFixed(2)}
        </span>

        <span>
          <span className={`badge ${memory.status.toLowerCase()}`}>
            {memory.status}
          </span>
        </span>
      </button>
    ))}
  </div>

  <div className="memory-security-summary">

    <div className="memory-summary-header">
      <div>
        <span className="panel-kicker">
          SECURITY STATE
        </span>

        <strong>
          Current memory posture
        </strong>
      </div>

      <ShieldCheck size={18} />
    </div>

    <div className="memory-summary-grid">

      <div>
        <span>PROTECTED</span>
        <strong>{dashboard.protected_memories}</strong>
      </div>

      <div>
        <span>TRUSTED</span>
        <strong>{dashboard.trusted_memories}</strong>
      </div>

      <div>
        <span>QUARANTINED</span>
        <strong>{dashboard.quarantined_memories}</strong>
      </div>

      <div>
        <span>INTEGRITY</span>
        <strong>{dashboard.integrity_percentage}%</strong>
      </div>

    </div>

  </div>
</section>

          <section className="panel memory-detail">
            <div className="panel-header">
              <div>
                <span className="panel-kicker">MEMORY DETAIL</span>
                <h2>{selectedMemory?.id || "Loading..."}</h2>
              </div>
              <ShieldCheck size={21} />
            </div>

            <div className="detail-stat-grid">
  <DetailStat
    label="Version"
    value={selectedMemory?.version || "-"}
  />

  <DetailStat
    label="Trust"
    value={
      selectedMemory
        ? selectedMemory.trust.toFixed(2)
        : "-"
    }
  />

  <DetailStat
    label="Suspicion"
    value={
      selectedMemory
        ? selectedMemory.suspicion.toFixed(2)
        : "-"
    }
  />

  <DetailStat
    label="Status"
    value={selectedMemory?.status || "-"}
  />
</div>

            <div className="content-block">
              <span>MEMORY CONTENT</span>
              <p>
  {selectedMemory?.content || "No memory selected."}
</p>
            </div>

            <div className="content-block">
              <span>INTEGRITY</span>
              <div className="integrity-status">
                <CheckCircle2 size={18} />
                Valid trusted state
              </div>
            </div>

            <div className="content-block memory-timeline-section">

  <div className="timeline-header">
    <div>
      <span>MEMORY VERSION TIMELINE</span>
      <small>
        {memoryHistory.length} recorded versions
      </small>
    </div>

    {memoryHistory.length > 8 && (
      <span className="timeline-summary">
        Showing latest 8
      </span>
    )}
  </div>

  <div className="memory-timeline">

    {memoryHistory
      .slice(-8)
      .reverse()
      .map((version) => {

        const state =
  String(version.state || "").toUpperCase()

const compromised =
  state === "COMPROMISED"

const restoredState =
  state === "RESTORED"




        return (
  <div
    className={`timeline-item ${
      compromised
        ? "corrupted"
        : restoredState
        ? "restored"
        : "trusted"
    }`}
    key={version.id}
  >

    <div className="timeline-marker">
      {compromised ? (
        <AlertTriangle size={13} />
      ) : (
        <CheckCircle2 size={13} />
      )}
    </div>

    <div className="timeline-content">

      <div className="timeline-title">

        <strong>
          {version.version}
        </strong>

        <span
          className={`timeline-state ${
            compromised
              ? "danger"
              : restoredState
              ? "recovered"
              : "safe"
          }`}
        >
          {compromised
            ? "COMPROMISED"
            : restoredState
            ? "RESTORED"
            : "TRUSTED"}
        </span>

              </div>

              <p>
                {version.content}
              </p>

              <small>
                Trust{" "}
                {Number(version.trust).toFixed(2)}
                {" · "}
                {version.status}
              </small>

              {compromised &&
                recoveryResult?.memory?.compromised?.attack_type && (
                  <div className="timeline-attack">

                    <AlertTriangle size={13} />

                    <span>
                      {
                        recoveryResult.memory.compromised.attack_type
                      }

                      {recoveryResult.memory.compromised.attacker
                        ? ` · ${recoveryResult.memory.compromised.attacker}`
                        : ""}
                    </span>

                  </div>
                )}

            </div>

          </div>
        )
      })}

  </div>

  {memoryHistory.length > 8 && (
    <div className="timeline-footer">
      <span>
        {memoryHistory.length - 8} earlier versions
        retained in persistent memory history.
      </span>
    </div>
  )}

</div>
          </section>
        </div>
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
: "Memory"}
</div>

          <div className="topbar-actions">
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
