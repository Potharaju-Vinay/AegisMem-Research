"""
AegisMem Security Operations Center (SOC) - Forensic Incident Dossier Generator
Milestone M10: Unified Incident Object, Multi-format Forensic Exporters (JSON, Markdown, PDF).
"""

import difflib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

logger = logging.getLogger(__name__)


def compute_content_diff(before: str, after: str, label_before: str = "Original", label_after: str = "Modified") -> str:
    """Generates standard unified diff representation between two versions of text."""
    before_lines = before.splitlines(keepends=True)
    after_lines = after.splitlines(keepends=True)
    diff = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile=label_before,
        tofile=label_after,
        lineterm=""
    )
    return "\n".join(diff).strip()


def _render_minimal_pdf(lines: List[str], output_path: Path) -> Path:
    """
    Renders a standard, spec-compliant PDF-1.4 forensic report.
    Pure-Python implementation with multi-page text layout requiring zero external dependencies.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines_per_page = 44
    chunks = [lines[i:i + lines_per_page] for i in range(0, len(lines), lines_per_page)]
    if not chunks:
        chunks = [["[EMPTY INCIDENT DOSSIER]"]]

    total_pages = len(chunks)
    font_id = 3 + 2 * total_pages

    objs: Dict[int, str] = {}
    objs[1] = "<< /Type /Catalog /Pages 2 0 R >>"
    page_kids = " ".join(f"{3 + 2 * i} 0 R" for i in range(total_pages))
    objs[2] = f"<< /Type /Pages /Kids [{page_kids}] /Count {total_pages} >>"

    for i, page_lines in enumerate(chunks):
        p_id = 3 + 2 * i
        c_id = 4 + 2 * i
        objs[p_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Contents {c_id} 0 R /Resources << /Font << /F1 {font_id} 0 R >> >> >>"
        )

        text_ops = ["BT", "/F1 9 Tf", "40 750 Td", "14 TL"]
        for line in page_lines:
            safe = (
                line.replace("\\", "\\\\")
                .replace("(", "\\(")
                .replace(")", "\\)")
                .encode("ascii", errors="replace")
                .decode("ascii")
            )
            # Truncate line length to fit 8.5" width
            if len(safe) > 95:
                safe = safe[:92] + "..."
            text_ops.append(f"({safe}) '")
        text_ops.append("ET")
        stream_data = "\n".join(text_ops)
        objs[c_id] = f"<< /Length {len(stream_data)} >>\nstream\n{stream_data}\nendstream"

    objs[font_id] = "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"

    pdf_parts = ["%PDF-1.4\n"]
    offsets: Dict[int, int] = {}
    curr_offset = len(pdf_parts[0].encode("latin-1"))

    for obj_id in sorted(objs.keys()):
        offsets[obj_id] = curr_offset
        body = f"{obj_id} 0 obj\n{objs[obj_id]}\nendobj\n"
        pdf_parts.append(body)
        curr_offset += len(body.encode("latin-1"))

    xref_offset = curr_offset
    pdf_parts.append(f"xref\n0 {font_id + 1}\n0000000000 65535 f \n")
    for obj_id in range(1, font_id + 1):
        pdf_parts.append(f"{offsets[obj_id]:010d} 00000 n \n")

    pdf_parts.append(f"trailer\n<< /Size {font_id + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n")

    output_path.write_bytes("".join(pdf_parts).encode("latin-1"))
    return output_path


@dataclass
class IncidentReport:
    """
    Unified Forensic Incident Dossier for enterprise security operations.
    Captures end-to-end evidence from probe to self-healing recovery.
    """
    incident_id: str
    title: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "RESOLVED_SECURE"
    severity: str = "HIGH"
    severity_score: float = 0.85
    attacker: Dict[str, Any] = field(default_factory=dict)
    session: Dict[str, Any] = field(default_factory=dict)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    read_items: List[Dict[str, Any]] = field(default_factory=list)
    modified_items: List[Dict[str, Any]] = field(default_factory=list)
    detection_evidence: Dict[str, Any] = field(default_factory=dict)
    dependency_impact: Dict[str, Any] = field(default_factory=dict)
    tcrp_decision: Dict[str, Any] = field(default_factory=dict)
    recovery_ladder_level: Dict[str, Any] = field(default_factory=dict)
    derived_state_repair: Dict[str, Any] = field(default_factory=dict)
    validation: Dict[str, Any] = field(default_factory=dict)
    exposure_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_markdown(self) -> str:
        md = []
        md.append(f"# AegisMem Forensic Incident Dossier: `{self.incident_id}`")
        md.append(f"**Title:** {self.title}")
        md.append(f"**Status:** `{self.status}` | **Severity:** `{self.severity}` (Score: {self.severity_score:.2f})")
        md.append(f"**Recorded UTC:** `{self.timestamp}`\n")
        md.append("---")

        # 1. Executive Summary
        md.append("## 1. Executive Summary & Exposure Window")
        exposure_status = "**ZERO WRONG ANSWERS SERVED (0)**" if self.exposure_count == 0 else f"**WARNING: {self.exposure_count} EXPOSED**"
        md.append(f"- **Exposure Window Guarantee:** {exposure_status}")
        md.append(f"- **Adversary Dwell Time:** {self.session.get('dwell_time_seconds', 0.0):.4f} s")
        md.append(f"- **Time to Detect:** {self.detection_evidence.get('time_to_detect_ms', 0.0):.2f} ms")
        md.append(f"- **Time to Recover:** {self.recovery_ladder_level.get('time_to_recover_ms', 0.0):.2f} ms")
        md.append(f"- **Recovery Ladder Level Reached:** Level {self.recovery_ladder_level.get('level', 1)} ({self.recovery_ladder_level.get('level_name', 'UNKNOWN')})")
        md.append(f"- **Cryptographic Chain of Custody:** {'VERIFIED ✅' if self.validation.get('hash_chain_valid', True) else 'COMPROMISED ❌'}\n")

        # 2. Threat Actor Profile
        md.append("## 2. Threat Actor & Session Metadata")
        md.append(f"- **Actor Identifier:** `{self.attacker.get('actor', 'unknown')}`")
        md.append(f"- **Source IP / Port:** `{self.attacker.get('source_ip', '127.0.0.1')}:{self.attacker.get('source_port', 0)}`")
        md.append(f"- **Attack Scenario:** `{self.attacker.get('scenario', 'UNKNOWN')}`")
        md.append(f"- **MITRE TTP Mapping:** `{self.attacker.get('ttp', 'T1565.001 - Stored Data Manipulation')}`")
        md.append(f"- **Correlated Session ID:** `{self.session.get('session_id', 'N/A')}`\n")

        # 3. Detection Evidence
        md.append("## 3. Cryptographic & Behavioral Detection Evidence")
        evidence = self.detection_evidence
        md.append(f"- **Signature Valid:** {'✅ Valid' if evidence.get('signature_valid') else '❌ Invalid / Missing Signature'}")
        md.append(f"- **Hash Chain Continuity:** {'✅ Continuous' if evidence.get('hash_chain_valid') else '❌ Broken Hash Pointer'}")
        md.append(f"- **Independent Trust Anchor:** {'✅ Countersigned' if evidence.get('anchor_verified') else '❌ Unanchored / Mismatch'}")
        md.append(f"- **Clock Skew Detected:** `{evidence.get('timestamp_skew_seconds', 0.0):.4f} s`")
        md.append(f"- **Anomaly Suspicion Score:** `{evidence.get('suspicion_score', 0.0):.2f}`")
        if evidence.get("signals"):
            md.append("- **Triggered Anomaly Signals:**")
            for sig in evidence["signals"]:
                md.append(f"  - `{sig}`")
        md.append("")

        # 4. Modified Items & Unified Diff
        md.append("## 4. Tampered Memory Items & Content Diff")
        for item in self.modified_items:
            md.append(f"### Target Memory: `{item.get('memory_id')}` (Class: `{item.get('memory_class', 'POLICY')}`)")
            md.append(f"- **Pre-Attack Hash:** `{item.get('original_hash')}`")
            md.append(f"- **Tampered Hash:** `{item.get('tampered_hash')}`")
            md.append(f"- **Post-Recovery Hash:** `{item.get('recovered_hash')}`")
            md.append("\n```diff")
            md.append(item.get("content_diff", "No diff available."))
            md.append("```\n")

        # 5. Dependency Impact & Contagion Analysis
        md.append("## 5. Dependency Cascade & Blast Radius")
        impact = self.dependency_impact
        md.append(f"- **Primary Compromised Node:** `{impact.get('primary_node', 'N/A')}`")
        md.append(f"- **Blast Radius Score:** `{impact.get('blast_radius_score', 0.0):.2f}`")
        md.append(f"- **Direct Downstream Dependents:** {', '.join(f'`{d}`' for d in impact.get('direct_dependents', [])) or 'None'}")
        md.append(f"- **Transitive Dependents:** {', '.join(f'`{d}`' for d in impact.get('transitive_dependents', [])) or 'None'}")
        md.append(f"- **Quarantined Cascading Items:** {', '.join(f'`{q}`' for q in impact.get('quarantined_items', [])) or 'None'}\n")

        # 6. TCRP Recovery Decision Matrix
        md.append("## 6. TCRP Candidate Costs & Recovery Planning")
        tcrp = self.tcrp_decision
        md.append(f"- **Planner Selected Action:** `{tcrp.get('selected_action', 'ROLLBACK')}`")
        md.append(f"- **Decision Rationale:** {tcrp.get('rationale', 'Feasibility-constrained cost minimization')}")
        if tcrp.get("candidate_costs"):
            md.append("| Candidate Action | Evaluated Cost | Feasibility State |")
            md.append("|---|---|---|")
            for action, cost in tcrp["candidate_costs"].items():
                feas = "Feasible" if cost < 1.0 else "Infeasible (Unsafe)"
                md.append(f"| `{action}` | {cost:.4f} | {feas} |")
        md.append("")

        # 7. Recovery Ladder & Derived State Repair
        md.append("## 7. Recovery Ladder Execution & Derived State Repair")
        ladder = self.recovery_ladder_level
        md.append(f"- **Ladder Source Level:** Level {ladder.get('level', 1)}: `{ladder.get('level_name', 'N/A')}`")
        md.append(f"- **Restored Version:** v{ladder.get('restored_version', 1)}")
        md.append(f"- **Attestation Receipt:** `{ladder.get('attestation_id', 'N/A')}`")
        md.append(f"- **Total Recovery Latency:** `{ladder.get('time_to_recover_ms', 0.0):.2f} ms`")
        
        derived = self.derived_state_repair
        md.append("- **Purged Memory Gate Caches:** " + (", ".join(f"`{c}`" for c in derived.get("purged_cache_keys", [])) or "None"))
        md.append("- **Invalidated Response Templates:** " + (", ".join(f"`{t}`" for t in derived.get("invalidated_templates", [])) or "None"))
        md.append("- **Re-indexed Vector Embeddings:** " + (", ".join(f"`{e}`" for e in derived.get("reindexed_embeddings", [])) or "None"))
        md.append("")

        # 8. Forensic Chronological Timeline
        md.append("## 8. Chronological Event Timeline")
        md.append("| Time Offset | Event Type | Actor | Memory ID | Verified | Wrong Answer | Key Details |")
        md.append("|---|---|---|---|---|---|---|")
        t0 = None
        for ev in self.timeline:
            ts = ev.get("timestamp", 0.0)
            if t0 is None:
                t0 = ts
            dt = ts - t0
            verified_icon = "✅" if ev.get("verified", True) else "❌"
            wrong_icon = "⚠️ YES" if ev.get("wrong_answer_served", False) else "🛡️ 0"
            details_str = json.dumps(ev.get("details", {}))
            if len(details_str) > 40:
                details_str = details_str[:37] + "..."
            md.append(f"| +{dt:.4f}s | `{ev.get('event_type')}` | {ev.get('actor')} | `{ev.get('memory_id')}` | {verified_icon} | {wrong_icon} | {details_str} |")
        md.append("")

        # 9. Read Path Interception Log
        md.append("## 9. Read-Path Interception & Verification Log")
        if self.read_items:
            md.append("| Actor | Memory ID | Gate Decision | Verified | Safe Fallback | Wrong Answer Served |")
            md.append("|---|---|---|---|---|---|")
            for rd in self.read_items:
                dec = rd.get("gate_decision", "ALLOW")
                ver = "✅" if rd.get("verified", True) else "❌"
                fallback = "🛡️ Yes" if rd.get("safe_fallback_used") else "No"
                wrong = "⚠️ YES" if rd.get("wrong_answer_served") else "🛡️ 0"
                md.append(f"| {rd.get('actor')} | `{rd.get('memory_id')}` | `{dec}` | {ver} | {fallback} | {wrong} |")
        else:
            md.append("No active reads intercepted during the incident window.")
        md.append("")

        # 10. Post-Recovery Validation Sign-Off
        md.append("## 10. Post-Recovery Security Sign-Off")
        val = self.validation
        md.append(f"- **Hash Chain Integrity:** {'PASS ✅' if val.get('hash_chain_valid', True) else 'FAIL ❌'}")
        md.append(f"- **Anchor Countersignature:** {'PASS ✅' if val.get('anchor_countersigned', True) else 'FAIL ❌'}")
        md.append(f"- **Read-Path Gate Unblocked:** {'PASS ✅' if val.get('read_gate_verified', True) else 'FAIL ❌'}")
        md.append(f"- **Agent Answer Verification:** {'PASS ✅' if val.get('agent_answer_verified', True) else 'FAIL ❌'}")
        md.append(f"- **Final Certification:** `{val.get('status', 'RESOLVED_SECURE')}`")
        return "\n".join(md)

    def export_json(self, path: Optional[Path | str] = None) -> Path:
        """Exports the structured incident report to a JSON file."""
        if path is None:
            path = Path("data") / "incidents" / f"{self.incident_id}.json"
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return out_path

    def export_markdown(self, path: Optional[Path | str] = None) -> Path:
        """Exports the incident report to a Markdown dossier."""
        if path is None:
            path = Path("data") / "incidents" / f"{self.incident_id}.md"
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(self.to_markdown(), encoding="utf-8")
        return out_path

    def export_pdf(self, path: Optional[Path | str] = None) -> Path:
        """Exports the incident report to a clean, spec-compliant PDF document."""
        if path is None:
            path = Path("data") / "incidents" / f"{self.incident_id}.pdf"
        out_path = Path(path)
        
        # Build text lines for PDF printing
        raw_lines = []
        for line in self.to_markdown().splitlines():
            # Strip markdown formatting markers for clear Courier printing
            clean = (
                line.replace("#", "")
                .replace("**", "")
                .replace("`", "")
                .replace("---", "--------------------------------------------------------------------------------")
            )
            raw_lines.append(clean)
            
        return _render_minimal_pdf(raw_lines, out_path)


class IncidentManager:
    """Manages active and historical incident dossiers on disk."""

    def __init__(self, incidents_dir: Path | str = "data/incidents"):
        self.incidents_dir = Path(incidents_dir)
        self.incidents_dir.mkdir(parents=True, exist_ok=True)

    def save_incident(self, incident: IncidentReport) -> Dict[str, Path]:
        json_path = incident.export_json(self.incidents_dir / f"{incident.incident_id}.json")
        md_path = incident.export_markdown(self.incidents_dir / f"{incident.incident_id}.md")
        pdf_path = incident.export_pdf(self.incidents_dir / f"{incident.incident_id}.pdf")
        return {"json": json_path, "md": md_path, "pdf": pdf_path}

    def get_incident(self, incident_id: str) -> Optional[IncidentReport]:
        json_file = self.incidents_dir / f"{incident_id}.json"
        if not json_file.exists():
            return None
        data = json.loads(json_file.read_text(encoding="utf-8"))
        return IncidentReport(**data)

    def list_incidents(self) -> List[Dict[str, Any]]:
        results = []
        for json_file in sorted(self.incidents_dir.glob("*.json"), reverse=True):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                results.append({
                    "incident_id": data.get("incident_id"),
                    "title": data.get("title"),
                    "timestamp": data.get("timestamp"),
                    "status": data.get("status"),
                    "severity": data.get("severity"),
                    "severity_score": data.get("severity_score"),
                    "attacker": data.get("attacker", {}).get("actor"),
                    "exposure_count": data.get("exposure_count", 0),
                    "ladder_level": data.get("recovery_ladder_level", {}).get("level", 1),
                })
            except Exception as e:
                logger.warning(f"Could not load incident {json_file}: {e}")
        return results


_GLOBAL_INCIDENT_MANAGER: Optional[IncidentManager] = None


def get_incident_manager(incidents_dir: Path | str = "data/incidents") -> IncidentManager:
    global _GLOBAL_INCIDENT_MANAGER
    if _GLOBAL_INCIDENT_MANAGER is None:
        _GLOBAL_INCIDENT_MANAGER = IncidentManager(incidents_dir)
    return _GLOBAL_INCIDENT_MANAGER

