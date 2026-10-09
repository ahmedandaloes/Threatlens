"""Agent tools. Each tool reads/writes the shared AgentState and returns a
compact JSON-serialisable summary (what the LLM sees as the tool result)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from . import kb
from .models import (Architecture, Component, DATA_LABELS, Finding, RemediationItem, STRIDE, ZONE_LABELS)
from .parser import architecture_from_dict, architecture_from_text, endpoints_from_openapi


@dataclass
class AgentState:
    raw_input: Any = None
    input_kind: str = "arch"          # arch | text
    openapi: dict | None = None
    arch: Architecture | None = None
    inventory: dict | None = None
    analyzed_components: set = field(default_factory=set)
    flows_analyzed: bool = False
    endpoints_analyzed: bool = False
    system_analyzed: bool = False
    findings: list[Finding] = field(default_factory=list)
    reflections: list[dict] = field(default_factory=list)
    plan: list[RemediationItem] = field(default_factory=list)
    diagram: str = ""
    report_paths: dict = field(default_factory=dict)
    trace: list[dict] = field(default_factory=list)
    llm_extractor: Callable[[str], dict | None] | None = None
    mode: str = "offline"
    model: str = ""

    def _next_id(self) -> str:
        return f"TMP-{len(self.findings)+1:03d}"

    def add_finding(self, f: Finding) -> bool:
        key = (f.rule_id, f.target)
        if any((x.rule_id, x.target) == key for x in self.findings):
            return False
        self.findings.append(f)
        return True


def _fmt(rule: kb.Rule, **kw) -> str:
    try:
        return rule.description.format(**kw)
    except (KeyError, IndexError):
        return rule.description


def _data_str(data: list[str]) -> str:
    return ", ".join(DATA_LABELS.get(d, d) for d in data) or "business data"


# --------------------------------------------------------------------------
def parse_architecture(state: AgentState, **_) -> dict:
    """Normalise the input (YAML/JSON dict or free text) into an Architecture."""
    if state.input_kind == "text":
        arch = None
        if state.llm_extractor:
            try:
                d = state.llm_extractor(state.raw_input)
                if d:
                    arch = architecture_from_dict(d, source_kind="text+llm")
                    arch.assumptions.append("Architecture extracted from free text by the LLM; review components and flows.")
            except Exception as e:  # noqa: BLE001 - fall back to heuristics
                state.trace.append({"note": f"LLM extraction failed ({e}); using heuristic extractor"})
        state.arch = arch or architecture_from_text(state.raw_input)
    else:
        state.arch = architecture_from_dict(state.raw_input)
    if state.openapi:
        api = next((c for c in state.arch.components if c.type == "api"), None)
        state.arch.endpoints = endpoints_from_openapi(state.openapi, api.id if api else "")
    a = state.arch
    return {"system": a.name, "components": len(a.components), "flows": len(a.flows),
            "endpoints": len(a.endpoints), "source": a.source_kind,
            "component_ids": [c.id for c in a.components]}


def enumerate_components(state: AgentState, **_) -> dict:
    """Build asset & data-flow inventory and derive trust boundaries."""
    a = state.arch
    assets = []
    for c in a.components:
        assets.append({"id": c.id, "name": c.name, "type": c.type, "zone": c.zone, "tech": c.tech,
                       "data": c.data, "sensitivity": c.sensitivity, "internet_facing": c.internet_facing,
                       "auth": c.auth, "controls": c.controls})
    crossings = []
    for f in a.flows:
        s, t = a.component(f.source), a.component(f.target)
        if s and t and s.zone != t.zone:
            crossings.append({"flow": f.id, "from": s.id, "to": t.id, "boundary": f"{s.zone} -> {t.zone}",
                              "protocol": f.protocol, "data": f.data})
    zones = sorted({c.zone for c in a.components}, key=lambda z: list(ZONE_LABELS).index(z) if z in ZONE_LABELS else 99)
    crown = sorted([c for c in a.components if c.type in kb.STORES and c.sensitivity >= 4],
                   key=lambda c: -c.sensitivity)
    state.inventory = {
        "assets": assets,
        "trust_zones": [{"zone": z, "label": ZONE_LABELS.get(z, z), "members": [c.id for c in a.components if c.zone == z]}
                        for z in zones],
        "boundary_crossings": crossings,
        "crown_jewels": [c.id for c in crown],
        "data_classes": sorted({d for c in a.components for d in c.data}),
    }
    return {"assets": len(assets), "trust_zones": zones, "boundary_crossings": len(crossings),
            "crown_jewels": state.inventory["crown_jewels"]}


def _component_finding(state: AgentState, rule: kb.Rule, c: Component) -> Finding:
    lik = rule.likelihood + (1 if rule.internet_bonus and c.internet_facing else 0)
    return Finding(
        id=state._next_id(), rule_id=rule.id, title=f"{rule.title} — {c.name}", stride=rule.stride,
        target=c.id, target_kind="component",
        description=_fmt(rule, name=c.name, auth=c.auth, data=_data_str(c.data)),
        cwe=list(rule.cwe), asvs=list(rule.asvs), likelihood=min(lik, 5),
        impact=max(1, (rule.impact or c.sensitivity) + rule.impact_delta), mitigations=list(rule.mitigations),
        evidence=f"type={c.type}, zone={c.zone}, auth={c.auth}, controls={c.controls or 'none documented'}",
    )


def stride_analyze_component(state: AgentState, component_id: str = "", additional_threats: list | None = None, **_) -> dict:
    """Run STRIDE rules from the knowledge base against one component.
    `additional_threats` lets an LLM contribute context-specific threats."""
    a = state.arch
    c = a.component(component_id)
    if not c:
        return {"error": f"unknown component '{component_id}'", "valid_ids": [x.id for x in a.components]}
    new = []
    if c.type != "user":
        for rule in kb.COMPONENT_RULES:
            try:
                ok = rule.applies(c, a)
            except Exception:  # noqa: BLE001
                ok = False
            if ok:
                f = _component_finding(state, rule, c)
                if state.add_finding(f):
                    new.append(f)
    for t in additional_threats or []:
        f = _llm_threat(state, c, t)
        if f and state.add_finding(f):
            new.append(f)
    state.analyzed_components.add(c.id)
    return {"component": c.id, "new_findings": [{"id": f.id, "stride": f.stride, "title": f.title} for f in new],
            "stride_covered": sorted({f.stride for f in new})}


def _llm_threat(state: AgentState, c: Component, t: dict) -> Finding | None:
    if not isinstance(t, dict) or not t.get("title"):
        return None
    stride = str(t.get("stride", "T"))[:1].upper()
    if stride not in STRIDE:
        stride = "T"
    cwes = [x.upper() if x.upper().startswith("CWE-") else f"CWE-{x}" for x in
            re.findall(r"\d+", str(t.get("cwe", "")))][:3]
    mit = t.get("mitigation") or "Review and implement a compensating control."
    key = "llm_" + re.sub(r"[^a-z0-9]+", "_", str(t["title"]).lower())[:40]
    kb.MITIGATIONS.setdefault(key, dict(title=str(mit)[:120], detail=str(mit), effort=float(t.get("effort_days", 2) or 2),
                                        owner="Engineering"))
    return Finding(id=state._next_id(), rule_id=key, title=f"{t['title']} — {c.name}", stride=stride, target=c.id,
                   target_kind="component", description=str(t.get("description", t["title"])), cwe=cwes,
                   likelihood=max(1, min(5, int(t.get("likelihood", 3) or 3))), impact=c.sensitivity,
                   mitigations=[key], evidence="Proposed by LLM from system context", source="llm")


def analyze_data_flows(state: AgentState, **_) -> dict:
    """Apply flow rules (cleartext, unauthenticated boundary crossing, webhooks, exposed data stores)."""
    a = state.arch
    new = []
    for f in a.flows:
        s, t = a.component(f.source), a.component(f.target)
        if not s or not t:
            continue
        for rule in kb.FLOW_RULES:
            if rule.applies(f, s, t, a):
                crosses = s.zone != t.zone
                lik = rule.likelihood + (1 if crosses and s.zone in ("internet", "third_party") else 0)
                finding = Finding(
                    id=state._next_id(), rule_id=rule.id, title=f"{rule.title} — {s.name} → {t.name}",
                    stride=rule.stride, target=f.id, target_kind="flow",
                    description=_fmt(rule, src=s.name, dst=t.name, protocol=f.protocol.upper(), data=_data_str(f.data),
                                     szone=s.zone, tzone=t.zone),
                    cwe=list(rule.cwe), asvs=list(rule.asvs), likelihood=min(lik, 5),
                    impact=rule.impact or max(f.sensitivity, t.sensitivity if rule.id == "F-04" else 0),
                    mitigations=list(rule.mitigations),
                    evidence=f"{f.id}: {f.protocol} auth={f.auth} {s.zone}->{t.zone}")
                if state.add_finding(finding):
                    new.append(finding)
    state.flows_analyzed = True
    return {"flows_checked": len(a.flows), "new_findings": [{"id": f.id, "title": f.title} for f in new]}


def analyze_api_endpoints(state: AgentState, **_) -> dict:
    """Apply OpenAPI rules. Endpoints are grouped per rule into one finding."""
    a = state.arch
    new = []
    api = a.component(a.endpoints[0].component) if a.endpoints else None
    for rule in kb.ENDPOINT_RULES:
        hits = [e for e in a.endpoints if rule.applies(e)]
        if not hits:
            continue
        listed = ", ".join(f"`{e.method} {e.path}`" for e in hits[:8]) + (f" (+{len(hits)-8} more)" if len(hits) > 8 else "")
        target = api.id if api else "system"
        f = Finding(id=state._next_id(), rule_id=rule.id, title=f"{rule.title} ({len(hits)} endpoint{'s' if len(hits)>1 else ''})",
                    stride=rule.stride, target=target, target_kind="endpoint",
                    description=_fmt(rule, endpoints=listed), cwe=list(rule.cwe), asvs=list(rule.asvs),
                    likelihood=min(rule.likelihood + (1 if api and api.internet_facing else 0), 5),
                    impact=rule.impact or (api.sensitivity if api else 3), mitigations=list(rule.mitigations),
                    evidence=f"OpenAPI: {len(hits)} matching operations")
        if state.add_finding(f):
            new.append(f)
    state.endpoints_analyzed = True
    return {"endpoints_checked": len(a.endpoints), "new_findings": [{"id": f.id, "title": f.title} for f in new]}


def analyze_system(state: AgentState, **_) -> dict:
    """System-wide rules (secrets, monitoring, dependencies)."""
    a = state.arch
    new = []
    for rule in kb.SYSTEM_RULES:
        if rule.applies(a):
            f = Finding(id=state._next_id(), rule_id=rule.id, title=rule.title, stride=rule.stride, target="system",
                        target_kind="system", description=rule.description, cwe=list(rule.cwe), asvs=list(rule.asvs),
                        likelihood=rule.likelihood, impact=rule.impact or 4, mitigations=list(rule.mitigations),
                        evidence=f"global_controls={a.global_controls or 'none documented'}")
            if state.add_finding(f):
                new.append(f)
    state.system_analyzed = True
    return {"new_findings": [{"id": f.id, "title": f.title} for f in new]}


def map_to_owasp(state: AgentState, **_) -> dict:
    """Map every finding to OWASP Top 10 2021 (via CWE) and ASVS 4.0.3 sections."""
    n = 0
    for f in state.findings:
        if f.mapped:
            continue
        f.owasp_top10 = kb.top10_for(f.cwe)
        if not f.asvs:
            f.asvs = ["V1.1 Secure Software Development Lifecycle"]
        f.mapped = True
        n += 1
    return {"mapped": n, "total": len(state.findings)}


def severity_for(risk: int) -> str:
    if risk >= 20:
        return "Critical"
    if risk >= 12:
        return "High"
    if risk >= 6:
        return "Medium"
    return "Low"


def score_risk(state: AgentState, **_) -> dict:
    """Risk = likelihood (1-5) x impact (1-5); renumber findings by risk."""
    for f in state.findings:
        f.likelihood = max(1, min(5, int(f.likelihood)))
        f.impact = max(1, min(5, int(f.impact)))
        f.risk = f.likelihood * f.impact
        f.severity = severity_for(f.risk)
        f.scored = True
    order = {"S": 0, "T": 1, "R": 2, "I": 3, "D": 4, "E": 5}
    state.findings.sort(key=lambda f: (-f.risk, order.get(f.stride, 9), f.rule_id, f.target))
    for i, f in enumerate(state.findings, 1):
        f.id = f"TL-{i:03d}"
    counts = {s: sum(1 for f in state.findings if f.severity == s) for s in ("Critical", "High", "Medium", "Low")}
    return {"scored": len(state.findings), "by_severity": counts,
            "top": [{"id": f.id, "risk": f.risk, "title": f.title} for f in state.findings[:5]]}


def reflect(state: AgentState, **_) -> dict:
    """Self-check: coverage of components, flows, STRIDE categories, mapping & scoring."""
    a = state.arch
    gaps, notes = [], []
    missing = [c.id for c in a.components if c.type != "user" and c.id not in state.analyzed_components]
    if missing:
        gaps.append({"type": "unanalyzed_components", "ids": missing})
    if not state.flows_analyzed and a.flows:
        gaps.append({"type": "flows_not_analyzed"})
    if a.endpoints and not state.endpoints_analyzed:
        gaps.append({"type": "endpoints_not_analyzed"})
    if not state.system_analyzed:
        gaps.append({"type": "system_rules_not_run"})
    if any(not f.mapped for f in state.findings):
        gaps.append({"type": "unmapped_findings"})
    if any(not f.scored for f in state.findings):
        gaps.append({"type": "unscored_findings"})
    covered = {f.stride for f in state.findings}
    for k, v in STRIDE.items():
        if k not in covered:
            notes.append(f"No {v} threats found. Verify the documented controls are really in place.")
    if state.inventory:
        for cj in state.inventory["crown_jewels"]:
            if not any(f.target == cj for f in state.findings):
                notes.append(f"Crown-jewel store '{cj}' has no findings; confirm its controls with evidence.")
    if not a.flows:
        notes.append("No data flows supplied; boundary analysis is limited.")
    undocumented = [c.name for c in a.components if c.type not in ("user", "third_party") and not c.controls]
    if undocumented:
        notes.append("No controls documented for: " + ", ".join(undocumented) + ". Conservative assumptions were applied.")
    r = {"iteration": len(state.reflections) + 1, "gaps": gaps, "notes": notes, "complete": not gaps}
    state.reflections.append(r)
    return r


def build_remediation_plan(state: AgentState, **_) -> dict:
    """Group findings by mitigation, prioritise by risk reduced per effort-day, phase into Now/Next/Later."""
    groups: dict[str, list[Finding]] = {}
    for f in state.findings:
        for m in f.mitigations:
            groups.setdefault(m, []).append(f)
    items = []
    for key, fs in groups.items():
        m = kb.MITIGATIONS.get(key, dict(title=key, detail="", effort=2, owner="Engineering"))
        max_risk = max(f.risk for f in fs)
        total = sum(f.risk for f in fs)
        effort = float(m["effort"])
        if max_risk >= 20 or (max_risk >= 12 and effort <= 2):
            phase = "Now (0-2 weeks)"
        elif max_risk >= 12 or (max_risk >= 6 and effort <= 1):
            phase = "Next (30 days)"
        else:
            phase = "Later (90 days)"
        items.append(RemediationItem(key=key, title=m["title"], detail=m["detail"], effort_days=effort,
                                     owner=m["owner"], phase=phase, priority=0,
                                     findings=sorted({f.id for f in fs}), risk_reduced=total))
    phase_rank = {"Now (0-2 weeks)": 0, "Next (30 days)": 1, "Later (90 days)": 2}
    maxrisk = {k: max(f.risk for f in fs) for k, fs in groups.items()}
    items.sort(key=lambda i: (phase_rank[i.phase], -maxrisk[i.key], -(i.risk_reduced / max(i.effort_days, 0.5))))
    for n, i in enumerate(items, 1):
        i.priority = n
    state.plan = items
    by_phase = {p: round(sum(i.effort_days for i in items if i.phase == p), 1) for p in phase_rank}
    return {"actions": len(items), "effort_days_by_phase": by_phase,
            "total_effort_days": round(sum(i.effort_days for i in items), 1),
            "first_actions": [i.title for i in items[:3]]}


_SHAPES = {
    "user": ('["👤 {}"]', "actor"), "web_frontend": ('("{}")', "proc"), "mobile_app": ('("{}")', "proc"),
    "api": ('("{}")', "proc"), "service": ('("{}")', "proc"), "admin_panel": ('("{}")', "proc"),
    "database": ('[("{}")]', "store"), "object_storage": ('[("{}")]', "store"), "cache": ('[("{}")]', "store"),
    "queue": ('[/"{}"/]', "store"), "identity_provider": ('{{{{"{}"}}}}', "ext"), "third_party": ('{{{{"{}"}}}}', "ext"),
}


def _nid(cid: str) -> str:
    return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", cid)


def _m(s: str) -> str:
    return s.replace('"', "'").replace("\n", " ")


def render_diagram(state: AgentState, **_) -> dict:
    """Mermaid data-flow diagram with one subgraph per trust zone."""
    a = state.arch
    worst: dict[str, str] = {}
    rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    flow_target = {f.id: f.target for f in a.flows}
    for f in state.findings:
        tgt = flow_target.get(f.target, f.target)
        if rank.get(f.severity, 0) > rank.get(worst.get(tgt, ""), 0):
            worst[tgt] = f.severity
    lines = ["flowchart LR"]
    for zone in [z for z in ZONE_LABELS if any(c.zone == z for c in a.components)]:
        lines.append(f'  subgraph z_{zone}["{ZONE_LABELS[zone]}"]')
        for c in a.components:
            if c.zone == zone:
                shape, _ = _SHAPES.get(c.type, ('("{}")', "proc"))
                label = _m(c.name + (f"<br/><small>{c.tech}</small>" if c.tech else ""))
                lines.append(f"    {_nid(c.id)}{shape.format(label)}")
        lines.append("  end")
    for f in a.flows:
        data = ",".join(f.data[:3])
        label = _m(f"{f.id} {f.protocol.upper()}" + (f" · {data}" if data else ""))
        arrow = "-.->" if f.protocol.lower() in ("http", "ftp", "tcp", "smtp", "ws", "mqtt") else "-->"
        lines.append(f'  {_nid(f.source)} {arrow}|"{label}"| {_nid(f.target)}')
    lines += ["  classDef critical fill:#fde2e1,stroke:#c0392b,stroke-width:2px",
              "  classDef high fill:#fff1db,stroke:#e67e22,stroke-width:2px",
              "  classDef medium fill:#fffbe0,stroke:#c9a400"]
    for sev in ("Critical", "High", "Medium"):
        ids = [cid for cid, s in worst.items() if s == sev and a.component(cid)]
        if ids:
            lines.append(f"  class {','.join(_nid(i) for i in ids)} {sev.lower()}")
    state.diagram = "\n".join(lines)
    return {"lines": len(lines), "highlighted": len(worst)}


def render_report(state: AgentState, output_dir: str = "threatlens_output", **_) -> dict:
    """Write Markdown, HTML, JSON and Mermaid outputs."""
    from .report import write_reports
    state.report_paths = write_reports(state, output_dir)
    return {"written": state.report_paths}


# --------------------------------------------------------------------------
TOOLS: dict[str, dict] = {
    "parse_architecture": {"fn": parse_architecture, "description": "Parse and normalise the provided system description into components and data flows. Call first.", "params": {}},
    "enumerate_components": {"fn": enumerate_components, "description": "Build the asset & data-flow inventory, trust zones, boundary crossings and crown-jewel data stores.", "params": {}},
    "stride_analyze_component": {"fn": stride_analyze_component, "description": "Run the STRIDE knowledge base against ONE component. Optionally add context-specific threats the knowledge base may miss.",
                                 "params": {"component_id": {"type": "string", "description": "Component id from parse_architecture"},
                                            "additional_threats": {"type": "array", "description": "Optional extra threats you identified for this component",
                                                                   "items": {"type": "object", "properties": {
                                                                       "title": {"type": "string"}, "stride": {"type": "string", "description": "One of S,T,R,I,D,E"},
                                                                       "description": {"type": "string"}, "cwe": {"type": "string"},
                                                                       "likelihood": {"type": "integer"}, "mitigation": {"type": "string"},
                                                                       "effort_days": {"type": "number"}}, "required": ["title", "stride"]}}},
                                 "required": ["component_id"]},
    "analyze_data_flows": {"fn": analyze_data_flows, "description": "Analyse all data flows for cleartext transport, unauthenticated trust-boundary crossings, forged webhooks and exposed data stores.", "params": {}},
    "analyze_api_endpoints": {"fn": analyze_api_endpoints, "description": "Analyse OpenAPI operations (only if endpoints > 0).", "params": {}},
    "analyze_system": {"fn": analyze_system, "description": "Run system-wide checks: secrets management, monitoring, dependency scanning.", "params": {}},
    "map_to_owasp": {"fn": map_to_owasp, "description": "Map all findings to OWASP Top 10 2021, OWASP ASVS 4.0.3 and CWE.", "params": {}},
    "score_risk": {"fn": score_risk, "description": "Score every finding: risk = likelihood x impact (1-25) and assign severity.", "params": {}},
    "reflect": {"fn": reflect, "description": "Self-check coverage and quality. Returns gaps that must be fixed before reporting.", "params": {}},
    "build_remediation_plan": {"fn": build_remediation_plan, "description": "Create the prioritised remediation plan with effort estimates.", "params": {}},
    "render_diagram": {"fn": render_diagram, "description": "Generate the Mermaid data-flow diagram.", "params": {}},
    "render_report": {"fn": render_report, "description": "Write the final Markdown + HTML + JSON report. Call last.", "params": {}},
}


def openai_tool_specs() -> list[dict]:
    specs = []
    for name, t in TOOLS.items():
        props = dict(t["params"])
        specs.append({"type": "function", "function": {
            "name": name, "description": t["description"],
            "parameters": {"type": "object", "properties": {k: v for k, v in props.items() if k != "required"},
                           "required": props.get("required", [])}}})
    return specs
