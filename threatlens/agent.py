"""The ThreatLens agent loop: plan -> call tools -> reflect -> (repair) -> report.

Two planners drive the same tools:
* OfflinePlanner  – deterministic policy over the agent state (no network, no key).
* LLM planner     – an OpenAI-compatible model chooses tool calls (function calling),
                    may add context-specific threats, and the deterministic guardrail
                    completes anything the model skipped so the report is never partial.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .llm import LLMClient, LLMConfig, extract_architecture, resolve_config
from .parser import load_file
from .tools import TOOLS, AgentState, openai_tool_specs

MAX_STEPS = 60
MAX_REFLECTIONS = 2

SYSTEM_PROMPT = """You are ThreatLens, a senior application-security consultant agent.
Goal: produce a complete STRIDE threat model for a small/medium business system using the tools.
Workflow: parse_architecture -> enumerate_components -> stride_analyze_component for EVERY non-user component
(add 0-3 additional_threats per component ONLY when the system context reveals a specific risk the knowledge base
would miss, e.g. business-logic abuse; include stride letter, CWE and a concrete mitigation) -> analyze_data_flows ->
analyze_api_endpoints (if endpoints>0) -> analyze_system -> map_to_owasp -> score_risk -> reflect.
If reflect returns gaps, fix them and reflect again. Then build_remediation_plan -> render_diagram -> render_report.
Call one or more tools per turn. Be concise. When render_report has succeeded, reply with a 3-sentence executive summary."""


class ThreatLensAgent:
    def __init__(self, offline: bool | None = None, llm_config: LLMConfig | None = None,
                 client: Any = None, verbose: bool = False):
        self.verbose = verbose
        cfg = llm_config or (None if offline else resolve_config())
        self.client = client or (LLMClient(cfg) if cfg and not offline else None)
        self.offline = offline if offline is not None else self.client is None
        if self.offline:
            self.client = None
        self.summary = ""

    # ------------------------------------------------------------------ input
    @staticmethod
    def build_state(arch_input: str | dict | None = None, text: str | None = None,
                    openapi: str | dict | None = None) -> AgentState:
        st = AgentState()
        if isinstance(arch_input, dict):
            st.raw_input, st.input_kind = arch_input, "arch"
        elif arch_input:
            kind, payload = load_file(arch_input)
            if kind == "openapi":
                st.openapi = payload
                st.raw_input, st.input_kind = (text or payload.get("info", {}).get("description", "API")), "text"
            else:
                st.raw_input, st.input_kind = payload, kind
        elif text:
            st.raw_input, st.input_kind = text, "text"
        else:
            raise ValueError("Provide an architecture file/dict or a free-text description.")
        if text and st.input_kind == "arch":
            st.raw_input.setdefault("description", text)
        if openapi is not None and st.openapi is None:
            st.openapi = openapi if isinstance(openapi, dict) else load_file(openapi)[1]
        return st

    # ------------------------------------------------------------------ run
    def run(self, state: AgentState, output_dir: str = "threatlens_output") -> AgentState:
        self.output_dir = output_dir
        state.mode = "offline" if self.offline else f"llm:{self.client.cfg.model}" if hasattr(self.client, "cfg") else "llm"
        state.model = getattr(getattr(self.client, "cfg", None), "model", "") if self.client else "rule-based KB"
        t0 = time.perf_counter()
        self._log(state, "plan", thought=self._plan_text(state))
        if self.client:
            state.llm_extractor = lambda txt: extract_architecture(self.client, txt)
            try:
                self._run_llm(state)
            except Exception as e:  # noqa: BLE001
                self._log(state, "note", thought=f"LLM planner failed ({e}); deterministic guardrail takes over.")
        self._run_offline(state)          # completes whatever is left (all of it in offline mode)
        state.trace.append({"step": "done", "elapsed_s": round(time.perf_counter() - t0, 3)})
        return state

    def _plan_text(self, st: AgentState) -> str:
        return ("Plan: parse input -> inventory assets & trust boundaries -> STRIDE per component -> data flows"
                f"{' -> OpenAPI endpoints' if st.openapi else ''} -> system checks -> map OWASP/ASVS/CWE -> score risk"
                " -> reflect & repair gaps -> remediation plan -> DFD -> report.")

    # deterministic policy ------------------------------------------------
    def _next_action(self, st: AgentState) -> tuple[str, dict, str] | None:
        if st.arch is None:
            return "parse_architecture", {}, "Normalise the input into components and flows."
        if st.inventory is None:
            return "enumerate_components", {}, "Inventory assets, data classes and trust boundaries."
        for c in st.arch.components:
            if c.type != "user" and c.id not in st.analyzed_components:
                return "stride_analyze_component", {"component_id": c.id}, f"Apply STRIDE to {c.name} ({c.type})."
        if not st.flows_analyzed:
            return "analyze_data_flows", {}, "Check every data flow and boundary crossing."
        if st.arch.endpoints and not st.endpoints_analyzed:
            return "analyze_api_endpoints", {}, f"Review {len(st.arch.endpoints)} OpenAPI operations."
        if not st.system_analyzed:
            return "analyze_system", {}, "System-wide checks (secrets, monitoring, dependencies)."
        if any(not f.mapped for f in st.findings):
            return "map_to_owasp", {}, "Map findings to OWASP Top 10 / ASVS / CWE."
        if any(not f.scored for f in st.findings):
            return "score_risk", {}, "Score likelihood x impact."
        if not st.reflections or (not st.reflections[-1]["complete"] and len(st.reflections) < MAX_REFLECTIONS):
            return "reflect", {}, "Self-check coverage before writing the plan."
        if not st.plan:
            return "build_remediation_plan", {}, "Prioritise fixes by risk reduced per effort-day."
        if not st.diagram:
            return "render_diagram", {}, "Draw the data-flow diagram with trust boundaries."
        if not st.report_paths:
            return "render_report", {"output_dir": self.output_dir}, "Write Markdown/HTML/JSON report."
        return None

    def _run_offline(self, st: AgentState) -> None:
        for _ in range(MAX_STEPS):
            nxt = self._next_action(st)
            if nxt is None:
                return
            name, args, thought = nxt
            self._call(st, name, args, thought, actor="planner" if self.offline else "guardrail")
        raise RuntimeError("Agent exceeded MAX_STEPS")

    # LLM policy -----------------------------------------------------------
    def _run_llm(self, st: AgentState) -> None:
        sys_msg = SYSTEM_PROMPT
        user = "Threat-model this system. Input kind: " + st.input_kind + (
            "\n\n" + st.raw_input[:6000] if st.input_kind == "text" else
            "\n\n" + json.dumps(st.raw_input)[:6000])
        messages: list[dict] = [{"role": "system", "content": sys_msg}, {"role": "user", "content": user}]
        tools = openai_tool_specs()
        for _ in range(MAX_STEPS):
            msg = self.client.chat(messages, tools=tools)
            calls = msg.get("tool_calls") or []
            messages.append({"role": "assistant", "content": msg.get("content") or "", **({"tool_calls": calls} if calls else {})})
            if not calls:
                self.summary = msg.get("content") or ""
                return
            for tc in calls:
                fn = tc.get("function", {})
                name = fn.get("name", "")
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                if name == "render_report":
                    args["output_dir"] = self.output_dir
                if name not in TOOLS:
                    result = {"error": f"unknown tool {name}"}
                elif name == "render_report" and self._next_action(st)[0] != "render_report":
                    result = {"error": "Not ready. Missing step: " + self._next_action(st)[0]}
                else:
                    result = self._call(st, name, args, msg.get("content") or f"LLM chose {name}", actor="llm")
                messages.append({"role": "tool", "tool_call_id": tc.get("id", name), "name": name,
                                 "content": json.dumps(result, default=str)[:4000]})
            if st.report_paths:
                # one more turn for the executive summary
                try:
                    self.summary = self.client.chat(messages).get("content") or ""
                except Exception:  # noqa: BLE001
                    pass
                return

    # ---------------------------------------------------------------------
    def _call(self, st: AgentState, name: str, args: dict, thought: str, actor: str) -> dict:
        t = time.perf_counter()
        try:
            result = TOOLS[name]["fn"](st, **args)
        except Exception as e:  # noqa: BLE001
            result = {"error": f"{type(e).__name__}: {e}"}
        self._log(st, "tool", tool=name, args={k: v for k, v in args.items() if k != "additional_threats"} |
                  ({"additional_threats": len(args["additional_threats"])} if args.get("additional_threats") else {}),
                  thought=thought, actor=actor, result=_short(result), ms=round((time.perf_counter() - t) * 1000, 1))
        return result

    def _log(self, st: AgentState, kind: str, **kw) -> None:
        entry = {"step": len(st.trace) + 1, "kind": kind, **kw}
        st.trace.append(entry)
        if self.verbose:
            if kind == "tool":
                print(f"  [{entry['step']:02d}] {kw.get('actor')}: {kw['tool']}({_args(kw.get('args'))}) -> {kw.get('result')}")
            else:
                print(f"  [{entry['step']:02d}] {kind}: {kw.get('thought')}")


def _args(a: dict | None) -> str:
    return ", ".join(f"{k}={v}" for k, v in (a or {}).items())


def _short(r: Any) -> str:
    s = json.dumps(r, default=str, ensure_ascii=False)
    return s if len(s) <= 160 else s[:157] + "..."


def run_threat_model(arch_input: str | dict | None = None, text: str | None = None, openapi: str | dict | None = None,
                     output_dir: str = "threatlens_output", offline: bool | None = None,
                     verbose: bool = False) -> tuple[AgentState, ThreatLensAgent]:
    agent = ThreatLensAgent(offline=offline, verbose=verbose)
    state = agent.build_state(arch_input, text=text, openapi=openapi)
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    agent.run(state, output_dir=output_dir)
    return state, agent
