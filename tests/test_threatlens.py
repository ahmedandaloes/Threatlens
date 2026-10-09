import json
from pathlib import Path

import pytest

from threatlens import kb
from threatlens.agent import ThreatLensAgent, run_threat_model
from threatlens.cli import main as cli_main
from threatlens.llm import resolve_config, OLLAMA_CLOUD_URL, OLLAMA_DEFAULT_MODEL
from threatlens.parser import architecture_from_text, load_file
from threatlens.tools import severity_for

EX = Path(__file__).resolve().parents[1] / "examples"


def _run(name, tmp_path, **kw):
    state, _ = run_threat_model(str(EX / name), output_dir=str(tmp_path), offline=True, **kw)
    return state


def test_clinic_offline_full_report(tmp_path):
    st = _run("clinic_booking.yaml", tmp_path)
    assert len(st.findings) >= 20
    assert {f.stride for f in st.findings} == set("STRIDE")          # all six STRIDE categories
    assert all(f.mapped and f.scored and f.owasp_top10 and f.cwe for f in st.findings)
    assert any(f.rule_id == "F-03" for f in st.findings)              # forged Paymob callback
    assert any(f.rule_id == "I-03" for f in st.findings)              # IDOR on patient records
    for kind in ("markdown", "html", "json", "mermaid"):
        assert Path(st.report_paths[kind]).exists()
    md = Path(st.report_paths["markdown"]).read_text()
    assert "```mermaid" in md and "remediation plan" in md and "A01:2021" in md
    data = json.loads(Path(st.report_paths["json"]).read_text())
    assert data["summary"]["findings"] == len(st.findings)


def test_findings_sorted_and_risk_math(tmp_path):
    st = _run("hr_payroll_portal.json", tmp_path)
    risks = [f.risk for f in st.findings]
    assert risks == sorted(risks, reverse=True)
    for f in st.findings:
        assert f.risk == f.likelihood * f.impact and 1 <= f.risk <= 25
        assert f.severity == severity_for(f.risk)
    assert severity_for(25) == "Critical" and severity_for(12) == "High" and severity_for(6) == "Medium" and severity_for(5) == "Low"


def test_controls_reduce_findings(tmp_path):
    """Documented controls must suppress the matching threats (HR portal has MFA via SSO + RBAC)."""
    st = _run("hr_payroll_portal.json", tmp_path)
    ids = {(f.rule_id, f.target) for f in st.findings}
    assert ("S-03", "hr_admin") not in ids       # admin has MFA
    assert ("E-01", "api") not in ids            # api has RBAC
    assert ("F-01", "F12") in ids                # legacy HTTP attendance feed is flagged


def test_openapi_endpoint_analysis(tmp_path):
    st = _run("ecommerce_store.yaml", tmp_path, openapi=str(EX / "ecommerce_openapi.yaml"))
    rules = {f.rule_id: f for f in st.findings}
    assert "API-02" in rules and "{orderId}" in rules["API-02"].description   # BOLA candidates
    assert "API-04" in rules                                                   # unsigned callbacks
    assert "/admin/export/customers" in rules["API-01"].description           # unauthenticated admin export


def test_free_text_heuristic_extraction(tmp_path):
    kind, text = load_file(EX / "pharmacy_delivery.txt")
    assert kind == "text"
    arch = architecture_from_text(text)
    types = {c.type for c in arch.components}
    assert {"mobile_app", "api", "database", "admin_panel", "third_party"} <= types
    assert "waf" in arch.global_controls                                       # "Cloudflare" detected
    st = _run("pharmacy_delivery.txt", tmp_path)
    assert any("Moyasar" in f.title for f in st.findings)


def test_remediation_plan_phases(tmp_path):
    st = _run("clinic_booking.yaml", tmp_path)
    assert st.plan and st.plan[0].phase.startswith("Now")
    covered = {fid for i in st.plan for fid in i.findings}
    assert covered == {f.id for f in st.findings}                             # every finding has a fix
    assert all(i.effort_days > 0 for i in st.plan)


def test_ollama_cloud_alias():
    cfg = resolve_config({"OLLAMA_API_KEY": "x"})
    assert cfg.base_url == OLLAMA_CLOUD_URL and cfg.model == OLLAMA_DEFAULT_MODEL and cfg.provider == "ollama-cloud"
    cfg = resolve_config({"OPENAI_API_KEY": "k", "OPENAI_BASE_URL": "https://ollama.com/v1", "MODEL": "qwen3-coder:480b"})
    assert cfg.provider == "ollama-cloud" and cfg.model == "qwen3-coder:480b"
    assert resolve_config({}) is None


class FakeLLM:
    """Scripted OpenAI-style client: exercises the real LLM tool-calling loop without network."""
    class cfg:  # noqa: N801
        model = "fake-model"

    def __init__(self):
        self.turn = 0

    def _call(self, name, args=None):
        return {"id": f"c{self.turn}_{name}", "type": "function",
                "function": {"name": name, "arguments": json.dumps(args or {})}}

    def chat(self, messages, tools=None, json_mode=False, temperature=0.2):
        self.turn += 1
        script = {
            1: [self._call("parse_architecture"), self._call("enumerate_components")],
            2: [self._call("stride_analyze_component", {"component_id": "api", "additional_threats": [
                {"title": "Appointment slot hoarding by bots", "stride": "D", "cwe": "CWE-799",
                 "description": "Bots book and hold all slots of popular doctors.", "mitigation": "Deposit + per-patient booking limits",
                 "likelihood": 4}]})],
            3: [self._call("render_report")],     # premature: guardrail must refuse
        }
        if self.turn in script:
            return {"content": "", "tool_calls": script[self.turn]}
        return {"content": "Summary: done."}


def test_llm_agent_loop_with_guardrail(tmp_path):
    agent = ThreatLensAgent(offline=False, client=FakeLLM())
    st = agent.build_state(str(EX / "clinic_booking.yaml"))
    agent.run(st, output_dir=str(tmp_path))
    actors = {t.get("actor") for t in st.trace if t.get("kind") == "tool"}
    assert {"llm", "guardrail"} <= actors                      # LLM drove, guardrail completed
    assert any(f.source == "llm" and f.stride == "D" for f in st.findings)
    assert Path(st.report_paths["html"]).exists()
    assert st.mode.startswith("llm")


def test_cli(tmp_path, capsys):
    assert cli_main([str(EX / "clinic_booking.yaml"), "--offline", "-q", "-o", str(tmp_path)]) == 0
    assert "findings" in capsys.readouterr().out


def test_kb_mappings_consistent():
    for r in kb.all_rules():
        assert r.stride in "STRIDE"
        for m in r.mitigations:
            assert m in kb.MITIGATIONS, (r.id, m)
        assert kb.top10_for(r.cwe)
