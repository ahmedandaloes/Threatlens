"""ThreatLens web UI — run with:  streamlit run app.py"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components
import yaml

from threatlens.agent import ThreatLensAgent
from threatlens.llm import load_dotenv, resolve_config
from threatlens.models import STRIDE
from threatlens.report import executive_summary, summary_stats

load_dotenv()
ROOT = Path(__file__).parent
EXAMPLES = {
    "🏥 Clinic booking (Egypt) — YAML": ("examples/clinic_booking.yaml", None),
    "🛍️ E-commerce + Paymob/Fawry (Egypt) — YAML + OpenAPI": ("examples/ecommerce_store.yaml", "examples/ecommerce_openapi.yaml"),
    "💼 HR & payroll portal (KSA) — JSON": ("examples/hr_payroll_portal.json", None),
    "💊 Pharmacy delivery (KSA) — free text": ("examples/pharmacy_delivery.txt", None),
}

st.set_page_config(page_title="ThreatLens — AI threat modeling for SMEs", page_icon="🛡️", layout="wide")
st.title("🛡️ ThreatLens")
st.caption("An AI agent that turns an app description into a STRIDE threat model, OWASP-mapped risks and a "
           "prioritised fix plan — in seconds instead of a 3–5 day consultant engagement.")

with st.sidebar:
    st.header("Settings")
    cfg = resolve_config()
    force_offline = st.toggle("Offline mode (no API key, deterministic)", value=cfg is None, disabled=cfg is None)
    if cfg is None:
        st.info("No OPENAI_API_KEY / OLLAMA_API_KEY found → offline rule-based mode.")
    else:
        st.success(f"LLM available: {cfg.provider} · `{cfg.model}`")
    st.markdown("---")
    st.markdown("**Input format** — see `examples/*.yaml`. Free text works too.")

src = st.radio("Input", ["Example", "Paste free text", "Upload YAML/JSON"], horizontal=True)
arch_input, text, openapi = None, None, None
if src == "Example":
    choice = st.selectbox("Example SME system", list(EXAMPLES))
    path, oa = EXAMPLES[choice]
    with st.expander("View input", expanded=False):
        st.code((ROOT / path).read_text(encoding="utf-8"), language="yaml" if not path.endswith(".txt") else None)
    if path.endswith(".txt"):
        text = (ROOT / path).read_text(encoding="utf-8")
    else:
        arch_input = str(ROOT / path)
    if oa:
        openapi = str(ROOT / oa)
elif src == "Paste free text":
    text = st.text_area("Describe your system (components, data, integrations, controls)", height=220,
                        placeholder="We run a Laravel API and a Flutter app for our clinic. Patients book and pay with Paymob…")
else:
    up = st.file_uploader("Architecture YAML/JSON", type=["yaml", "yml", "json"])
    if up:
        raw = up.read().decode("utf-8")
        arch_input = json.loads(raw) if up.name.endswith(".json") else yaml.safe_load(raw)
oa_up = st.file_uploader("Optional OpenAPI spec", type=["yaml", "yml", "json"])
if oa_up:
    raw = oa_up.read().decode("utf-8")
    openapi = json.loads(raw) if oa_up.name.endswith(".json") else yaml.safe_load(raw)

if st.button("Run threat model", type="primary", disabled=not (arch_input or (text and text.strip()))):
    out = tempfile.mkdtemp(prefix="threatlens_")
    with st.status("Agent working…", expanded=True) as status:
        agent = ThreatLensAgent(offline=force_offline or cfg is None)
        state = agent.build_state(arch_input, text=text, openapi=openapi)
        agent.run(state, output_dir=out)
        for t in state.trace:
            if t.get("kind") == "tool":
                st.write(f"`{t['tool']}` — {t.get('thought', '')}")
        status.update(label=f"Done in {state.trace[-1]['elapsed_s']}s · {len(state.findings)} findings", state="complete")
    st.session_state["result"] = (state, out, agent.summary)

if "result" in st.session_state:
    state, out, llm_summary = st.session_state["result"]
    s = summary_stats(state)
    c = st.columns(6)
    for col, (k, v) in zip(c, list(s["by_severity"].items()) + [("Findings", s["findings"]), ("Fix effort (dev-days)", s["effort_days"])]):
        col.metric(k, v)
    st.markdown(executive_summary(state))
    if llm_summary:
        st.info(llm_summary)
    tabs = st.tabs(["Findings", "Remediation plan", "Data-flow diagram", "Inventory", "Agent trace", "Download"])
    with tabs[0]:
        st.dataframe([{"ID": f.id, "Severity": f.severity, "Risk": f.risk, "STRIDE": STRIDE[f.stride], "Threat": f.title,
                       "OWASP": ", ".join(x.split(" ")[0] for x in f.owasp_top10), "CWE": ", ".join(f.cwe),
                       "ASVS": "; ".join(f.asvs)} for f in state.findings], use_container_width=True, hide_index=True)
        for f in state.findings[:10]:
            with st.expander(f"{f.id} · {f.severity} · {f.title}"):
                st.write(f.description)
                st.caption(f"Likelihood {f.likelihood} × Impact {f.impact} = {f.risk} · {'; '.join(f.owasp_top10)} · {', '.join(f.cwe)}")
    with tabs[1]:
        st.dataframe([{"#": i.priority, "Phase": i.phase, "Action": i.title, "Owner": i.owner, "Effort (days)": i.effort_days,
                       "Fixes": ", ".join(i.findings), "Risk removed": i.risk_reduced} for i in state.plan],
                     use_container_width=True, hide_index=True)
    with tabs[2]:
        components.html(f"""<pre class="mermaid">{state.diagram}</pre>
<script type="module">import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
mermaid.initialize({{startOnLoad:true}});</script>""", height=620, scrolling=True)
        st.code(state.diagram, language="text")
    with tabs[3]:
        st.json(state.inventory, expanded=False)
    with tabs[4]:
        st.dataframe([{"step": t.get("step"), "actor": t.get("actor", "agent"), "tool": t.get("tool", t.get("kind")),
                       "reasoning": t.get("thought", ""), "result": t.get("result", "")} for t in state.trace if t.get("kind")],
                     use_container_width=True, hide_index=True)
    with tabs[5]:
        for kind, p in state.report_paths.items():
            st.download_button(f"Download {kind}", Path(p).read_bytes(), file_name=Path(p).name, key=kind)
