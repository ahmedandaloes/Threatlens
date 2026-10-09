"""ThreatLens web UI — run with:  streamlit run app.py"""
from __future__ import annotations

import html
import json
import os
import tempfile
from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components
import yaml

from threatlens.agent import ThreatLensAgent
from threatlens.llm import load_dotenv, resolve_config
from threatlens.models import STRIDE
from threatlens.report import summary_stats

load_dotenv()
ROOT = Path(__file__).parent
EXAMPLES = {
    "Clinic booking · Egypt": ("examples/clinic_booking.yaml", None, "🏥"),
    "Online store · Egypt": ("examples/ecommerce_store.yaml", "examples/ecommerce_openapi.yaml", "🛍️"),
    "HR & payroll · KSA": ("examples/hr_payroll_portal.json", None, "💼"),
    "Pharmacy delivery · KSA": ("examples/pharmacy_delivery.txt", None, "💊"),
}
SEV_COLOR = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#16a34a"}

st.set_page_config(page_title="ThreatLens — threat modeling for SMEs", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="collapsed")

st.markdown("""
<style>
#MainMenu, footer, header [data-testid="stToolbar"], [data-testid="stDecoration"] {visibility:hidden;}
.block-container {padding-top:1.2rem; max-width:1180px;}
html, body, [class*="css"] {font-family: Inter, "Segoe UI", system-ui, sans-serif;}
.tl-hero {background:linear-gradient(135deg,#0b1220 0%,#132347 60%,#1e3a8a 100%); border-radius:22px;
  padding:34px 40px; color:#e2e8f0; margin-bottom:22px; position:relative; overflow:hidden;}
.tl-hero:after {content:""; position:absolute; right:-80px; top:-80px; width:320px; height:320px;
  background:radial-gradient(circle,#3b82f655 0%,transparent 70%);}
.tl-brand {display:flex; align-items:center; gap:12px; font-size:30px; font-weight:800; color:#fff;}
.tl-pill {font-size:12px; font-weight:600; background:#ffffff1a; border:1px solid #ffffff33; color:#bfdbfe;
  padding:4px 10px; border-radius:99px; margin-left:8px;}
.tl-hero h1 {font-size:40px; line-height:1.15; color:#fff; margin:18px 0 8px; font-weight:800;}
.tl-hero p {font-size:17px; color:#cbd5e1; margin:0; max-width:720px;}
.tl-steps {display:flex; gap:12px; margin-top:22px; flex-wrap:wrap;}
.tl-step {background:#ffffff12; border:1px solid #ffffff22; border-radius:14px; padding:10px 16px; font-size:14px; color:#e2e8f0;}
.tl-step b {color:#93c5fd; margin-right:6px;}
.tl-h {font-size:22px; font-weight:800; color:#0f172a; margin:8px 0 2px; display:flex; align-items:center; gap:10px;}
.tl-num {background:#1e3a8a; color:#fff; width:30px; height:30px; border-radius:99px; display:inline-flex;
  align-items:center; justify-content:center; font-size:15px;}
.tl-sub {color:#64748b; font-size:14px; margin-bottom:10px;}
.tl-kpis {display:grid; grid-template-columns:repeat(6,1fr); gap:12px; margin:8px 0 18px;}
.tl-kpi {background:#fff; border:1px solid #e2e8f0; border-radius:16px; padding:16px 18px; box-shadow:0 1px 2px #0f172a0d;}
.tl-kpi .v {font-size:32px; font-weight:800; color:#0f172a; line-height:1.1;}
.tl-kpi .l {font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:#64748b; font-weight:700;}
.tl-kpi.sev {border-top:4px solid var(--c);} .tl-kpi.sev .v {color:var(--c);}
.tl-summary {background:#f1f5f9; border-radius:16px; padding:18px 22px; color:#0f172a; font-size:16px; line-height:1.55; margin-bottom:14px;}
.tl-card {background:#fff; border:1px solid #e2e8f0; border-left:5px solid var(--c); border-radius:14px;
  padding:14px 18px; margin-bottom:10px; box-shadow:0 1px 2px #0f172a0d;}
.tl-card .t {font-weight:700; font-size:16px; color:#0f172a;}
.tl-card .d {color:#334155; font-size:14px; margin:6px 0 8px; line-height:1.5;}
.tl-badge {display:inline-block; font-size:11px; font-weight:700; padding:3px 9px; border-radius:99px; margin-right:6px;
  background:#f1f5f9; color:#334155;}
.tl-badge.s {background:var(--c); color:#fff;}
.tl-fix {font-size:13px; color:#1e3a8a; background:#eff6ff; border-radius:10px; padding:8px 12px;}
.tl-phase {font-size:13px; font-weight:800; text-transform:uppercase; letter-spacing:.08em; color:#1e3a8a; margin:16px 0 8px;}
.tl-act {display:flex; gap:14px; align-items:center; background:#fff; border:1px solid #e2e8f0; border-radius:12px; padding:12px 16px; margin-bottom:8px;}
.tl-act .n {background:#1e3a8a; color:#fff; min-width:28px; height:28px; border-radius:99px; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:13px;}
.tl-act .a {flex:1; font-weight:600; color:#0f172a; font-size:15px;}
.tl-act .m {font-size:12px; color:#64748b; text-align:right; white-space:nowrap;}
.tl-trace {font-family:ui-monospace,Menlo,monospace; font-size:13px; background:#0b1220; color:#cbd5e1; border-radius:14px; padding:16px 18px; line-height:1.7;}
.tl-trace .k {color:#4ade80;}
div.stButton > button[kind="primary"] {background:#1e3a8a; border:0; border-radius:12px; padding:.7rem 1.6rem; font-weight:700; font-size:16px;}
div.stButton > button[kind="primary"]:hover {background:#1d4ed8;}
.stTabs [data-baseweb="tab-list"] {gap:6px;}
.stTabs [data-baseweb="tab"] {background:#f1f5f9; border-radius:10px; padding:8px 16px; font-weight:600;}
.stTabs [aria-selected="true"] {background:#1e3a8a !important; color:#fff !important;}
.stTabs [data-baseweb="tab-highlight"], .stTabs [data-baseweb="tab-border"] {display:none;}
</style>
""", unsafe_allow_html=True)

cfg = resolve_config()
mode_txt = f"LLM · {cfg.model}" if cfg else "Offline mode · no API key needed"
st.markdown(f"""
<div class="tl-hero">
  <div class="tl-brand">🛡️ ThreatLens <span class="tl-pill">{html.escape(mode_txt)}</span></div>
  <h1>Your app's threat model in seconds, not weeks.</h1>
  <p>Describe your system in plain words. ThreatLens finds the security risks, maps them to OWASP,
  and gives your team a prioritised fix plan.</p>
  <div class="tl-steps">
    <div class="tl-step"><b>1</b>Describe your app</div>
    <div class="tl-step"><b>2</b>Click Analyze</div>
    <div class="tl-step"><b>3</b>Get risks + fix plan</div>
  </div>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------- step 1: input
st.markdown('<div class="tl-h"><span class="tl-num">1</span>Describe your app</div>'
            '<div class="tl-sub">Pick the easiest way. A few sentences are enough.</div>', unsafe_allow_html=True)

arch_input, text, openapi = None, None, None
mode = st.segmented_control("How", ["✍️ Answer 6 questions", "📋 Paste a description", "⚡ Try an example", "📁 Upload YAML/JSON"],
                            default="⚡ Try an example", label_visibility="collapsed")

if mode == "✍️ Answer 6 questions":
    c1, c2 = st.columns(2)
    with c1:
        name = st.text_input("1 · App name and what it does", placeholder="Shifa Care — clinic booking for 6 branches")
        apps = st.multiselect("2 · What do users open?", ["Website", "Android/iOS app", "Admin dashboard"], default=["Website"])
        backend = st.text_input("3 · Backend and database", placeholder="Laravel API, MySQL, files on S3")
    with c2:
        data = st.multiselect("4 · What sensitive data do you keep?", ["Names, phones, addresses", "Passwords / OTP codes",
                              "Payment data", "Health records", "National ID / Iqama", "Salaries / bank details"],
                              default=["Names, phones, addresses", "Passwords / OTP codes"])
        third = st.text_input("5 · Third-party services", placeholder="Paymob payments, WhatsApp, Unifonic SMS")
        host = st.text_input("6 · Where is it hosted? (optional)", placeholder="AWS, one VPS, Cloudflare in front")
    if name and backend:
        parts = [f"{name}."]
        if apps:
            parts.append("Users access it through " + ", ".join(a.lower().replace("android/ios app", "an Android and iOS mobile app")
                                                           .replace("website", "a website").replace("admin dashboard", "a web admin dashboard")
                                                           for a in apps) + ".")
        parts.append(f"The backend is {backend}.")
        if data:
            parts.append("We store " + ", ".join(d.lower() for d in data) + ".")
        if third:
            parts.append(f"We integrate with {third}.")
        if host:
            parts.append(f"We host on {host}.")
        text = " ".join(parts)
        st.caption("ThreatLens will read: " + text)
elif mode == "📋 Paste a description":
    text = st.text_area("Your description", height=170, label_visibility="collapsed",
                        placeholder="Example: We run a Flutter app and a Laravel API for our clinic. Patients book and pay "
                                    "with Paymob, we store lab results in S3 and send WhatsApp reminders…")
elif mode == "📁 Upload YAML/JSON":
    up = st.file_uploader("Architecture YAML/JSON", type=["yaml", "yml", "json"])
    if up:
        raw = up.read().decode("utf-8")
        arch_input = json.loads(raw) if up.name.endswith(".json") else yaml.safe_load(raw)
    oa_up = st.file_uploader("Optional: OpenAPI spec for endpoint checks", type=["yaml", "yml", "json"])
    if oa_up:
        raw = oa_up.read().decode("utf-8")
        openapi = json.loads(raw) if oa_up.name.endswith(".json") else yaml.safe_load(raw)
else:
    choice = st.radio("Example", list(EXAMPLES), horizontal=True, label_visibility="collapsed",
                      format_func=lambda k: f"{EXAMPLES[k][2]} {k}")
    path, oa, _ = EXAMPLES[choice]
    raw = (ROOT / path).read_text(encoding="utf-8")
    with st.expander("See what this example describes"):
        st.code(raw, language=None if path.endswith(".txt") else "yaml")
    if path.endswith(".txt"):
        text = raw
    else:
        arch_input = str(ROOT / path)
    if oa:
        openapi = str(ROOT / oa)

# a new input clears old results so the page never mixes two systems
sig = (mode, text, str(arch_input), str(openapi))
if st.session_state.get("sig") != sig:
    st.session_state.pop("result", None)
    st.session_state["sig"] = sig

# ---------------------------------------------------------------- step 2: run
st.markdown('<div class="tl-h" style="margin-top:18px"><span class="tl-num">2</span>Analyze</div>', unsafe_allow_html=True)
ready = bool(arch_input or (text and text.strip()))
if st.button("🔍 Analyze my app", type="primary", disabled=not ready):
    out = tempfile.mkdtemp(prefix="threatlens_")
    with st.status("ThreatLens agent is working…", expanded=False) as status:
        agent = ThreatLensAgent(offline=cfg is None)
        state = agent.build_state(arch_input, text=text, openapi=openapi)
        agent.run(state, output_dir=out)
        status.update(label=f"Done in {state.trace[-1]['elapsed_s']}s · {len(state.findings)} risks found", state="complete")
    st.session_state["result"] = (state, out, agent.summary)
elif not ready:
    st.caption("Fill in step 1 first.")

# ---------------------------------------------------------------- step 3: results
if "result" in st.session_state:
    state, out, llm_summary = st.session_state["result"]
    s = summary_stats(state)
    st.markdown('<div class="tl-h" style="margin-top:22px"><span class="tl-num">3</span>Your results · '
                f'{html.escape(state.arch.name)}</div>', unsafe_allow_html=True)
    k = "".join(f'<div class="tl-kpi sev" style="--c:{SEV_COLOR[n]}"><div class="v">{v}</div><div class="l">{n}</div></div>'
                for n, v in s["by_severity"].items())
    k += f'<div class="tl-kpi"><div class="v">{s["findings"]}</div><div class="l">Risks found</div></div>'
    k += f'<div class="tl-kpi"><div class="v">{s["effort_days"]:g}</div><div class="l">Dev-days to fix</div></div>'
    st.markdown(f'<div class="tl-kpis">{k}</div>', unsafe_allow_html=True)
    top = state.findings[:3]
    st.markdown(f'<div class="tl-summary"><b>In short:</b> {s["components"]} components and {s["flows"]} data flows checked. '
                f'Fix these first: ' + "; ".join(f"<b>{html.escape(f.title.split(' — ')[0])}</b>" for f in top) +
                f'. Doing the first {sum(1 for i in state.plan if i.phase.startswith("Now"))} actions '
                f'(~{s["effort_now_days"]:g} dev-days) removes most of the risk.</div>', unsafe_allow_html=True)
    if llm_summary:
        st.info(llm_summary)

    tabs = st.tabs(["🚨 Top risks", "🛠️ Fix plan", "🗺️ Data-flow map", "🤖 How the agent worked", "⬇️ Download"])
    with tabs[0]:
        fix_for = {}
        for i in state.plan:
            for fid in i.findings:
                fix_for.setdefault(fid, i.title)
        show = len(state.findings) if st.toggle(f"Show all {len(state.findings)} risks") else min(8, len(state.findings))
        for f in state.findings[:show]:
            c = SEV_COLOR.get(f.severity, "#64748b")
            title, _, where = f.title.partition(" — ")
            fix = fix_for.get(f.id, "")
            st.markdown(f"""<div class="tl-card" style="--c:{c}">
<span class="tl-badge s" style="--c:{c}">{f.severity} · {f.risk}/25</span><span class="tl-badge">{f.id}</span>
<span class="tl-badge">{STRIDE[f.stride]}</span><span class="tl-badge">{html.escape(', '.join(x.split(' ')[0] for x in f.owasp_top10))}</span>
<span class="tl-badge">{html.escape(', '.join(f.cwe))}</span>
<div class="t" style="margin-top:8px">{html.escape(title)}{f' <span style="color:#64748b;font-weight:500">· {html.escape(where)}</span>' if where else ''}</div>
<div class="d">{html.escape(f.description)}</div>
{f'<div class="tl-fix">✅ <b>Fix:</b> {html.escape(fix)}</div>' if fix else ''}</div>""", unsafe_allow_html=True)
    with tabs[1]:
        for phase in dict.fromkeys(i.phase for i in state.plan):
            items = [i for i in state.plan if i.phase == phase]
            days = sum(i.effort_days for i in items)
            st.markdown(f'<div class="tl-phase">{html.escape(phase)} · {days:g} dev-days</div>', unsafe_allow_html=True)
            st.markdown("".join(f'<div class="tl-act"><div class="n">{i.priority}</div><div class="a">{html.escape(i.title)}</div>'
                                f'<div class="m">{html.escape(i.owner)} · {i.effort_days:g} d<br>fixes {html.escape(", ".join(i.findings[:4]))}'
                                f'{"…" if len(i.findings) > 4 else ""}</div></div>' for i in items), unsafe_allow_html=True)
    with tabs[2]:
        local_js = os.environ.get("THREATLENS_MERMAID_JS")
        js = f"<script>{Path(local_js).read_text()}</script>" if local_js else \
            '<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>'
        # render only once the tab is visible (a hidden iframe has zero width and mermaid draws nothing)
        js += """<script>mermaid.initialize({startOnLoad:false});
const go=()=>{if(document.body.clientWidth>0){mermaid.run();}else{setTimeout(go,200);}};go();</script>"""
        st.caption("Red = hot spots · dashed arrows = data sent without encryption")
        components.html(f'<pre class="mermaid">{state.diagram}</pre>{js}', height=640, scrolling=True)
    with tabs[3]:
        rows = [t for t in state.trace if t.get("kind") == "tool"]
        st.markdown('<div class="tl-trace">' + "<br>".join(
            f'<span class="k">{html.escape(t["tool"])}</span> — {html.escape(t.get("thought", ""))}' for t in rows) + "</div>",
            unsafe_allow_html=True)
    with tabs[4]:
        cols = st.columns(len(state.report_paths))
        for col, (kind, p) in zip(cols, state.report_paths.items()):
            col.download_button(f"⬇️ {kind.upper()}", Path(p).read_bytes(), file_name=Path(p).name, key=kind,
                                use_container_width=True)
