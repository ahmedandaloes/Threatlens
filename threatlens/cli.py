"""Command-line interface: python -m threatlens <input> [options]."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .agent import run_threat_model
from .llm import load_dotenv, resolve_config
from .report import summary_stats


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="threatlens", description="AI threat-modeling agent for SMEs (STRIDE + OWASP).")
    p.add_argument("input", nargs="?", help="Architecture YAML/JSON, free-text .txt/.md description, or OpenAPI file")
    p.add_argument("--text", help="Free-text system description (instead of / in addition to a file)")
    p.add_argument("--openapi", help="Optional OpenAPI 3 spec (YAML/JSON) for the backend API")
    p.add_argument("-o", "--output", default="threatlens_output", help="Output directory (default: threatlens_output)")
    p.add_argument("--offline", action="store_true", help="Force deterministic offline mode (no LLM / no network)")
    p.add_argument("-q", "--quiet", action="store_true", help="Do not print the agent trace")
    p.add_argument("--version", action="version", version=f"ThreatLens {__version__}")
    args = p.parse_args(argv)
    if not args.input and not args.text:
        p.error("give an input file or --text")
    load_dotenv()
    cfg = None if args.offline else resolve_config()
    mode = "offline (built-in STRIDE knowledge base)" if cfg is None else f"LLM via {cfg.provider} · {cfg.model} @ {cfg.base_url}"
    print(f"ThreatLens {__version__} — mode: {mode}")
    if args.input and not Path(args.input).exists():
        print(f"error: input file not found: {args.input}", file=sys.stderr)
        return 2
    state, agent = run_threat_model(args.input, text=args.text, openapi=args.openapi, output_dir=args.output,
                                    offline=cfg is None, verbose=not args.quiet)
    s = summary_stats(state)
    sev = s["by_severity"]
    print(f"\n✔ {s['system']}: {s['findings']} findings "
          f"(Critical {sev['Critical']}, High {sev['High']}, Medium {sev['Medium']}, Low {sev['Low']}) · "
          f"{s['remediation_actions']} remediation actions · {s['effort_days']} dev-days · "
          f"{sum(1 for t in state.trace if t.get('kind') == 'tool')} tool calls in {state.trace[-1]['elapsed_s']}s")
    if agent.summary:
        print("\nLLM summary:", agent.summary.strip())
    for k, v in state.report_paths.items():
        print(f"  {k:8s} {v}")
    return 0
