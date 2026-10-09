"""Exercise the real stdlib HTTP client against a local fake OpenAI-compatible server."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from threatlens.agent import ThreatLensAgent
from threatlens.llm import LLMConfig

EX = Path(__file__).resolve().parents[1] / "examples"


class Handler(BaseHTTPRequestHandler):
    calls = []

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Handler.calls.append({"auth": self.headers.get("Authorization"), "path": self.path, "body": body})
        if body.get("response_format"):            # free-text extraction request
            content = json.dumps({"name": "Tiny Shop", "components": [
                {"id": "u", "name": "Shopper", "type": "user", "zone": "internet"},
                {"id": "api", "name": "Shop API", "type": "api", "zone": "dmz", "data": ["pii", "payment"], "auth": "jwt", "internet_facing": True},
                {"id": "db", "name": "DB", "type": "database", "zone": "data", "data": ["pii"]}],
                "flows": [{"from": "u", "to": "api", "protocol": "https"}, {"from": "api", "to": "db", "protocol": "tcp", "data": ["pii"]}]})
            msg = {"role": "assistant", "content": content}
        elif len([c for c in Handler.calls if c["body"].get("tools")]) == 1:
            msg = {"role": "assistant", "content": "", "tool_calls": [
                {"id": "t1", "type": "function", "function": {"name": "parse_architecture", "arguments": "{}"}}]}
        else:
            msg = {"role": "assistant", "content": "Done."}
        out = json.dumps({"choices": [{"message": msg}], "usage": {"prompt_tokens": 10, "completion_tokens": 5}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


def test_http_llm_free_text(tmp_path, monkeypatch):
    for k in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(k, "127.0.0.1,localhost")
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = LLMConfig(api_key="test-key", base_url=f"http://127.0.0.1:{srv.server_port}/v1", model="gpt-oss:120b")
        agent = ThreatLensAgent(offline=False, llm_config=cfg)
        st = agent.build_state(text="Tiny shop with an API and a database")
        agent.run(st, output_dir=str(tmp_path))
    finally:
        srv.shutdown()
    assert Handler.calls, [t for t in st.trace if t.get("kind") == "note"]
    assert Handler.calls[0]["path"] == "/v1/chat/completions"
    assert Handler.calls[0]["auth"] == "Bearer test-key"
    assert st.arch.name == "Tiny Shop" and st.arch.source_kind == "text+llm"
    assert st.findings and Path(st.report_paths["markdown"]).exists()
    assert agent.client.usage["prompt_tokens"] > 0
