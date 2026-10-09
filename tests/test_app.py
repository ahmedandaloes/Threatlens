"""Smoke-test the Streamlit UI headlessly (no browser) with Streamlit's AppTest."""
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

APP = str(Path(__file__).resolve().parents[1] / "app.py")


def test_app_runs_example_end_to_end(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    at.button[0].click().run()
    assert not at.exception
    state = at.session_state["result"][0]
    assert len(state.findings) > 10
    assert any("Risks found" in m.value for m in at.markdown)
