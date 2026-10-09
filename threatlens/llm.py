"""Minimal OpenAI-compatible chat client (stdlib only, no SDK required).

Works with any provider exposing /chat/completions with tool calling:
OpenAI, Ollama Cloud (https://ollama.com/v1), OpenRouter, Groq, Together,
a local Ollama / vLLM / LM Studio server, etc.

Resolution order:
  OPENAI_API_KEY  -> OPENAI_BASE_URL (default https://api.openai.com/v1), MODEL (default gpt-4o-mini)
  OLLAMA_API_KEY  -> OPENAI_BASE_URL or OLLAMA_BASE_URL (default https://ollama.com/v1), MODEL (default gpt-oss:120b)
No key at all     -> offline deterministic mode.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

OPENAI_DEFAULT_URL = "https://api.openai.com/v1"
OPENAI_DEFAULT_MODEL = "gpt-4o-mini"
OLLAMA_CLOUD_URL = "https://ollama.com/v1"
OLLAMA_DEFAULT_MODEL = "gpt-oss:120b"


@dataclass
class LLMConfig:
    api_key: str
    base_url: str
    model: str
    provider: str = "openai-compatible"
    timeout: int = 120


def load_dotenv(path: str = ".env") -> None:
    """Tiny .env loader (does not override existing env vars)."""
    if not os.path.exists(path):
        return
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def resolve_config(env: dict | None = None) -> LLMConfig | None:
    env = dict(os.environ if env is None else env)
    model = env.get("MODEL") or env.get("THREATLENS_MODEL") or ""
    if env.get("OPENAI_API_KEY"):
        base = env.get("OPENAI_BASE_URL") or OPENAI_DEFAULT_URL
        is_ollama = "ollama" in base
        return LLMConfig(api_key=env["OPENAI_API_KEY"], base_url=base.rstrip("/"),
                         model=model or (OLLAMA_DEFAULT_MODEL if is_ollama else OPENAI_DEFAULT_MODEL),
                         provider="ollama-cloud" if "ollama.com" in base else _provider(base))
    if env.get("OLLAMA_API_KEY"):
        base = env.get("OPENAI_BASE_URL") or env.get("OLLAMA_BASE_URL") or OLLAMA_CLOUD_URL
        return LLMConfig(api_key=env["OLLAMA_API_KEY"], base_url=base.rstrip("/"),
                         model=model or OLLAMA_DEFAULT_MODEL, provider="ollama-cloud")
    return None


def _provider(base: str) -> str:
    for k in ("openrouter", "groq", "together", "openai", "localhost", "deepseek", "mistral"):
        if k in base:
            return k
    return "openai-compatible"


class LLMClient:
    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        self.calls = 0
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0}

    def chat(self, messages: list[dict], tools: list[dict] | None = None, json_mode: bool = False,
             temperature: float = 0.2) -> dict:
        body: dict = {"model": self.cfg.model, "messages": messages, "temperature": temperature}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        req = urllib.request.Request(
            f"{self.cfg.base_url}/chat/completions", data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self.cfg.api_key}", "Content-Type": "application/json",
                     "HTTP-Referer": "https://github.com/threatlens", "X-Title": "ThreatLens"})
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout) as r:
                data = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"LLM HTTP {e.code}: {e.read().decode()[:300]}") from e
        self.calls += 1
        for k in self.usage:
            self.usage[k] += int((data.get("usage") or {}).get(k, 0) or 0)
        return data["choices"][0]["message"]


EXTRACT_PROMPT = """You convert an SME's free-text system description into a JSON architecture for threat modeling.
Return ONLY JSON with keys: name, description, industry, region, compliance (list), global_controls (list),
components (list of {id, name, type, zone, tech, data, auth, internet_facing, controls, features, category}),
flows (list of {id, from, to, protocol, data, auth, description}).
type in: user, web_frontend, mobile_app, api, service, admin_panel, database, object_storage, cache, queue, identity_provider, third_party.
zone in: internet, dmz, internal, data, third_party.
data values from: phi, payment, credentials, secrets, national_id, financial, pii, internal, public.
auth in: none, password, session, jwt, oauth, sso, api_key, mtls, mfa, hmac.
controls from: tls, waf, cdn, mfa, rate_limiting, encryption_at_rest, backups, audit_logging, logging, input_validation,
rbac, object_level_authz, csp, csrf, private_bucket, signed_urls, secrets_manager, monitoring, sca, secure_storage, dpa.
features from: file_upload, url_fetch, webhooks_in, webhooks_out, otp. third_party category: payment, messaging, shipping, government, analytics.
ONLY list controls the text explicitly states. Model external human actors as type 'user'. Include webhook flows from payment gateways to the API."""


def extract_architecture(client: LLMClient, text: str) -> dict | None:
    msg = client.chat([{"role": "system", "content": EXTRACT_PROMPT}, {"role": "user", "content": text}], json_mode=True)
    content = (msg.get("content") or "").strip()
    if content.startswith("```"):
        content = content.strip("`").split("\n", 1)[1].rsplit("```", 1)[0]
    d = json.loads(content)
    return d if isinstance(d, dict) and d.get("components") else None
