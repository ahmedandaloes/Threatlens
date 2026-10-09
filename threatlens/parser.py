"""Input parsing: architecture YAML/JSON, free text, and OpenAPI specs."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from .models import Architecture, Component, Endpoint, Flow, COMPONENT_TYPES, ZONES

TYPE_ALIASES = {
    "frontend": "web_frontend", "web": "web_frontend", "spa": "web_frontend", "website": "web_frontend",
    "mobile": "mobile_app", "app": "mobile_app", "backend": "api", "rest_api": "api",
    "worker": "service", "microservice": "service", "db": "database", "storage": "object_storage",
    "bucket": "object_storage", "s3": "object_storage", "redis": "cache", "admin": "admin_panel",
    "dashboard": "admin_panel", "idp": "identity_provider", "sso": "identity_provider",
    "external": "third_party", "saas": "third_party", "actor": "user", "external_entity": "user",
}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_") or "c"


def _list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [x.strip().lower() for x in v.split(",") if x.strip()]
    return [str(x).strip().lower() for x in v]


def architecture_from_dict(d: dict[str, Any], source_kind: str = "yaml") -> Architecture:
    arch = Architecture(
        name=d.get("name", "Unnamed system"),
        description=d.get("description", ""),
        industry=d.get("industry", ""),
        region=d.get("region", ""),
        users=str(d.get("users", "")),
        compliance=list(d.get("compliance", []) or []),
        global_controls=_list(d.get("global_controls") or d.get("controls")),
        assumptions=list(d.get("assumptions", []) or []),
        source_kind=source_kind,
    )
    for raw in d.get("components", []) or []:
        ctype = str(raw.get("type", "service")).lower()
        ctype = TYPE_ALIASES.get(ctype, ctype)
        if ctype not in COMPONENT_TYPES:
            arch.assumptions.append(f"Unknown component type '{ctype}' for {raw.get('name')}; treated as 'service'.")
            ctype = "service"
        zone = str(raw.get("zone", "")).lower() or _default_zone(ctype, bool(raw.get("internet_facing")))
        if zone not in ZONES:
            zone = "internal"
        cid = str(raw.get("id") or _slug(raw.get("name", ctype)))
        arch.components.append(Component(
            id=cid, name=raw.get("name", cid), type=ctype, zone=zone, tech=str(raw.get("tech", "")),
            data=_list(raw.get("data")), auth=str(raw.get("auth", "none")).lower(),
            internet_facing=bool(raw.get("internet_facing", zone in ("internet", "dmz") and ctype != "user")),
            controls=_list(raw.get("controls")), features=_list(raw.get("features")),
            category=str(raw.get("category", "")).lower(), notes=str(raw.get("notes", "")),
        ))
    for i, raw in enumerate(d.get("flows", []) or [], 1):
        arch.flows.append(Flow(
            id=str(raw.get("id") or f"F{i:02d}"), source=str(raw.get("from") or raw.get("source")),
            target=str(raw.get("to") or raw.get("target")), protocol=str(raw.get("protocol", "https")).lower(),
            data=_list(raw.get("data")), auth=str(raw.get("auth", "none")).lower(),
            description=str(raw.get("description", "")), controls=_list(raw.get("controls")),
        ))
    known = {c.id for c in arch.components}
    for f in arch.flows:
        for end in (f.source, f.target):
            if end not in known:
                arch.assumptions.append(f"Flow {f.id} references unknown component '{end}'; added as external entity.")
                arch.components.append(Component(id=end, name=end, type="user", zone="internet"))
                known.add(end)
    return arch


def _default_zone(ctype: str, internet_facing: bool) -> str:
    if ctype == "user":
        return "internet"
    if ctype == "third_party" or ctype == "identity_provider":
        return "third_party"
    if ctype in ("database", "object_storage", "cache", "queue"):
        return "data"
    if ctype in ("web_frontend", "mobile_app") or internet_facing:
        return "dmz"
    return "internal"


# --------------------------------------------------------------------------
# Free-text heuristic extraction (offline mode)
# --------------------------------------------------------------------------
_TEXT_COMPONENTS = [
    # (regex, id, name, type, extra)
    (r"\b(mobile app|android|ios|flutter|react native)\b", "mobile_app", "Mobile App", "mobile_app", {}),
    (r"\b(web ?site|web app|web portal|storefront|react|next\.?js|angular|vue|portal)\b", "web_app", "Web App", "web_frontend", {}),
    (r"\b(admin|dashboard|back[- ]?office|staff panel)\b", "admin_panel", "Admin Dashboard", "admin_panel", {}),
    (r"\b(api|backend|laravel|django|node|express|spring|\.net|fastapi|nestjs)\b", "backend_api", "Backend API", "api", {}),
    (r"\b(postgres\w*|mysql|mariadb|mongo\w*|sql server|database|firestore)\b", "database", "Database", "database", {}),
    (r"\b(s3|bucket|blob storage|file storage|uploads?|documents? storage|minio)\b", "file_storage", "File Storage", "object_storage", {}),
    (r"\b(redis|memcached|cache)\b", "cache", "Cache", "cache", {}),
    (r"\b(queue|rabbitmq|kafka|sqs)\b", "queue", "Message Queue", "queue", {}),
]
_PAYMENT = r"\b(paymob|fawry|stripe|hyperpay|moyasar|tap payments|paytabs|checkout\.com|mada|stc pay|vodafone cash|instapay|payment gateway)\b"
_MESSAGING = r"\b(whatsapp|twilio|sms|unifonic|vonage|infobip|firebase cloud messaging|push notifications?)\b"
_SHIPPING = r"\b(bosta|aramex|smsa|mylerz|careem|shipping|courier)\b"
_GENERIC = {"sms", "push notification", "push notifications", "shipping", "courier", "payment gateway", "card", "firebase cloud messaging"}
_DATA_HINTS = {
    "phi": r"\b(patient|medical|health|diagnos\w*|prescription|lab results?|clinic|pharmacy)\b",
    "payment": r"\b(card|payment|wallet|checkout|pay)\b",
    "national_id": r"\b(national id|iqama|passport|nid)\b",
    "financial": r"\b(salary|salaries|payroll|iban|bank account|invoice|loan|balance)\b",
    "pii": r"\b(name|phone|email|address|customer|employee|user profile|personal)\b",
    "credentials": r"\b(password|login|otp|sign[- ]?in)\b",
}
_CONTROL_HINTS = {
    "mfa": r"\b(mfa|2fa|two[- ]factor|multi[- ]factor)\b",
    "waf": r"\b(waf|cloudflare)\b",
    "encryption_at_rest": r"\b(encrypted at rest|encryption at rest|kms)\b",
    "rate_limiting": r"\b(rate limit\w*|throttl\w*)\b",
    "backups": r"\b(backups?)\b",
    "secrets_manager": r"\b(vault|secrets manager)\b",
}


def architecture_from_text(text: str, name: str | None = None) -> Architecture:
    t = text.lower()
    comps: list[Component] = []
    data = [k for k, rx in _DATA_HINTS.items() if re.search(rx, t)]
    controls = [k for k, rx in _CONTROL_HINTS.items() if re.search(rx, t)]
    sensitive = [d for d in data if d != "credentials"] or ["pii"]
    comps.append(Component(id="end_user", name="Customer / End user", type="user", zone="internet"))
    for rx, cid, cname, ctype, _ in _TEXT_COMPONENTS:
        if re.search(rx, t):
            comps.append(Component(
                id=cid, name=cname, type=ctype, zone=_default_zone(ctype, ctype in ("api", "admin_panel")),
                data=sensitive + (["credentials"] if ctype in ("api", "web_frontend", "mobile_app", "admin_panel") else []),
                auth="password" if ctype in ("web_frontend", "mobile_app", "admin_panel") else ("jwt" if ctype == "api" else "none"),
                internet_facing=ctype in ("web_frontend", "mobile_app", "api", "admin_panel"),
                controls=[c for c in controls if c not in ("waf", "secrets_manager", "backups") or (c == "backups" and ctype == "database")],
                features=["file_upload"] if ctype == "api" and re.search(r"upload|attach|document|photo|scan", t) else [],
            ))
    ids = {c.id for c in comps}
    if "backend_api" not in ids:
        comps.append(Component(id="backend_api", name="Backend API", type="api", zone="dmz", data=sensitive + ["credentials"],
                               auth="jwt", internet_facing=True, controls=list(controls)))
        ids.add("backend_api")
    if "database" not in ids:
        comps.append(Component(id="database", name="Database", type="database", zone="data", data=sensitive))
        ids.add("database")
    for rx, cid, cname, cat, cdata in [
        (_PAYMENT, "payment_gateway", "Payment Gateway", "payment", ["payment", "pii"]),
        (_MESSAGING, "messaging", "SMS / WhatsApp Provider", "messaging", ["pii"]),
        (_SHIPPING, "shipping", "Shipping / Courier API", "shipping", ["pii"]),
    ]:
        hits = [m.group(1) for m in re.finditer(rx, t)]
        if hits:
            vendor = next((h for h in hits if h not in _GENERIC), hits[0])
            label = f"{cname} ({vendor.title()})" if vendor not in _GENERIC else cname
            comps.append(Component(id=cid, name=label, type="third_party", zone="third_party",
                                   data=cdata, category=cat, auth="api_key"))
            ids.add(cid)
    if "admin_panel" in ids:
        comps.insert(1, Component(id="staff", name="Staff / Admin user", type="user", zone="internet"))
        ids.add("staff")
    flows: list[Flow] = []

    def add(s, d, data_, proto="https", auth="none", desc=""):
        if s in ids and d in ids:
            flows.append(Flow(id=f"F{len(flows)+1:02d}", source=s, target=d, protocol=proto, data=data_, auth=auth, description=desc))

    clients = [c for c in ("web_app", "mobile_app") if c in ids]
    for c in clients:
        add("end_user", c, sensitive + ["credentials"], desc="User interaction")
        add(c, "backend_api", sensitive + ["credentials"], auth="jwt", desc="API calls")
    if not clients:
        add("end_user", "backend_api", sensitive + ["credentials"], desc="API calls")
    add("staff", "admin_panel", sensitive + ["credentials"], desc="Staff login")
    add("admin_panel", "backend_api", sensitive, auth="session", desc="Admin operations")
    add("backend_api", "database", sensitive, proto="tcp/tls", auth="password", desc="Queries")
    add("backend_api", "file_storage", sensitive, auth="api_key", desc="Store files")
    add("backend_api", "cache", ["credentials"], proto="tcp", desc="Sessions / cache")
    add("backend_api", "queue", sensitive, proto="amqp", desc="Async jobs")
    add("backend_api", "payment_gateway", ["payment", "pii"], auth="api_key", desc="Create payment")
    add("payment_gateway", "backend_api", ["payment"], desc="Payment callback / webhook")
    add("backend_api", "messaging", ["pii"], auth="api_key", desc="Send OTP / notifications")
    add("backend_api", "shipping", ["pii"], auth="api_key", desc="Create shipment")
    for c in comps:
        if c.id == "messaging":
            c.features.append("otp")
    first_line = re.split(r"\s[—–:-]\s|[.:]\s", text.strip().splitlines()[0])[0][:80] if text.strip() else "System"
    arch = Architecture(
        name=name or first_line, description=text.strip(), source_kind="text", components=comps, flows=flows,
        global_controls=[c for c in controls if c in ("waf", "secrets_manager", "rate_limiting", "backups")],
        assumptions=[
            "Architecture inferred from free text by the offline heuristic extractor; review components and flows.",
            "Controls not explicitly mentioned in the description are assumed absent (conservative).",
        ],
    )
    return arch


# --------------------------------------------------------------------------
# OpenAPI
# --------------------------------------------------------------------------
def endpoints_from_openapi(spec: dict[str, Any], component: str = "") -> list[Endpoint]:
    global_sec = bool(spec.get("security"))
    out: list[Endpoint] = []
    for path, ops in (spec.get("paths") or {}).items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            op = op or {}
            sec = op.get("security")
            secured = bool(sec) if sec is not None else global_sec
            cts = list(((op.get("requestBody") or {}).get("content") or {}).keys())
            out.append(Endpoint(method=method.upper(), path=path, summary=op.get("summary", ""),
                                secured=secured, content_types=cts, component=component))
    return out


def load_file(path: str | Path) -> tuple[str, Any]:
    """Return (kind, payload) where kind in {'arch', 'text', 'openapi'}."""
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml", ".json"):
        data = json.loads(raw) if p.suffix.lower() == ".json" else yaml.safe_load(raw)
        if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
            return "openapi", data
        if isinstance(data, dict):
            return "arch", data
    return "text", raw
