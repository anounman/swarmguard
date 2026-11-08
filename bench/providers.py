"""Model -> provider/key resolution (PLAN C13-C16, budget.yaml is the law). No network here."""
from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
BUDGET = ROOT / "budget.yaml"
# legacy CLI names -> budget.yaml price keys. gpt-4.1 goes to OpenRouter, NEVER OpenAI direct (C13/C16).
ALIASES = {"gpt-4.1": "openai/gpt-4.1", "deepseek-v4.1-flash": "deepseek/deepseek-v4.1-flash"}
OLLAMA_KEYS = {"A": "OLLAMA_API_KEY", "B": "OLLAMA_API_KEY1"}
MODELS = ["gpt-oss:120b", "gpt-oss:20b", "deepseek/deepseek-v4.1-flash", "openai/gpt-4.1", "claude-haiku-5-5",
          "kimi-k3.1-pro", *ALIASES]


def load_budget(path: str | Path | None = None) -> dict:
    return yaml.safe_load(Path(path or BUDGET).read_text())


def canonical(model: str) -> str:
    return ALIASES.get(model, model)


def provider_of(model: str, budget: dict | None = None) -> str:
    budget = budget or load_budget()
    return (budget.get("prices", {}).get(canonical(model)) or {}).get("provider", "ollama")


def dir_name(model: str) -> str:
    """Logdir segment: last path part, so openai/gpt-4.1 resumes the legacy runs/mad/<cfg>/gpt-4.1 dir."""
    return canonical(model).rsplit("/", 1)[-1]


def env_key(name: str, home: str | Path | None = None) -> str | None:
    """Env var if set and non-empty, else the last `export NAME=...` line in ~/.zshrc (session env may be stale)."""
    if os.environ.get(name):
        return os.environ[name]
    rc = Path(home or os.path.expanduser("~")) / ".zshrc"
    if not rc.exists():
        return None
    val = None
    for m in re.finditer(rf'^\s*export\s+{re.escape(name)}=(.*)$', rc.read_text(), re.M):
        val = m.group(1).strip().strip('"').strip("'")
    return val or None


def resolve(model: str, key: str | None = "A", budget: dict | None = None) -> dict:
    """-> {provider, base_url, key, key_name, model_id_for_api}. key = A|B (ollama only). Raises ValueError."""
    budget = budget or load_budget()
    m = canonical(model)
    prov = provider_of(m, budget)
    pcfg = budget["providers"].get(prov) or {}
    if pcfg.get("allowed") is False or prov in ("openai", "groq"):
        raise ValueError(f"provider {prov} not allowed by budget.yaml")
    if m == "claude-haiku-5-5":
        # ponytail: fork pipeline (bench/mad_guard.make_pipeline) only speaks OpenAI /chat/completions; haiku needs
        # Anthropic /messages with a base_url -> would need new code, so it stays out (budget.yaml only_if).
        raise ValueError("claude-haiku-5-5 needs the Anthropic /messages endpoint; mad_guard.make_pipeline is "
                         "OpenAI-only -> not supported without new code")
    if prov == "openrouter" and m not in pcfg.get("allowed_models", [m]):
        raise ValueError(f"{m} not in openrouter.allowed_models")
    if prov == "ollama":
        key = key or "A"
        key_name = OLLAMA_KEYS[key]
    else:
        key, key_name = None, pcfg["key_env"]
    return {"provider": prov, "base_url": pcfg["base_url"], "key": key, "key_name": key_name,
            "model_id_for_api": m}


def provider_env(res: dict) -> dict:
    """Env for the fork's OPENAI_COMPATIBLE provider. Exits with a clear line if the key is missing."""
    val = env_key(res["key_name"])
    if not val:
        raise SystemExit(f"{res['key_name']} not set (env or ~/.zshrc)")
    return {"OPENAI_COMPATIBLE_BASE_URL": res["base_url"], "OPENAI_COMPATIBLE_API_KEY": val}
