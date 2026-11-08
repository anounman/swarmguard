"""Model -> provider/key resolution (PLAN C13-C16, budget.yaml is the law). No network here."""
from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
BUDGET = ROOT / "budget.yaml"
# legacy CLI names -> budget.yaml price keys. gpt-4.1 goes to OpenRouter, NEVER OpenAI direct (C13/C16).
# C29: bare deepseek-v4.1-flash is the Ollama Cloud model (no longer an alias of the Command Code id)
ALIASES = {"gpt-4.1": "openai/gpt-4.1",
           "kimi-k3.1-pro": "moonshotai/Kimi-K3.1-Pro"}
OLLAMA_KEYS = {"A": "OLLAMA_API_KEY", "B": "OLLAMA_API_KEY1"}
MODELS = ["deepseek-v4.1-flash",  # C29: bare id = Ollama Cloud (vendor-prefixed deepseek/... = Command Code)
          "gpt-oss:120b", "gpt-oss:20b", "deepseek/deepseek-v4.1-flash", "openai/gpt-4.1", "claude-haiku-5-5",
          "claude-sonnet-5-5", "claude-opus-5-5", "moonshotai/Kimi-K3.1-Pro", *ALIASES]


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
    """Last `export NAME=...` line in ~/.zshrc wins (the user edits keys there; session env copies go stale and
    caused 401s on Command Code); the env var is only the fallback when rc has no line."""
    rc = Path(home or os.path.expanduser("~")) / ".zshrc"
    val = None
    if rc.exists():
        for m in re.finditer(rf'^\s*export\s+{re.escape(name)}=(.*)$', rc.read_text(), re.M):
            val = m.group(1).strip().strip('"').strip("'")
    return val or os.environ.get(name) or None


def resolve(model: str, key: str | None = "A", budget: dict | None = None) -> dict:
    """-> {provider, base_url, key, key_name, model_id_for_api}. key = A|B (ollama only). Raises ValueError."""
    budget = budget or load_budget()
    m = canonical(model)
    prov = provider_of(m, budget)
    pcfg = budget["providers"].get(prov) or {}
    if pcfg.get("allowed") is False or prov in ("openai", "groq"):
        raise ValueError(f"provider {prov} not allowed by budget.yaml")
    # anthropic (incl. haiku) goes through Anthropic's OpenAI-compat /v1/chat/completions -> no special case
    if prov in ("openrouter", "anthropic") and m not in pcfg.get("allowed_models", [m]):
        raise ValueError(f"{m} not in {prov}.allowed_models")
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
