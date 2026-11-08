import pytest

from bench import providers as P

BUD = {"providers": {"ollama": {"base_url": "https://ollama.com/v1"},
                     "commandcode": {"base_url": "https://api.commandcode.ai/provider/v1", "key_env": "COMMAND_CODE_API"},
                     "openrouter": {"base_url": "https://openrouter.ai/api/v1", "key_env": "OPENROUTER_API_KEY",
                                    "allowed_models": ["openai/gpt-4.1"]},
                     "anthropic": {"base_url": "https://api.anthropic.com/v1", "key_env": "ANTHROPIC_API_KEY",
                                   "allowed_models": ["claude-sonnet-5-5", "claude-haiku-5-5"]},
                     "openai": {"allowed": False}},
       "prices": {"gpt-oss:120b": {"input": 0.15, "output_est": 0.6},
                  "deepseek/deepseek-v4.1-flash": {"input": 0.15, "output": 0.6, "provider": "commandcode"},
                  "claude-haiku-5-5": {"input": 1, "output": 5, "provider": "anthropic"},
                  "claude-sonnet-5-5": {"input": 3, "output": 15, "provider": "anthropic"},
                  "claude-opus-5-5": {"input": 15, "output": 75, "provider": "anthropic"},
                  "moonshotai/Kimi-K3.1-Pro": {"input": 2, "output": 10, "provider": "commandcode"},
                  "openai/gpt-4.1": {"input": 2, "output": 8, "provider": "openrouter"}}}


def test_legacy_gpt41_goes_to_openrouter_never_openai():
    r = P.resolve("gpt-4.1", budget=BUD)
    assert r["provider"] == "openrouter" and "openai.com" not in r["base_url"]
    assert r["model_id_for_api"] == "openai/gpt-4.1" and r["key_name"] == "OPENROUTER_API_KEY"
    assert P.dir_name("openai/gpt-4.1") == "gpt-4.1"  # legacy NONE logs stay resumable


def test_ollama_keys_and_commandcode():
    assert P.resolve("gpt-oss:120b", "B", BUD)["key_name"] == "OLLAMA_API_KEY1"
    assert P.resolve("gpt-oss:120b", None, BUD)["key_name"] == "OLLAMA_API_KEY"
    r = P.resolve("deepseek-v4.1-flash", "A", BUD)
    assert (r["provider"], r["model_id_for_api"], r["key"]) == ("commandcode", "deepseek/deepseek-v4.1-flash", None)


def test_anthropic_compat_and_allowed_models():
    r = P.resolve("claude-sonnet-5-5", budget=BUD)
    assert (r["provider"], r["base_url"], r["key_name"], r["key"]) == (
        "anthropic", "https://api.anthropic.com/v1", "ANTHROPIC_API_KEY", None)
    assert P.resolve("claude-haiku-5-5", budget=BUD)["provider"] == "anthropic"  # compat layer, no refusal
    with pytest.raises(ValueError, match="anthropic.allowed_models"):
        P.resolve("claude-opus-5-5", budget=BUD)
    assert P.dir_name("claude-sonnet-5-5") == "claude-sonnet-5-5"


def test_kimi_alias_goes_to_commandcode():
    r = P.resolve("kimi-k3.1-pro", budget=BUD)
    assert (r["provider"], r["model_id_for_api"]) == ("commandcode", "moonshotai/Kimi-K3.1-Pro")
    assert P.dir_name("kimi-k3.1-pro") == "Kimi-K3.1-Pro"


def test_real_budget_yaml_resolves():
    assert P.resolve("openai/gpt-4.1")["base_url"].startswith("https://openrouter.ai")
    assert P.resolve("claude-sonnet-5-5")["base_url"] == "https://api.anthropic.com/v1"
    assert P.resolve("moonshotai/Kimi-K3.1-Pro")["provider"] == "commandcode"
    for m in ("claude-sonnet-5-5", "claude-opus-5-5", "claude-haiku-5-5", "kimi-k3.1-pro"):
        assert m in P.MODELS


def test_key_loader_zshrc_first_then_env(tmp_path, monkeypatch):
    (tmp_path / ".zshrc").write_text('export FAKE_K="old"\nexport FAKE_K="fromrc"\nexport ONLY_ENV_K=""\n')
    monkeypatch.setenv("FAKE_K", "")
    assert P.env_key("FAKE_K", home=tmp_path) == "fromrc"  # rc, last line wins
    monkeypatch.setenv("HOME", str(tmp_path))
    assert P.env_key("FAKE_K") == "fromrc"
    monkeypatch.setenv("FAKE_K", "stale-env")
    assert P.env_key("FAKE_K", home=tmp_path) == "fromrc"  # rc beats a (possibly stale) env copy
    monkeypatch.setenv("ONLY_ENV_K", "fromenv")
    assert P.env_key("ONLY_ENV_K", home=tmp_path) == "fromenv"  # rc line empty -> env fallback
    monkeypatch.delenv("FAKE_K")
    assert P.env_key("MISSING_K", home=tmp_path) is None


def test_supervise_cells_extra_columns():
    from bench import supervise as S  # import must not start the loop
    c = S.parse_cells("# hdr\nNONE claude-sonnet-5-5 workspace important_instructions - --max-episodes 150\n"
                      "NONE gpt-oss:120b banking none A\n")
    assert S.run_args(c[0])[-4:] == ["--attack", "important_instructions", "--max-episodes", "150"]
    assert "--key" not in S.run_args(c[0]) and S.run_args(c[1])[-2:] == ["--key", "A"]
    assert S.marker(c[0]).name == "NONE_claude-sonnet-5-5_workspace_important_instructions.done"
