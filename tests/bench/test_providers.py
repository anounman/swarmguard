import pytest

from bench import providers as P

BUD = {"providers": {"ollama": {"base_url": "https://ollama.com/v1"},
                     "commandcode": {"base_url": "https://api.commandcode.ai/provider/v1", "key_env": "COMMAND_CODE_API"},
                     "openrouter": {"base_url": "https://openrouter.ai/api/v1", "key_env": "OPENROUTER_API_KEY",
                                    "allowed_models": ["openai/gpt-4.1"]},
                     "openai": {"allowed": False}},
       "prices": {"gpt-oss:120b": {"input": 0.15, "output_est": 0.6},
                  "deepseek/deepseek-v4.1-flash": {"input": 0.15, "output": 0.6, "provider": "commandcode"},
                  "claude-haiku-5-5": {"input": 0.1, "output": 0.5, "provider": "commandcode"},
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


def test_haiku_rejected_clearly():
    with pytest.raises(ValueError, match="messages"):
        P.resolve("claude-haiku-5-5", budget=BUD)


def test_real_budget_yaml_resolves():
    assert P.resolve("openai/gpt-4.1")["base_url"].startswith("https://openrouter.ai")


def test_key_loader_env_then_zshrc(tmp_path, monkeypatch):
    (tmp_path / ".zshrc").write_text('export FAKE_K="old"\nexport FAKE_K="fromrc"\n')
    monkeypatch.setenv("FAKE_K", "")
    assert P.env_key("FAKE_K", home=tmp_path) == "fromrc"  # empty env -> rc, last line wins
    monkeypatch.setenv("HOME", str(tmp_path))
    assert P.env_key("FAKE_K") == "fromrc"
    monkeypatch.setenv("FAKE_K", "fromenv")
    assert P.env_key("FAKE_K", home=tmp_path) == "fromenv"
    monkeypatch.delenv("FAKE_K")
    assert P.env_key("MISSING_K", home=tmp_path) is None
