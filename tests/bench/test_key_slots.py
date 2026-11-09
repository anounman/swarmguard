from bench.providers import env_key, key_slots


def test_key_slot_picks_suffixed_key(tmp_path, monkeypatch):
    (tmp_path / ".zshrc").write_text('export FOO_KEY="k1"\nexport FOO_KEY_2="k2"\nexport FOO_KEY_3="k3"\n')
    monkeypatch.delenv("FOO_KEY", raising=False)
    monkeypatch.setenv("SG_KEY_SLOT", "2")
    assert env_key("FOO_KEY", tmp_path) == "k2"
    monkeypatch.setenv("SG_KEY_SLOT", "9")  # no such slot -> plain key
    assert env_key("FOO_KEY", tmp_path) == "k1"
    monkeypatch.delenv("SG_KEY_SLOT")
    assert env_key("FOO_KEY", tmp_path) == "k1"
    assert key_slots("FOO_KEY", tmp_path) == 3
    assert key_slots("NOPE", tmp_path) == 0
