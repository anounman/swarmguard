import hashlib
import json

from sg.gateway import Gateway
from sg.log import heads_path, pk_hex, verify
from sg.schema import GuardConfig


def _run(tmp_path):
    log = tmp_path / "e.jsonl"
    gw = Gateway(GuardConfig.STATIC, "r1", log_path=str(log))
    _, tok, _ = gw.spawn(None, "agent", ["read_file"], "task")
    gw.check(tok, "read_file", {"file_path": "a"}, "task")
    gw.check(tok, "delete_file", {"file_path": "a"}, "task")
    return gw, log, {gw.run_id: pk_hex(gw.id.pk)}


def test_clean_log_verifies_with_signed_head(tmp_path):
    gw, log, pin = _run(tmp_path)
    assert heads_path(log).exists()
    assert verify(str(log), pubkeys=pin) is None
    assert verify(str(log)) is None


def test_chained_append_caught_by_signed_head(tmp_path):
    gw, log, pin = _run(tmp_path)
    lines = log.read_text().splitlines()
    extra = {**json.loads(lines[-1]), "eid": "x", "prev": hashlib.sha256(lines[-1].encode()).hexdigest()}
    log.write_text(log.read_text() + json.dumps(extra) + "\n")
    assert verify(str(log), signed=False) is None  # unkeyed chain alone misses it
    assert "differs from signed head" in verify(str(log), pubkeys=pin)


def test_missing_sidecar_is_reported(tmp_path):
    gw, log, pin = _run(tmp_path)
    heads_path(log).unlink()
    assert verify(str(log), pubkeys=pin).startswith("head missing")


def test_deleted_run_reported(tmp_path):
    gw, log, pin = _run(tmp_path)
    log.write_text("")
    assert "run deleted" in verify(str(log), pubkeys=pin)


def test_no_sidecar_without_log_path():
    gw = Gateway(GuardConfig.STATIC, "r2")
    gw.spawn(None, "agent", ["read_file"], "task")
    assert gw.log.head is not None
