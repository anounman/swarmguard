import json
from pathlib import Path

import pytest

ROLE = Path(__file__).resolve().parents[2] / "docker/role.json"


@pytest.fixture
def cli(tmp_path, monkeypatch, capsys):
    import sg.cli as C
    monkeypatch.setattr(C, "HOME", tmp_path)
    monkeypatch.delenv("SG_PUBKEY", raising=False)

    def run(*argv):
        code = C.main(list(argv))
        return code, capsys.readouterr()
    return run


def test_door(cli, tmp_path):
    code, out = cli("token", "mint", "--role", str(ROLE))
    tok = out.out.strip()
    assert code == 0 and cli("token", "verify", tok)[0] == 0
    assert oct((tmp_path / "key.pem").stat().st_mode & 0o777) == "0o600"
    assert cli("token", "verify", tok[:-4] + "AAAA")[0] == 1  # tampered signature
    assert cli("check", "--token", tok, "--tool", "send_email", "--args", '{"recipients": ["a@bluesparrowtech.com"]}')[0] == 0
    assert cli("check", "--token", tok, "--tool", "send_email", "--args", '{"recipients": ["x@evil.com"]}')[0] == 1
    assert cli("check", "--token", tok, "--tool", "send_email", "--args", "{bad")[0] == 2
    assert cli("check", "--token", tok, "--tool", "delete_file")[0] == 1
    assert cli("run", "--token", tok, "--", "echo", "hi")[0] == 0
    code, out = cli("run", "--token", tok, "--", "rm", "-rf", "/")
    assert code == 126 and "allow_cmds" in out.err
    code, out = cli("run", "--token", tok, "--", "echo", "curl", "x")
    assert code == 126 and "deny pattern" in out.err
    log = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    assert "DENY" in {e["kind"] for e in log} and len({e["step"] for e in log}) == len(log)  # steps persist


def test_budget_and_revoke_persist(cli, tmp_path):
    role = json.loads(ROLE.read_text()) | {"budget_calls": 2}
    (tmp_path / "r.json").write_text(json.dumps(role))
    tok = cli("token", "mint", "--role", str(tmp_path / "r.json"))[1].out.strip()
    assert [cli("run", "--token", tok, "--", "echo", "hi")[0] for _ in range(3)] == [0, 0, 126]
    tok2 = cli("token", "mint", "--role", str(ROLE))[1].out.strip()
    assert cli("token", "revoke", tok2)[0] == 0
    code, out = cli("run", "--token", tok2, "--", "echo", "hi")
    assert code == 126 and "revoked" in out.err


def test_verify_only_refuses_mint_and_self_minted(cli, tmp_path, monkeypatch):
    tok = cli("token", "mint", "--role", str(ROLE))[1].out.strip()  # issuer side
    sandbox = tmp_path / "sandbox"
    import sg.cli as C
    monkeypatch.setattr(C, "HOME", sandbox)
    monkeypatch.setenv("SG_PUBKEY", str(tmp_path / "key.pub"))
    assert cli("run", "--token", tok, "--", "echo", "hi")[0] == 0
    code, out = cli("token", "mint", "--role", str(ROLE))
    assert code == 1 and "verify-only" in out.err and not (sandbox / "key.pem").exists()
    # a token signed by any other key (e.g. a key the agent generated itself) is rejected
    monkeypatch.delenv("SG_PUBKEY")
    rogue = cli("token", "mint", "--role", str(ROLE))[1].out.strip()
    monkeypatch.setenv("SG_PUBKEY", str(tmp_path / "key.pub"))
    assert cli("run", "--token", rogue, "--", "echo", "hi")[0] == 126
