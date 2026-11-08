import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sg.gateway import Gateway
from sg.identity import Identity, TokenError
from sg.schema import GuardConfig, Role, TokenClaims


def claims(**kw):
    return TokenClaims.for_role(Role(task_id="t", tools=["read_file"]), "run", "a1", **kw)


def test_roundtrip_and_failures():
    idt = Identity()
    c = claims()
    tok = idt.mint(c)
    assert idt.verify(tok).role.tools == ["read_file"]
    # forged: signed with another key
    forged = jwt.encode(c.model_dump(mode="json"), Ed25519PrivateKey.generate(), algorithm="EdDSA")
    with pytest.raises(TokenError):
        idt.verify(forged)
    # wrong key: other gateway's token
    with pytest.raises(TokenError):
        Identity().verify(tok)
    # tampered payload
    h, p, s = tok.split(".")
    with pytest.raises(TokenError):
        idt.verify(f"{h}.{p[:-2]}xx.{s}")
    # expired
    old = c.model_copy(update={"exp": time.time() - 100})
    with pytest.raises(TokenError):
        idt.verify(idt.mint(old))
    # revoked -> replay denied
    idt.revoke(c.jti)
    with pytest.raises(TokenError):
        idt.verify(tok)
    assert idt.spend("x") == 1 and idt.spend("x") == 2


def test_gateway_denies_bad_tokens():
    gw = Gateway(GuardConfig.STATIC, "run")
    aid, tok, _ = gw.spawn(None, "orchestrator", ["read_file"], "read it")
    assert gw.check(tok, "read_file", {}, "read it").allow
    other = Gateway(GuardConfig.STATIC, "run")
    _, foreign, _ = other.spawn(None, "orchestrator", ["read_file"], "x")
    assert not gw.check(foreign, "read_file", {}, "x").allow  # wrong key
    assert not gw.check("garbage", "read_file", {}, "x").allow
    gw.id.revoke(gw.verify(tok).jti)
    d = gw.check(tok, "read_file", {}, "read it")  # replay after revoke
    assert not d.allow and "revoked" in d.deny_reason
