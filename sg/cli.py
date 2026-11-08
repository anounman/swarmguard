"""`sg` door CLI (PLAN §2 B4): mint/verify tokens, check a call, run a command only if the role allows it.

  sg token mint --role role.json          -> prints JWT           (issuer side only: needs the private key)
  sg token verify <jwt>                   -> prints claims JSON
  sg token revoke <jwt>                   -> revoked for every later CLI call
  sg check --token <jwt> --tool send_email --args '{...}'
  sg run --token <jwt> -- <cmd...>        -> exec only if check(tool='run', args={'cmd': ...}) allows

Reused: sg.gateway.Gateway.check (S1) for the decision chain, sg.identity.Identity (PyJWT EdDSA).
Keys: the issuer keeps $SG_HOME/key.pem (+ key.pub). If $SG_PUBKEY is set the CLI is verify-only:
it loads that public key, never touches a private key, and refuses 'token mint'.
State that must survive across CLI calls (per-jti call counts, revoked jtis, step) lives in $SG_HOME/state.json.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sg.gateway import Gateway
from sg.identity import Identity, TokenError
from sg.schema import Decision, EventKind, Role, TokenClaims

HOME = Path(os.environ.get("SG_HOME", Path.home() / ".sg"))


def identity() -> Identity:
    ident = Identity()
    # ponytail: reach into S1's key slots; an Identity(sk=/pk=) constructor in S1 would remove this.
    if pub := os.environ.get("SG_PUBKEY"):  # verify-only (sandbox side)
        ident._sk = None
        ident.pk = serialization.load_pem_public_key(Path(pub).read_bytes())
        return ident
    HOME.mkdir(parents=True, exist_ok=True)
    kf = HOME / "key.pem"
    if not kf.exists():
        sk = Ed25519PrivateKey.generate()
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # never world-readable, not even briefly
        os.write(fd, sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        os.close(fd)
        (HOME / "key.pub").write_bytes(sk.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    ident._sk = serialization.load_pem_private_key(kf.read_bytes(), None)
    ident.pk = ident._sk.public_key()
    return ident


def gateway() -> Gateway:
    HOME.mkdir(parents=True, exist_ok=True)
    gw = Gateway("STATIC", "cli", log_path=str(HOME / "events.jsonl"))
    gw.id = identity()
    st = json.loads((HOME / "state.json").read_text()) if (HOME / "state.json").exists() else {}
    gw.id.calls.update(st.get("calls", {}))
    gw.id.revoked |= set(st.get("revoked", []))
    gw.step = st.get("step", 0)
    return gw


def save(gw: Gateway) -> None:
    # ponytail: read-modify-write without a lock; concurrent CLI calls can lose a count.
    (HOME / "state.json").write_text(json.dumps(
        {"calls": dict(gw.id.calls), "revoked": sorted(gw.id.revoked), "step": gw.step}))


def check(token: str, tool: str, args: dict) -> Decision:
    gw = gateway()
    try:
        claims = gw.verify(token)
    except TokenError:
        claims = None  # gw.check below logs the token failure
    # Gateway.check does not look at allow_cmds, so the CLI enforces it for 'run' (one DENY event).
    if tool == "run" and claims is not None:
        exe = (shlex.split(str(args.get("cmd", ""))) or ["_"])[0]
        if exe not in claims.role.allow_cmds:
            why = f"command {exe!r} not in allow_cmds {claims.role.allow_cmds}"
            ev = gw._event(agent_id=claims.agent_id, kind=EventKind.DENY, tool=tool, args=args, reason=why,
                           meta={"action": "DENY", "config": "STATIC"})
            save(gw)
            return Decision(allow=False, deny_reason=why, event_id=ev.eid)
    # CLI caller is the principal: its own args count as task text (trusted), not tool output.
    dec = gw.check(token, tool, args, json.dumps(args))
    save(gw)
    return dec


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sg")
    sp = p.add_subparsers(dest="cmd", required=True)
    tok = sp.add_parser("token").add_subparsers(dest="sub", required=True)
    m = tok.add_parser("mint")
    m.add_argument("--role", required=True)
    m.add_argument("--agent", default="cli-agent")
    tok.add_parser("verify").add_argument("jwt")
    tok.add_parser("revoke").add_argument("jwt")
    c = sp.add_parser("check")
    c.add_argument("--token", required=True)
    c.add_argument("--tool", required=True)
    c.add_argument("--args", default="{}")
    r = sp.add_parser("run")
    r.add_argument("--token", required=True)
    r.add_argument("argv", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)

    def err(msg: str, code: int = 1) -> int:
        print(f"PermissionError: {msg}", file=sys.stderr)
        return code

    if a.cmd == "token" and a.sub == "mint":
        ident = identity()
        if ident._sk is None:
            return err("verify-only CLI (SG_PUBKEY set): tokens are minted by the issuer, not here")
        role = Role.model_validate_json(Path(a.role).read_text())
        print(ident.mint(TokenClaims.for_role(role, run_id="cli", agent_id=a.agent)))
        return 0
    if a.cmd == "token":
        gw = gateway()
        try:
            claims = gw.verify(a.jwt)
        except TokenError as e:
            return err(str(e))
        if a.sub == "revoke":
            gw.id.revoke(claims.jti)
            save(gw)
            print(f"revoked {claims.jti}")
        else:
            print(claims.model_dump_json(indent=1))
        return 0
    if a.cmd == "check":
        try:
            args = json.loads(a.args)
        except json.JSONDecodeError as e:
            print(f"error: --args is not valid JSON: {e}", file=sys.stderr)
            return 2
        dec = check(a.token, a.tool, args)
        print(dec.model_dump_json())
        return 0 if dec.allow else 1
    cmd = a.argv[1:] if a.argv[:1] == ["--"] else a.argv
    dec = check(a.token, "run", {"cmd": shlex.join(cmd)})
    if not dec.allow:
        return err(f"{dec.deny_reason} (event {dec.event_id})", 126)
    return subprocess.run(cmd).returncode  # argv list, no shell


if __name__ == "__main__":
    sys.exit(main())
