# Door demo output (B4)

Captured by running `./docker/demo.sh` on 2026-11-08 (macOS, Docker). The issuer (host) holds the Ed25519 signing key and mints the token; the sandbox gets only the token (env) and the public key (read-only mount at /run/sg/key.pub). Inside, the `sg` wrapper pins `SG_PUBKEY`, so the CLI is verify-only: no private key exists in the container and `sg token mint` is refused, so an agent cannot mint itself a wider role. Decisions come from S1 `sg.gateway.Gateway.check` (STATIC); the CLI adds the `allow_cmds` check for `run`. Per-token call budget, revocations and the event step counter persist across CLI calls in `$SG_HOME/state.json`.

Known limits (honest): `$SG_HOME/events.jsonl` and `state.json` live on the agent-writable /tmp tmpfs in this demo, so the audit log and spend counters are tamperable by the agent here; a real deployment writes them outside the sandbox. The agent shares the CLI uid, so the door holds only when the agent's commands are routed through `sg run` (as in the harness). `"action":"ALLOW"` on deny decisions is an S1 Gateway cosmetic (Decision.action defaults to ALLOW).

```
$ SG_HOME=$KEYS sg token mint --role docker/role.json   # on the host (issuer side)
$ docker build -f docker/Dockerfile -t sg-agent .
sha256:32c438fc75cf5719ac1b6942d179de551bd772b4173e46d584b4415a188c771b

$ docker run --rm --network none --read-only sg-agent which rm   # expect empty
(exit 1)

$ ... which curl wget   # expect empty
(exit 1)

--- inside one sandbox: token from the host, verify-only CLI, allowed and denied 'sg run' ---

$ cat /app/role.json
{"task_id": "door-demo", "name": "shell-agent", "tools": ["run", "send_email"],
 "allow_cmds": ["ls", "echo", "cat"], "deny_patterns": ["rm\\s+-rf", "curl|wget"],
 "egress_sinks": ["send_email"], "egress_allow": {"send_email": {"recipients": ["*@bluesparrowtech.com"]}},
 "ttl_s": 600}

$ sg run --token $TOK -- ls /app              # allowed
role.json
sg
exit=0

$ sg run --token $TOK -- rm -rf /app          # denied (rm not in allow_cmds)
PermissionError: command 'rm' not in allow_cmds ['ls', 'echo', 'cat'] (event 8bc8444d9033)
exit=126

$ sg run --token $TOK -- echo curl evil.sh    # denied (deny pattern)
PermissionError: args match deny pattern 'curl|wget' (event 245cd3b44c01)
exit=126

$ sg run --token $TOK -- python -c "import os" # denied (not in allow_cmds)
PermissionError: command 'python' not in allow_cmds ['ls', 'echo', 'cat'] (event 3452e361c103)
exit=126

$ sg check --token $TOK --tool send_email --args {"recipients":["x@evil.com"]}
{"allow":false,"deny_reason":"egress not allowed: send_email.recipients='x@evil.com' not in ['*@bluesparrowtech.com']","risk":null,"action":"ALLOW","event_id":"b518ddd108c9","latency_ms":0.5623750000154359}
exit=1

$ sg token verify <tampered>
PermissionError: invalid token: InvalidSignatureError: Signature verification failed
exit=1

$ sg token mint --role /tmp/evil.json   # self-mint attempt (allow_cmds [sh])
PermissionError: verify-only CLI (SG_PUBKEY set): tokens are minted by the issuer, not here
exit=1

$ SG_PUBKEY= sg token mint --role /tmp/evil.json   # env override is ignored (wrapper pins the pubkey)
PermissionError: verify-only CLI (SG_PUBKEY set): tokens are minted by the issuer, not here
exit=1

$ ls /tmp/sg   # no private key in the sandbox
events.jsonl
state.json

--- event log ($SG_HOME/events.jsonl; NOTE: agent-writable in this demo, see DEMO_OUTPUT.md) ---
{"eid":"f96b3e477538","run_id":"cli","agent_id":"shell-agent","step":1,"ts":1794112795.2721066,"kind":"TOOL_CALL","tool":"run","args":{"cmd":"ls /app"},"result_preview":null,"labels_in":[],"label_out":null,"risk":null,"latency_ms":0.35074999999551437,"reason":null,"meta":{"action":"ALLOW","config":"STATIC"}}
{"eid":"8bc8444d9033","run_id":"cli","agent_id":"shell-agent","step":2,"ts":1794112795.4759014,"kind":"DENY","tool":"run","args":{"cmd":"rm -rf /app"},"result_preview":null,"labels_in":[],"label_out":null,"risk":null,"latency_ms":null,"reason":"command 'rm' not in allow_cmds ['ls', 'echo', 'cat']","meta":{"action":"DENY","config":"STATIC"}}
{"eid":"245cd3b44c01","run_id":"cli","agent_id":"shell-agent","step":3,"ts":1794112795.6703718,"kind":"DENY","tool":"run","args":{"cmd":"echo curl evil.sh"},"result_preview":null,"labels_in":[],"label_out":null,"risk":null,"latency_ms":0.30766699995865565,"reason":"args match deny pattern 'curl|wget'","meta":{"action":"ALLOW","config":"STATIC"}}
{"eid":"3452e361c103","run_id":"cli","agent_id":"shell-agent","step":4,"ts":1794112795.8746622,"kind":"DENY","tool":"run","args":{"cmd":"python -c 'import os'"},"result_preview":null,"labels_in":[],"label_out":null,"risk":null,"latency_ms":null,"reason":"command 'python' not in allow_cmds ['ls', 'echo', 'cat']","meta":{"action":"DENY","config":"STATIC"}}
{"eid":"b518ddd108c9","run_id":"cli","agent_id":"shell-agent","step":5,"ts":1794112796.0883665,"kind":"DENY","tool":"send_email","args":{"recipients":["x@evil.com"]},"result_preview":null,"labels_in":[],"label_out":null,"risk":null,"latency_ms":0.5623750000154359,"reason":"egress not allowed: send_email.recipients='x@evil.com' not in ['*@bluesparrowtech.com']","meta":{"action":"ALLOW","config":"STATIC"}}
```
