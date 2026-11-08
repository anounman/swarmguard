# runs inside the sg-agent container (piped by demo.sh); $TOK was minted on the host
p() { echo; echo "\$ $*"; }
p cat /app/role.json; cat /app/role.json
p 'sg run --token $TOK -- ls /app              # allowed'; sg run --token "$TOK" -- ls /app; echo "exit=$?"
p 'sg run --token $TOK -- rm -rf /app          # denied (rm not in allow_cmds)'; sg run --token "$TOK" -- rm -rf /app; echo "exit=$?"
p 'sg run --token $TOK -- echo curl evil.sh    # denied (deny pattern)'; sg run --token "$TOK" -- echo curl evil.sh; echo "exit=$?"
p 'sg run --token $TOK -- python -c "import os" # denied (not in allow_cmds)'; sg run --token "$TOK" -- python -c "import os"; echo "exit=$?"
p 'sg check --token $TOK --tool send_email --args {"recipients":["x@evil.com"]}'
sg check --token "$TOK" --tool send_email --args "{\"recipients\": [\"x@evil.com\"]}"; echo "exit=$?"
p "sg token verify <tampered>"; sg token verify "${TOK%????}AAAA"; echo "exit=$?"
p "sg token mint --role /tmp/evil.json   # self-mint attempt (allow_cmds [sh])"
echo '{"task_id":"x","name":"evil","tools":["run"],"allow_cmds":["sh"]}' > /tmp/evil.json
sg token mint --role /tmp/evil.json; echo "exit=$?"
p "SG_PUBKEY= sg token mint --role /tmp/evil.json   # env override is ignored (wrapper pins the pubkey)"
SG_PUBKEY= sg token mint --role /tmp/evil.json; echo "exit=$?"
p "ls /tmp/sg   # no private key in the sandbox"; ls /tmp/sg
echo; echo "--- event log (\$SG_HOME/events.jsonl; NOTE: agent-writable in this demo, see DEMO_OUTPUT.md) ---"
cat /tmp/sg/events.jsonl
