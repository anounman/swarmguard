#!/usr/bin/env bash
# Door demo: the issuer (host) holds the signing key and mints the token; the sandbox only gets the
# token + the public key (read-only mount), so the agent cannot mint its own tokens.
set -u
cd "$(dirname "$0")/.."
KEYS=$(mktemp -d)
echo "\$ SG_HOME=\$KEYS sg token mint --role docker/role.json   # on the host (issuer side)"
TOK=$(SG_HOME=$KEYS uv run --quiet python -m sg.cli token mint --role docker/role.json --agent shell-agent) || exit 1
chmod 644 "$KEYS/key.pub"; chmod 755 "$KEYS"
RUN="docker run -i --rm --network none --read-only --cap-drop ALL --tmpfs /tmp:uid=10001
     -v $KEYS/key.pub:/run/sg/key.pub:ro -e TOK=$TOK sg-agent"
echo "\$ docker build -f docker/Dockerfile -t sg-agent ."
docker build -q -f docker/Dockerfile -t sg-agent . || exit 1
echo; echo "\$ docker run --rm --network none --read-only sg-agent which rm   # expect empty"
docker run --rm --network none --read-only sg-agent which rm; echo "(exit $?)"
echo; echo "\$ ... which curl wget   # expect empty"
docker run --rm --network none --read-only sg-agent which curl wget; echo "(exit $?)"
echo; echo "--- inside one sandbox: token from the host, verify-only CLI, allowed and denied 'sg run' ---"
$RUN sh -s < docker/demo_inner.sh
rm -rf "$KEYS"
