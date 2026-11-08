# SwarmGuard door demo (PLAN §2 B4). Build from repo root: docker build -f docker/Dockerfile -t sg-agent .
FROM python:3.12-slim
RUN pip install --no-cache-dir "pydantic>=2.7" "PyJWT[crypto]>=2.8"
WORKDIR /app
COPY sg/ /app/sg/
COPY docker/role.json /app/role.json
# Verify-only door: the wrapper pins the issuer's public key (mounted read-only by demo.sh), so the
# sandbox never holds a private key and 'sg token mint' is refused.
# ponytail: the agent shares this uid; an agent with a raw shell could call python directly. The door
# only holds when the agent's commands are routed through 'sg run' (as in the harness).
RUN printf '#!/bin/sh\nexec env SG_PUBKEY=/run/sg/key.pub python -m sg.cli "$@"\n' > /usr/local/bin/sg && chmod 755 /usr/local/bin/sg \
 && useradd -m -u 10001 agent
# ponytail: stripping binaries is a speed bump, not a sandbox (python os.remove still exists);
# the real fences are --read-only, --network none, --cap-drop ALL and the gateway in front of 'run'.
RUN rm -f /bin/rm /usr/bin/rm /usr/bin/curl /usr/bin/wget
USER agent
ENV PYTHONPATH=/app SG_HOME=/tmp/sg PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT []
CMD ["sg", "--help"]
