"""Relaunch benchmark cells until each has completed once without error (fork runs are resumable).

ponytail: pgrep-based liveness + done-marker files; the loop's bench stage will subsume this.
Usage: uv run python bench/supervise.py cells.txt [--max-live 20]
cells.txt lines: CONFIG MODEL SUITE ATTACK KEY
"""
import os, re, subprocess, sys, time
from pathlib import Path

cells = [l.split() for l in Path(sys.argv[1]).read_text().splitlines() if l.strip() and not l.startswith("#")]
max_live = int(sys.argv[sys.argv.index("--max-live") + 1]) if "--max-live" in sys.argv else 20
DONE = Path("runs/mad/.done"); DONE.mkdir(parents=True, exist_ok=True)
tries: dict[str, int] = {}

def key_env() -> dict:
    env = dict(os.environ)
    if not env.get("OLLAMA_API_KEY1"):
        m = re.search(r'^export OLLAMA_API_KEY1="?([^"\n]+)"?', Path.home().joinpath(".zshrc").read_text(), re.M)
        if m: env["OLLAMA_API_KEY1"] = m.group(1)
    return env

def alive(c) -> bool:
    pat = f"run.py --bench mad --config {c[0]} --model {c[1]} --suite {c[2]} --attack {c[3]} "
    return subprocess.run(["pgrep", "-f", pat], capture_output=True).returncode == 0

def marker(c) -> Path:
    return DONE / ("_".join(c[:4]).replace("/", "-").replace(":", "-") + ".done")

def gate_allows(c) -> bool:
    """Ask run.py --dry-run (no model calls). rc 0 = allow; rc 2 = budget/window refusal -> wait, do not count a try."""
    r = subprocess.run(["uv", "run", "python", "bench/run.py", "--bench", "mad", "--config", c[0], "--model", c[1],
                        "--suite", c[2], "--attack", c[3], "--key", c[4], "--dry-run"], capture_output=True, text=True, env=key_env())
    if r.returncode == 2:
        print(time.strftime("%H:%M:%S"), "gate refused, waiting:", *c[:4], (r.stdout.strip().splitlines() or [""])[-1][:160], flush=True)
    return r.returncode == 0

def launch(c):
    log = Path(f"runs/mad/{c[0]}/{c[1].rsplit('/', 1)[-1]}"); log.mkdir(parents=True, exist_ok=True)
    cmd = (f"uv run python bench/run.py --bench mad --config {c[0]} --model {c[1]} --suite {c[2]} --attack {c[3]} --key {c[4]} "
           f">> {log}/{c[2]}-{c[3]}.log 2>&1 && touch {marker(c)}")
    subprocess.Popen(["sh", "-c", cmd], env=key_env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    tries[marker(c).name] = tries.get(marker(c).name, 0) + 1
    print(time.strftime("%H:%M:%S"), "launch", *c[:4], "try", tries[marker(c).name], flush=True)

while True:
    pending = [c for c in cells if not marker(c).exists() and tries.get(marker(c).name, 0) < 6]
    if not pending:
        print(time.strftime("%H:%M:%S"), "all cells done", flush=True); break
    live = [c for c in pending if alive(c)]
    for c in pending:
        if len(live) >= max_live: break
        if not alive(c) and gate_allows(c):
            launch(c); live.append(c); time.sleep(2)
    time.sleep(60)
