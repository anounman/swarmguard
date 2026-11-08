"""Relaunch benchmark cells until each has completed once without error (fork runs are resumable).

ponytail: pgrep-based liveness + done-marker files; the loop's bench stage will subsume this.
Usage: uv run python bench/supervise.py cells.txt [--max-live 20]
cells.txt lines: CONFIG MODEL SUITE ATTACK KEY [extra run.py args...]   (KEY '-' = no --key, non-ollama)
"""
import os, re, subprocess, sys, time
from pathlib import Path

DONE = Path(os.environ.get("SG_DONE_DIR", "runs/mad/.done"))  # C23: ADAPTIVE(v3) uses runs/mad/.done_v3
tries: dict[str, int] = {}

def parse_cells(text: str) -> list[list[str]]:
    return [l.split() for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]

def run_args(c) -> list[str]:
    """run.py args for a cell: '--attack X' stays right before --key/extras so alive()'s pattern still matches."""
    return (["--bench", "mad", "--config", c[0], "--model", c[1], "--suite", c[2], "--attack", c[3]]
            + (["--key", c[4]] if c[4] != "-" else []) + c[5:])

def key_env() -> dict:
    env = dict(os.environ)
    if not env.get("OLLAMA_API_KEY1"):
        m = re.search(r'^export OLLAMA_API_KEY1="?([^"\n]+)"?', Path.home().joinpath(".zshrc").read_text(), re.M)
        if m: env["OLLAMA_API_KEY1"] = m.group(1)
    return env

def alive(c) -> bool:
    pat = f"run.py --bench mad --config {c[0]} --model {c[1]} --suite {c[2]} --attack {c[3]} "
    if "--logdir" in c:  # C27: decider versions run as the same config with their own --logdir; match only this one
        pat += f".*--logdir {c[c.index('--logdir') + 1]}"
    return subprocess.run(["pgrep", "-f", pat], capture_output=True).returncode == 0

def marker(c) -> Path:
    return DONE / ("_".join(c[:4]).replace("/", "-").replace(":", "-") + ".done")

def gate_allows(c) -> bool:
    """Ask run.py --dry-run (no model calls). rc 0 = allow; rc 2 = budget/window refusal -> wait, do not count a try."""
    r = subprocess.run(["uv", "run", "python", "bench/run.py", *run_args(c), "--dry-run"], capture_output=True, text=True, env=key_env())
    if r.returncode == 2:
        print(time.strftime("%H:%M:%S"), "gate refused, waiting:", *c[:4], (r.stdout.strip().splitlines() or [""])[-1][:160], flush=True)
    return r.returncode == 0

def launch(c):
    log = Path(c[c.index("--logdir") + 1]) if "--logdir" in c else Path(f"runs/mad/{c[0]}/{c[1].rsplit('/', 1)[-1]}")
    log.mkdir(parents=True, exist_ok=True)
    cmd = (f"uv run python bench/run.py {' '.join(run_args(c))} "
           f">> {log}/{c[2]}-{c[3]}.log 2>&1 && touch {marker(c)}")
    subprocess.Popen(["sh", "-c", cmd], env=key_env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    tries[marker(c).name] = tries.get(marker(c).name, 0) + 1
    print(time.strftime("%H:%M:%S"), "launch", *c[:4], "try", tries[marker(c).name], flush=True)

if __name__ == "__main__":
    cells = parse_cells(Path(sys.argv[1]).read_text())
    max_live = int(sys.argv[sys.argv.index("--max-live") + 1]) if "--max-live" in sys.argv else 20
    DONE.mkdir(parents=True, exist_ok=True)
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
