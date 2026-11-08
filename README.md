# SwarmGuard

IAM-style per-task roles + one signed gateway + a small trained decider for multi-agent LLM systems.
Benchmarked on MultiAgentDojo against multi-CaMeL (arXiv 2610.05640).

Built during the Apart Research **Swarm Alignment Hackathon** (Nov 7–9, 2026). Tracks 4 (Oversight & Control) + 3 (Agent Infrastructure).

## Pre-sprint material (disclosed)
`PLAN.md` (v1–v3 sections), `ARCHITECTURE.md`, `HANDOFF.md` are planning notes written before the sprint window. `PLAN.md` v4 changelog + §15–17 and `PROGRESS.md` were written in-sprint. All code, data pipelines, results and the report were produced during the sprint.

## Layout
- `sg/` — the security layer: identity (Ed25519 JWT), roles, labels, policy, guarded executor, monitors, event log. `sg/schema.py` is the frozen shared contract.
- `bench/mad/` — vendored [MultiAgentDojo](https://github.com/james-pete/multiagentdojo) (MIT; = agentdojo 0.1.35 + multi-agent pipeline). `bench/mad_guard.py` wires SwarmGuard into it. `bench/run.py` runs every benchmark the same way.
- `bench/attacks/` — 6 multi-agent attacks + 5 benign twins (our extension).
- `train/` — decider data converters (AgentDojo runs, AgentDrift), QLoRA training, eval.
- `loop/` — build → smoke → bench → metrics → compare → harvest → retrain loop. `loop/targets.yaml` holds PASS criteria.
- `docs/REPORT.md` — the report. `results/` — metrics the report cites.

## Setup
```bash
uv sync --dev
cp .env.example .env   # fill keys
uv run pytest -q
```

## Providers and budget
All LLM calls go to **Ollama Cloud** (`https://ollama.com/v1`, OpenAI-compatible). `budget.yaml` holds the cap, keys, concurrency limit and model priority; the loop's bench stage refuses to launch a run whose projected cost exceeds the remaining budget. OpenAI and OpenRouter are not used in this project (see `PLAN.md` C13). `runs/mad/NONE/gpt-4.1/` is a partial undefended gpt-4.1 baseline recorded before that decision and is reported as partial.
