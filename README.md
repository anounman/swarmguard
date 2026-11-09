# SwarmGuard

Per-task roles, one gateway for every tool call, and a small trained decider for multi-agent LLM systems.

Ankush (GitHub: anounman), Universität des Saarlandes. Built in one weekend for the Apart Research Swarm Alignment Hackathon (November 6 to 8, 2026), Track 4 (Multi-Agent Oversight and Control), with limited time and budget. The long report is `docs/REPORT.md`.

## Problem

In a multi-agent LLM system, one injected instruction in content that a sub-agent reads (an email, a web page, a file) can make any agent in the tree send money or leak data. Multi-CaMeL (*Can CaMeLs Talk?*, [arXiv 2610.05640](https://arxiv.org/abs/2610.05640)) reports 0.0% attack success on MultiAgentDojo, but its published GPT-4.1 benign utility falls from 78.4% to 24.7% (reported, not reproduced by us). We asked whether a cheaper design keeps most of the utility.

## What we built

- **Roles.** Every delegated task gets an IAM-style role. A role keeps the sub-agent's existing tool list and limits destinations (recipients, accounts, URLs) to those named in the user task. It does not remove tools the task does not need.
- **Gateway.** Every tool call must pass one gateway: Ed25519-signed tokens, taint labels on tool output, and egress checks on calls that send, pay or share.
- **Decider.** A small trained model (Qwen3-4B, QLoRA) judges the suspicious calls the gateway passes to it and returns allow, flag, revoke tool, or stop run.

```
user task -> orchestrator -> sub-agents (each with a signed role token)
                                   | every tool call
                                   v
                    gateway: token valid? tool in role? destination allowed? tainted data -> sink?
                                   | suspicious calls only
                                   v
                    decider (4B): allow | flag | revoke tool | stop run
```

## Results

Benchmark: [MultiAgentDojo](https://github.com/james-pete/multiagentdojo) (an orchestrator plus 12 sub-agents, 4 suites, 97 benign tasks, 949 injected episodes, `important_instructions` attack) on gpt-oss:120b, one run per config.

| Config | ASR [95% CI] | Benign utility | Utility under attack |
|---|---|---|---|
| No guard (`NONE`) | 11.5% [9.6, 13.7] | 67.0% | 63.9% |
| Roles + gateway (`STATIC`) | 1.8% [1.1, 2.9] | 63.9% | 52.6% |
| + rules monitor (`ADAPTIVE_RULES`) | 0.6% [0.3, 1.4] | 63.9% | 50.8% |
| Full SwarmGuard, + decider (`ADAPTIVE`) | 1.1% [0.6, 1.9] | 64.9% | 58.6% |

- Deterministic enforcement (STATIC) does most of the security work.
- The decider raises utility under attack from 52.6% to 58.6% compared with STATIC (paired McNemar p = 0.0005) and keeps 96.9% of benign utility. Its ASR difference from STATIC is not significant (p = 0.14).
- Context against multi-CaMeL (GPT-4.1): our budget covered 249 of the 949 attack episodes (all 144 banking plus the first 105 workspace). The paper's unguarded numbers (78.4% utility, 36.1% ASR) fall inside our unguarded run's 95% intervals (81.4% [73.7, 89.2]; 31.7% [26.3, 37.7]), so the sample is consistent with their baseline. Multi-CaMeL reports 0.0% ASR at 24.7% benign utility; SwarmGuard keeps 79.4% at 1.6% ASR (244 episodes). Reported, not reproduced, and different samples: context, not a controlled comparison.

All numbers come from `results/metrics.json`; the readable summary is `results/results.md`.

## Remaining failures

10 of 949 attacks still succeed on gpt-oss:120b under ADAPTIVE: 5 web visits the gateway did not score, 3 cases where the decider overrode a rules taint hit, and 2 file deletions whose ID was too short for the taint check. 9 of the 10 passed through the orchestrator. The STRICT config (`bench/configs/ADAPTIVE_strict.yaml`) fixes all three causes in code, and an in-sample offline replay (`loop/replay_strict.py`) denies all 10, but STRICT has **not** been benchmarked end to end.

## Using `sg` in your own harness

`sg` is a Python library that replaces a harness's tool executor. It does not depend on MultiAgentDojo:

```python
from sg.schema import GuardConfig
from sg.gateway import Gateway
from sg.guard import GuardedToolsExecutor

gw = Gateway(GuardConfig.ADAPTIVE, run_id="r1", monitor=my_monitor, log_path="events.jsonl")
agent_id, token, role = gw.spawn(parent_token=None, spec_name="email_agent", tool_names=[...], task=user_task)
decision = gw.check(token, "send_email", {"recipients": ["bob@corp.com"]}, task_text=user_task)
```

Replace your tool executor with `GuardedToolsExecutor(gw, token, task_text)` and every call passes through `check()`. The `sg` CLI (`python -m sg.cli`: `token mint|verify|revoke`, `check`, `run -- <cmd>`) wraps the same gateway for shell commands; `docker/demo.sh` shows it as the only way out of a sandbox (captured output in `docker/DEMO_OUTPUT.md`). Interface notes: `sg/README.md`.

**Who it is for.** Systems built on models that do not resist injection on their own. In our runs Claude Sonnet 5.5 and Kimi K3.1 already had 0% attack success and only lost utility under the guard, while gpt-oss:120b (11.5%), gpt-oss:20b (9.8%), Gemma-4-31B (51.7%), Qwen3.5-397B (47.5%) and GPT-4.1 (31.7%) did not resist; the benefit tracks how easily a model is injected, not its size. Any architecture that spawns sub-agents (internal tools or chatbots with tool access built on open-weight models, or coding harnesses) could route its tool calls through the gateway, and the decider (2.5 GB quantized) ran on one consumer GPU. We have tested it only on MultiAgentDojo.

## Reproduce

```bash
uv sync --dev
cp .env.example .env          # provider keys
uv run pytest -q              # no network
make dry-run                  # plan + budget-gate decision per cell, launches nothing
uv run python bench/run.py --bench mad --config STATIC --model gpt-oss:120b --suite workspace --attack important_instructions --key A
make metrics                  # runs/ -> loop/metrics.py -> results/metrics.json, results/results.md
make report                   # fills docs/REPORT.md placeholders -> docs/REPORT.filled.md
```

Raw run logs (`runs/`) are not committed. Configs are in `bench/configs/`.

## Repository layout

| Path | What |
|---|---|
| `sg/` | The security layer: `schema.py` shared types, `identity.py` signed tokens, `roles.py`, `labels.py` taint, `gateway.py` checks, `guard.py` executor, `monitors.py` rules and decider monitors, `log.py` event log, `cli.py`. |
| `bench/` | `mad/` vendored MultiAgentDojo fork, `mad_guard.py` glue (one subclass), `run.py` benchmark runner, `configs/`, `attacks/`, `redteam/`, `tamper/`. |
| `train/` | Decider data converters, splits, QLoRA training, evaluation, GGUF export and Ollama `Modelfile`. |
| `loop/` | `metrics.py`, `paired.py` (McNemar tests), `compare.py`, `harvest.py`, `replay_strict.py`, and the loop driver. |
| `docker/` | Sandbox demo with `sg` as the only tool door. |
| `docs/` | `REPORT.md` (long report), `render.py`, figures, `REVIEW_2026-11-09.md` (independent review). |
| `results/` | `metrics.json`, `results.md`, decider evaluations, spend. |
| `PLAN.md`, `PROGRESS.md`, `HANDOFF.md`, `ARCHITECTURE.md` | Plan, decision log and progress notes. |

## Limitations

- One run per config. Some model cells are partial samples (for GPT-4.1, the attack episodes cover two suites).
- The taint rule arms on injection markers in tool output, so attacks without such markers are not caught by it.
- The decider shares the 97 user tasks with its training logs (public AgentDojo runs), though it saw no MultiAgentDojo trajectory.
- The adaptive red-team attacker we tried was weak (about 1% ASR even with no defence), so robustness to strong adaptive attacks is untested.
- Decider weights are not released.

## Prior and third-party work

- Only planning notes (`PLAN.md` v1 to v3, `ARCHITECTURE.md`, `HANDOFF.md`) existed before the sprint. All code, data pipelines, results and the report were written during it.
- `bench/mad/` is the MultiAgentDojo fork of AgentDojo (MIT), vendored with one in-sprint line change: `openai_llm.py` parses a tool call with null arguments as `{}` instead of crashing.
- Decider training data: AgentDojo run logs (MIT), AgentDrift (CC BY 4.0), StepGuard data (Apache-2.0), NVIDIA Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1 (CC BY 4.0).
- We build on and cite CaMeL, multi-CaMeL, Progent, AgentCap, trust-gated delegation and async control monitors.
- LLM use: Claude Code wrote code and text under the author's direction.
