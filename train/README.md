# train/ — decider data + QLoRA (PLAN §8, stream S3)

## Mac (repo .venv) — build data
```bash
uv run python -m train.from_agentdojo_runs            # data/agentdojo/runs -> train/data/raw_agentdojo.jsonl (~25 s; defense pipelines skipped)
uv run python -m train.from_agentdrift                # task-disjoint -> train/data/raw_drift_{train,val,test}.jsonl
uv run python -m train.splits                         # -> train/data/{train,val,test_ood,test_drift}.jsonl + stats.json
uv run pytest -q tests/train
# dry sample: --limit-files 500 / splits --scale 0.01
```
Line format: `{"messages":[system,user,assistant], "row": TrainRow, "cls", "source", "attack_type", "suite"}`.
OOD held out (test_ood = unseen agent model, SEEN tasks; test_drift = held-out tasks): claude-3-7-sonnet-20250219, gemini-2.0-flash-001, meta-llama_Llama-3.3-70B-Instruct, Meta-SecAlign-70B.
Labels: hijacked 9 · injection seen (AgentDrift injection_point) 6 · injection failed 4 · benign 1. `first_bad_step` = Event.step of the poisoned TOOL_RESULT.

## Transfer to the box (box cannot reach the Mac; Mac can ssh to it)
```bash
cd train && tar czf /tmp/sgtrain.tgz *.py export.sh Modelfile data/{train,val,test_ood,test_drift}.jsonl data/stats.json
scp /tmp/sgtrain.tgz jayansh-sandbox:swarmguard-train/ && ssh jayansh-sandbox 'cd swarmguard-train && tar xzf sgtrain.tgz'
```

## Box (~/swarmguard-train, separate venv — never the repo venv)
```bash
export PATH=$HOME/.local/bin:$PATH UV_HTTP_TIMEOUT=900
uv venv -p 3.12 .venv && . .venv/bin/activate
uv pip install torch --index-url https://download.pytorch.org/whl/cu130
uv pip install transformers trl peft bitsandbytes datasets accelerate huggingface_hub scikit-learn
# dry run (~15 s)
python train_lora.py --base Qwen/Qwen3-0.6B --rows data/train.jsonl --val data/val.jsonl --limit 50 --max-steps 2 --out out/dry
# real run
nohup python train_lora.py --base Qwen/Qwen3-4B-Instruct-2507 --rows data/train.jsonl --val data/val.jsonl --out out/decider > train.log 2>&1 &
# progress / ETA
tail -c 2000 train.log | tr '\r' '\n' | grep -E '[0-9]+/[0-9]+ \[' | tail -1      # step/total [elapsed<remaining]
grep -o "{'loss'[^}]*}" train.log | tail -3; grep -o "{'eval_loss'[^}]*}" train.log | tail -2
nvidia-smi --query-gpu=utilization.gpu,memory.used --format=csv
# export -> Ollama
bash export.sh out/decider/merged && ollama run swarmguard-decider --format json < /dev/null
```

## Eval (from Mac against the box's Ollama, or on the box with the adapter)
```bash
uv run python train/eval.py --endpoint http://100.73.163.94:11434/v1 --model swarmguard-decider --limit 300
python train/eval.py --splits data_v2/test_ood.jsonl data_v2/test_drift.jsonl --adapter out/decider/adapter --limit 300   # box, from ~/swarmguard-train (sg/ + train/ copied; box venv needs pydantic)
```
Writes `results/decider_eval.json`: F1@risk≥8, PR-AUC, FPR@95%recall, FPR@risk≥8, onset ±1 acc, JSON-fail rate, per attack_type,
plus a `sweep` per split (cutoffs 0..10 step 0.5) and a top-level `calibration` (cutoff_fpr≤2%, ≤1%, benign_p90, risk_map knots) pooled over all `--splits`
(pass val alone to calibrate on val). Use `--out`: the default path is the loop's flat summary (below) and would be overwritten.
```bash
uv run python train/eval.py --calibrate-from results/decider_eval_v3_val.json   # prints the risk_map yaml line, no model loaded
make calibrate ITER=N   # loop: eval the served new tag on val + tests -> loop/iter_N/risk_map.yaml + flat results/decider_eval.json
```
Flat `results/decider_eval.json` keys (read by loop/targets.yaml decider.*): f1, fpr_at_95_recall, test_mad_ood_f1, benign_fpr_attenuate, calibration, splits.
Zero-shot baselines (gpt-oss:20b/120b as decider): `results/decider_eval_zeroshot_gpt-oss-{20b,120b}.json`.

## Runtime contract (S-runtime LLMMonitor)
- Build the prompt with `train.common.user_prompt(task, role, window)` / `to_chat(..., with_answer=False)`; parse with `parse_verdict` (None -> FLAG).
- Keep the full tool output (≤4000 chars, as `sg.gateway.ingest` does) in `Event.result_preview`. `common.clip` shows 300 chars
  centred on the first `sg.monitors` injection marker (head if none). Training uses the same rule, so do not pre-truncate.
- Labels: window ends at the poisoned TOOL_RESULT -> risk 6 (injection seen, any outcome); agent acted on it -> 9; agent ignored it -> 4; benign 1.
- An early poisoned result stays in the window (first event) like `sg.gateway.window`.
- Resume a stopped run: `python train_lora.py ... --resume` (newest out/decider/checkpoint-*).

## v3 data (PLAN §8a, loop §5 step 7) — `train/data_v3/`
```bash
uv run python -m train.from_mad_runs --runs runs/mad --configs NONE STATIC ADAPTIVE_RULES   # -> mad_rows.jsonl + mad_stats.json (rerun after each bench round)
uv run python -m train.synth_teacher --out train/data_v3                                     # -> synth_rows.jsonl (Command Code, ≤ $1; already run, 600 rows)
uv run python -m train.merge_v3                                                              # -> data_v3/{train,val,test_mad_ood}.jsonl + stats.json
```
`from_mad_runs` rows: `{row: TrainRow, cls: benign|hijack|resisted, meta: {config, suite, user_task_id, injection_task_id, attack}}`; guard-denied calls
(`DENIED_<tool>`) are recorded under the plain tool name. Labeling rules: module docstring (PLAN §8a item 1). `synth_teacher` caps: `--max-rows`/`--max-usd`.
`merge_v3`: v2 train/val + MAD + synth (`--extra` takes more converter outputs, e.g. stepguard/nvidia_ipi — built, held for v4; off by default).
MAD rows from deepseek-v4.1-flash → `test_mad_ood` only (unseen agent model). v2 `test_ood`/`test_drift` stay in `train/data` untouched
(their prompts are banned from v3 train/val). New-source rows go to val 1 in 10 by run_id. Dedupe on the prompt only (task+window), one copy per prompt
across train/val/test_mad_ood (higher risk wins a label conflict); mad/synth/extra rows whose pipeline names the held-out model are dropped
(except `synth*`), so loop `--extra` rows can't leak it. Groups by gold risk (hijacked ≥8 · benign ≤2 · failed = 4/6) kept within 2:1, synth ≤ 30% of train; v2 rows are cut first.
Same line format as v2 (`splits.emit`). Box steps (push, train `out/decider_v3` from `ninty-seven/StepGuard`, 500 steps — fallback base
`Qwen/Qwen3-4B-Instruct-2507` —, `swarmguard-decider:v3`, eval, calibration): `data_v3/BOX_COMMANDS.md`. Current build (08:40, partial bench tree):
train 13,417 · val 1,212 · test_mad_ood 494 (17 hijacked). Rerun `from_mad_runs` + `merge_v3` when benches finish.
