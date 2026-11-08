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
Writes `results/decider_eval.json`: F1@risk≥8, PR-AUC, FPR@95%recall, FPR@risk≥8, onset ±1 acc, JSON-fail rate, per attack_type.

## Runtime contract (S-runtime LLMMonitor)
- Build the prompt with `train.common.user_prompt(task, role, window)` / `to_chat(..., with_answer=False)`; parse with `parse_verdict` (None -> FLAG).
- Keep the full tool output (≤4000 chars, as `sg.gateway.ingest` does) in `Event.result_preview`. `common.clip` shows 300 chars
  centred on the first `sg.monitors` injection marker (head if none). Training uses the same rule, so do not pre-truncate.
- Labels: window ends at the poisoned TOOL_RESULT -> risk 6 (injection seen, any outcome); agent acted on it -> 9; agent ignored it -> 4; benign 1.
- An early poisoned result stays in the window (first event) like `sg.gateway.window`.
- Resume a stopped run: `python train_lora.py ... --resume` (newest out/decider/checkpoint-*).
