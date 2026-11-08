# Decider v3 — box commands (PLAN §8a item 5, loop §5 step 7 "retrain")

Box = `jayansh-sandbox` (ssh from the Mac; the box cannot reach the Mac), dir `~/swarmguard-train`, its own `.venv`.
v2 got there by **tar + scp** (train/README.md "Transfer to the box"; box already has `data_v2/`, `sg/`, `train/`), so v3 uses the same.
**Do not start (b) until v2 training has finished (≈ 08:45 CET) — one GPU.** Check: `ssh jayansh-sandbox 'nvidia-smi --query-gpu=utilization.gpu,memory.used --format=csv; pgrep -af train_lora'`.

## Data decision (C20): v3 = v2 + MAD + synth only. `stepguard_rows.jsonl` / `nvidia_ipi_rows.jsonl` are built but held for v4 (`merge_v3 --extra ...`): 2 h GPU budget, in-distribution first, StepGuard base already saw StepGuard-Data.

## 0. Mac — build the data (≈ 10 s; rerun after a new bench round)
```bash
uv run python -m train.from_mad_runs --runs runs/mad --configs NONE STATIC ADAPTIVE_RULES \
  --out train/data_v3/mad_rows.jsonl --stats train/data_v3/mad_stats.json
uv run python -m train.merge_v3          # -> train/data_v3/{train,val,test_mad_ood}.jsonl + stats.json
```

## a. Push data_v3 (+ current sg/ and train/ code for eval) to the box
```bash
COPYFILE_DISABLE=1 tar czf /tmp/sgv3.tgz train/data_v3/{train,val,test_mad_ood}.jsonl train/data_v3/stats.json \
  train/*.py train/export.sh train/Modelfile sg/*.py
scp /tmp/sgv3.tgz jayansh-sandbox:swarmguard-train/
ssh jayansh-sandbox 'cd swarmguard-train && tar xzf sgv3.tgz && mkdir -p data_v3 && mv train/data_v3/* data_v3/ \
  && cp train/train_lora.py train/eval.py train/common.py . && wc -l data_v3/*.jsonl'
```

## b. Train fresh QLoRA (box, ≈ 2 h at ≈ 15 s/step)
```bash
ssh jayansh-sandbox
cd ~/swarmguard-train && . .venv/bin/activate && export PATH=$HOME/.local/bin:$PATH
nohup python train_lora.py --base ninty-seven/StepGuard --rows data_v3/train.jsonl --val data_v3/val.jsonl \
  --out out/decider_v3 --max-steps 500 > train_v3.log 2>&1 &
tail -c 2000 train_v3.log | tr '\r' '\n' | grep -E '[0-9]+/[0-9]+ \[' | tail -1      # progress / ETA
# stopped? same command + --resume
```
Base = `ninty-seven/StepGuard` (orchestrator decision 08:40 CET, PLAN §8a item 4 / C20): Qwen3ForCausalLM, same tokenizer family as v2's Qwen3-4B-Instruct-2507, already cached on the box. Fallback if it fails to load or its chat template breaks ChatML: `--base Qwen/Qwen3-4B-Instruct-2507`. v2 stays served as `swarmguard-decider:v2`.

## c. Export -> Ollama as `swarmguard-decider:v3` (box)
`export.sh` ends with `ollama create swarmguard-decider` (untagged), which would overwrite the v2 model, so run its steps with the v3 tag:
```bash
cd ~/swarmguard-train && . .venv/bin/activate
python llama.cpp/convert_hf_to_gguf.py out/decider_v3/merged --outfile decider-f16.gguf --outtype f16
ollama create swarmguard-decider:v3 -q q4_K_M -f Modelfile
ollama list | grep swarmguard-decider && ollama run swarmguard-decider:v3 --format json < /dev/null
```

## d. Eval sweep (Mac against the box's Ollama over LAN; Bash sandbox off, as for the ADAPTIVE cells)
```bash
H=http://192.168.0.146:11434/v1
# calibration source = val only (eval.py pools calibration over --splits)
uv run python train/eval.py --endpoint $H --model swarmguard-decider:v3 --splits train/data_v3/val.jsonl \
  --out results/decider_eval_v3_val.json
# held-out report (v2 tests untouched + MAD OOD model)
uv run python train/eval.py --endpoint $H --model swarmguard-decider:v3 --limit 300 \
  --splits train/data/test_ood.jsonl train/data/test_drift.jsonl train/data_v3/test_mad_ood.jsonl \
  --out results/decider_eval_v3_test.json
```
Box fallback (adapter, no Ollama): `python train/eval.py --adapter out/decider_v3/adapter --splits data_v3/val.jsonl --out decider_eval_v3_val.json`
(and the same with `data_v2/test_ood.jsonl data_v2/test_drift.jsonl data_v3/test_mad_ood.jsonl`), then scp the JSONs to `results/`.
Note: `test_mad_ood` currently has 0 hijacked rows (deepseek NONE runs so far had no successful attacks) → it only measures FPR.

## e. Calibration -> ADAPTIVE.yaml
```bash
uv run python train/eval.py --calibrate-from results/decider_eval_v3_val.json
# prints:   risk_map: [[0.0, 0.0], ...]   # from ...: fpr<=2% cutoff X, fpr<=1% cutoff Y
```
Paste that line over `risk_map:` in `bench/configs/ADAPTIVE.yaml` **and** `bench/configs/ADAPTIVE_AUDIT.yaml` (monitor block) and set `host_model: swarmguard-decider:v3` in both; serve with
`export SG_DECIDER_HOST=http://192.168.0.146:11434/v1`. Then the loop continues at §5 step 3 (bench, ADAPTIVE only) and
the orchestrator logs the iteration in PROGRESS.md. Report ADAPTIVE(v2) and ADAPTIVE(v3) side by side (PLAN §8a honesty).
