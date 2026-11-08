#!/usr/bin/env bash
# merged HF model -> GGUF f16 -> Ollama q4_K_M (SC3 recipe). Run on the box from ~/swarmguard-train.
# Usage: bash export.sh [merged_dir=out/decider/merged] [tag=swarmguard-decider]   (e.g. swarmguard-decider:v3)
set -euo pipefail
MERGED=${1:-out/decider/merged}
TAG=${2:-swarmguard-decider}
[ -d llama.cpp ] || git clone --depth 1 https://github.com/ggml-org/llama.cpp
# NEVER install llama.cpp's requirements into .venv: they pin torch==2.11.0+cpu and transformers 4.57.6 and wrecked the
# training venv on 2026-11-08 (CPU torch, hub mismatch). Conversion runs in its own venv.
[ -d .venv-gguf ] || uv venv .venv-gguf --python 3.12
uv pip install --python .venv-gguf/bin/python -q -r llama.cpp/requirements/requirements-convert_hf_to_gguf.txt
# transformers 4.57 cannot read the list-valued extra_special_tokens that newer transformers write -> drop the key
python3 -c "import json,sys;p='$MERGED/tokenizer_config.json';t=json.load(open(p));isinstance(t.get('extra_special_tokens'),list) and (t.pop('extra_special_tokens'),json.dump(t,open(p,'w'),indent=2))"
.venv-gguf/bin/python llama.cpp/convert_hf_to_gguf.py "$MERGED" --outfile decider-f16.gguf --outtype f16
# ponytail: ollama create -q quantizes from F16; if it fails for qwen3, build llama-quantize:
#   cmake -B build llama.cpp && cmake --build build -j --target llama-quantize
#   ./build/bin/llama-quantize decider-f16.gguf decider-q4_k_m.gguf Q4_K_M  (then FROM ./decider-q4_k_m.gguf)
ollama create "$TAG" -q q4_K_M -f Modelfile
ollama list | grep swarmguard-decider
