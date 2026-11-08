#!/usr/bin/env bash
# merged HF model -> GGUF f16 -> Ollama q4_K_M (SC3 recipe). Run on the box from ~/swarmguard-train.
# Usage: bash export.sh [merged_dir=out/decider/merged]
set -euo pipefail
MERGED=${1:-out/decider/merged}
[ -d llama.cpp ] || git clone --depth 1 https://github.com/ggml-org/llama.cpp
. .venv/bin/activate
uv pip install -q -r llama.cpp/requirements/requirements-convert_hf_to_gguf.txt
python llama.cpp/convert_hf_to_gguf.py "$MERGED" --outfile decider-f16.gguf --outtype f16
# ponytail: ollama create -q quantizes from F16; if it fails for qwen3, build llama-quantize:
#   cmake -B build llama.cpp && cmake --build build -j --target llama-quantize
#   ./build/bin/llama-quantize decider-f16.gguf decider-q4_k_m.gguf Q4_K_M  (then FROM ./decider-q4_k_m.gguf)
ollama create swarmguard-decider -q q4_K_M -f Modelfile
ollama list | grep swarmguard-decider
