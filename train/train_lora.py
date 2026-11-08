"""QLoRA SFT of the decider (PLAN §8, SC3 recipe). Runs on the Linux box venv, not the repo .venv.

Reused: trl SFTTrainer + peft LoRA + bitsandbytes 4-bit (SC3 fallback path; Unsloth skipped for install
reliability on sm_120). Data = train/data/{train,val}.jsonl "messages" -> prompt/completion (loss on the
assistant JSON only, trl default for prompt-completion datasets).
Dry run: python train_lora.py --base Qwen/Qwen3-0.6B --rows data/train.jsonl --max-steps 2 --limit 50
"""
from __future__ import annotations

import argparse
import json
import os

import torch
from datasets import Dataset
from peft import LoraConfig, PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import SFTConfig, SFTTrainer


def load_rows(path, limit=0):
    out = []
    with open(path) as f:
        for i, line in enumerate(f):
            if limit and i >= limit:
                break
            m = json.loads(line)["messages"]
            out.append({"prompt": m[:-1], "completion": m[-1:]})
    return Dataset.from_list(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="Qwen/Qwen3-4B-Instruct-2507")
    ap.add_argument("--rows", default="data/train.jsonl")
    ap.add_argument("--val", default="")
    ap.add_argument("--out", default="out/decider")
    ap.add_argument("--max-steps", type=int, default=-1)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--epochs", type=float, default=2)
    ap.add_argument("--bs", type=int, default=4)
    ap.add_argument("--accum", type=int, default=4)
    ap.add_argument("--no-merge", action="store_true")
    a = ap.parse_args()
    cuda = torch.cuda.is_available()
    tok = AutoTokenizer.from_pretrained(a.base)
    tok.pad_token = tok.pad_token or tok.eos_token
    q = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.bfloat16,
                           bnb_4bit_use_double_quant=True) if cuda else None
    model = AutoModelForCausalLM.from_pretrained(a.base, quantization_config=q, dtype=torch.bfloat16 if cuda else torch.float32,
                                                 device_map={"": 0} if cuda else None)
    lora = LoraConfig(r=32, lora_alpha=32, lora_dropout=0.0, task_type="CAUSAL_LM",
                      target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"])
    train = load_rows(a.rows, a.limit)
    val = load_rows(a.val, max(a.limit // 5, 0) or 400) if a.val else None
    cfg = SFTConfig(
        output_dir=a.out, num_train_epochs=a.epochs, max_steps=a.max_steps, per_device_train_batch_size=a.bs,
        gradient_accumulation_steps=a.accum, learning_rate=2e-4, lr_scheduler_type="cosine", warmup_steps=0.03,  # transformers 5: float = ratio
        bf16=cuda, gradient_checkpointing=True, max_length=4096, packing=False, logging_steps=10,
        eval_strategy="steps" if val is not None else "no", eval_steps=200, per_device_eval_batch_size=a.bs,
        save_steps=300, save_total_limit=2, report_to="none", seed=42, use_cpu=not cuda,
    )
    tr = SFTTrainer(model=model, args=cfg, train_dataset=train, eval_dataset=val, processing_class=tok, peft_config=lora)
    tr.train()
    adapter = os.path.join(a.out, "adapter")
    tr.model.save_pretrained(adapter)
    tok.save_pretrained(adapter)
    print("adapter ->", adapter)
    if a.no_merge:
        return
    del tr, model
    if cuda:
        torch.cuda.empty_cache()
    base = AutoModelForCausalLM.from_pretrained(a.base, dtype=torch.bfloat16)
    merged = PeftModel.from_pretrained(base, adapter).merge_and_unload()
    mdir = os.path.join(a.out, "merged")
    merged.save_pretrained(mdir, safe_serialization=True)
    tok.save_pretrained(mdir)
    print("merged ->", mdir)


if __name__ == "__main__":
    main()
