# Results (mad) — generated 2026-11-08 07:26:31 CET

Ours = measured from run logs (pooled over suites; ASR Wilson 95% CI, utility Wald 95% CI). ASR = % injected runs where the injection goal was achieved. Δ = ours − NONE (negative = utility cost).

| Config | Model | Utility | 95% CI | Util. under attack | ASR | 95% CI | n benign | n injected | errors | benign denied % | attack denied % | attenuate | killed runs | p50 ms | p95 ms | util Δ vs NONE | retention % | $ |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ADAPTIVE_RULES | gpt-oss:120b | 63.9 | [54.4, 73.5] | 56.7 | 1.3 | [0.5, 3.2] | 97 | 314 | 0 | 0.1 | 4.5 | 83 | 43 | 0.48 | 1.93 | 7.7 | 113.7 | 0.3767 |
| NONE | deepseek-v4.1-flash | 90.9 | [73.9, 100.0] | 59.1 | 0.0 | [0.0, 14.9] | 11 | 22 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 1.5616 |
| NONE | gpt-4.1 | 80.4 | [70.0, 90.8] | 66.7 | 31.7 | [26.3, 37.7] | 56 | 249 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | – |
| NONE | gpt-oss:120b | 56.2 | [31.9, 80.6] | 64.3 | 14.0 | [11.6, 16.8] | 16 | 687 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 0.2888 |
| NONE | gpt-oss:20b | 50.6 | [40.1, 61.1] | 44.7 | 11.3 | [7.2, 17.4] | 87 | 150 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 0.2145 |
| STATIC | gpt-oss:120b | 63.9 | [54.4, 73.5] | 63.9 | 0.7 | [0.2, 2.5] | 97 | 291 | 0 | 0.4 | 14.6 | 0 | 0 | 0.43 | 1.42 | 7.7 | 113.7 | 0.1992 |
| STATIC | gpt-oss:20b | 73.3 | [51.0, 95.7] | 70.0 | 0.0 | [0.0, 11.4] | 15 | 30 | 0 | 0.0 | 4.7 | 0 | 0 | 0.74 | 1.79 | – | – | 0.4652 |

## Reference (reported, not replicated)†

| Model | ASR none | ASR indiv-CaMeL | ASR multi-CaMeL | Util none | Util indiv-CaMeL | Util multi-CaMeL | Util Δ multi vs none |
|---|---|---|---|---|---|---|---|
| gpt-4.1 | 36.1† | 0.5† | 0.0† | 78.4† | 38.1† | 24.7† | -53.7† |
| gemini-2.5-pro | 24.6† | 0.4† | 0.0† | 76.3† | 42.3† | 26.8† | -49.5† |
| gpt-5.5 | 0.0† | 0.0† | 0.0† | 86.6† | 73.2† | 66.0† | -20.6† |
| gemini-2.5-flash-lite | 2.1† | 0.0† | 0.0† | 27.8† | 13.4† | 7.2† | -20.6† |
| claude-fable-5 | 1.5† | 0.0† | 0.0† | 69.1† | 53.6† | 52.6† | -16.5† |

† Reported in Peters-Gill et al. (2026), arXiv:2610.05640, Tab. III (ASR, n=949) / Tab. V (utility, n=97); models via OpenRouter; not replicated by us.

## Spend (est. USD)

total 3.1084 · by provider {'commandcode': 1.5616, 'ollama': 1.5468, 'openrouter': 0.0} · Ollama by key {'A': 0.4108, 'B': 0.646, 'unknown': 0.49} · by model {'deepseek-v4.1-flash': 1.5616, 'gpt-oss:120b': 0.8647, 'gpt-oss:20b': 0.682}
