# Results (mad) — generated 2026-11-08 07:22:01 CET

Ours = measured from run logs (pooled over suites; ASR Wilson 95% CI, utility Wald 95% CI). ASR = % injected runs where the injection goal was achieved. Δ = ours − NONE (negative = utility cost).

| Config | Model | Utility | 95% CI | Util. under attack | ASR | 95% CI | n benign | n injected | errors | benign denied % | attenuate | kill | p50 ms | p95 ms | util Δ vs NONE | retention % | $ |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ADAPTIVE_RULES | gpt-oss:120b | 64.6 | [55.0, 74.2] | 57.0 | 1.3 | [0.5, 3.4] | 96 | 298 | 0 | – | 69 | 48 | 0.46 | 1.81 | 8.4 | 114.9 | 0.2628 |
| NONE | deepseek-v4.1-flash | 85.7 | [59.8, 100.0] | 42.9 | 0.0 | [0.0, 21.5] | 7 | 14 | 0 | – | 0 | 0 | – | – | 0.0 | 100.0 | 1.5616 |
| NONE | gpt-4.1 | 80.4 | [70.0, 90.8] | 66.7 | 31.7 | [26.3, 37.7] | 56 | 249 | 0 | – | 0 | 0 | – | – | 0.0 | 100.0 | – |
| NONE | gpt-oss:120b | 56.2 | [31.9, 80.6] | 64.9 | 14.1 | [11.7, 17.0] | 16 | 679 | 0 | – | 0 | 0 | – | – | 0.0 | 100.0 | 0.2888 |
| NONE | gpt-oss:20b | 52.4 | [41.6, 63.2] | 47.4 | 10.2 | [6.2, 16.4] | 82 | 137 | 0 | – | 0 | 0 | – | – | 0.0 | 100.0 | 0.193 |
| STATIC | gpt-oss:120b | 63.9 | [54.4, 73.5] | 64.8 | 0.7 | [0.2, 2.7] | 97 | 270 | 0 | – | 0 | 0 | 0.41 | 1.34 | 7.7 | 113.7 | 0.1992 |
| STATIC | gpt-oss:20b | 71.4 | [38.0, 100.0] | 83.3 | 0.0 | [0.0, 24.2] | 7 | 12 | 0 | – | 0 | 0 | 0.83 | 2.24 | – | – | 0.3759 |

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

total 2.8837 · by provider {'commandcode': 1.5616, 'ollama': 1.3221} · Ollama by key {'?': 0.49, 'A': 0.3893, 'B': 0.4428}
