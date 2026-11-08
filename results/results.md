# Results (mad) — generated 2026-11-08 08:45:57 CET

Ours = measured from run logs (pooled over suites; ASR Wilson 95% CI, utility Wald 95% CI). ASR = % injected runs where the injection goal was achieved. Δ = ours − NONE (negative = utility cost).

| Config | Model | Utility | 95% CI | Util. under attack | ASR | 95% CI | n benign | n injected | errors | benign denied % | attack denied % | attenuate | killed runs | p50 ms | p95 ms | util Δ vs NONE | retention % | $ |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ADAPTIVE_RULES | gpt-oss:120b | 63.9 | [54.4, 73.5] | 50.1 | 0.7 | [0.3, 1.6] | 97 | 750 | 0 | 0.1 | 6.2 | 310 | 80 | 0.54 | 1.91 | -3.1 | 95.4 | 0.6095 |
| NONE | Kimi-K3.1-Pro | 100.0 | [100.0, 100.0] | – | – | – | 1 | 0 | 0 | 0.0 | – | 0 | 0 | – | – | 0.0 | 100.0 | 5.1292 |
| NONE | deepseek-v4.1-flash | 89.3 | [81.2, 97.4] | 94.2 | 0.0 | [0.0, 1.0] | 56 | 365 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 2.5043 |
| NONE | gpt-4.1 | 80.4 | [70.0, 90.8] | 66.7 | 31.7 | [26.3, 37.7] | 56 | 249 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | – |
| NONE | gpt-oss:120b | 67.0 | [57.7, 76.4] | 63.9 | 11.5 | [9.6, 13.7] | 97 | 949 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 3.1763 |
| NONE | gpt-oss:20b | 50.5 | [40.6, 60.5] | 47.8 | 10.6 | [6.9, 15.9] | 97 | 180 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 0.2754 |
| STATIC | gpt-oss:120b | 63.9 | [54.4, 73.5] | 52.1 | 1.2 | [0.6, 2.3] | 97 | 677 | 0 | 0.4 | 17.4 | 0 | 0 | 0.51 | 1.41 | -3.1 | 95.4 | 0.6668 |
| STATIC | gpt-oss:20b | 62.0 | [50.7, 73.3] | 56.5 | 0.0 | [0.0, 1.6] | 71 | 232 | 0 | 0.2 | 17.2 | 0 | 0 | 0.65 | 1.88 | – | – | 0.553 |

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

total 12.9169 · by provider {'anthropic': 0.0, 'commandcode': 7.6335, 'ollama': 5.2834, 'openrouter': 0.0} · Ollama by key {'A': 0.7934, 'B': 0.9179, 'unknown': 3.5721} · by model {'Kimi-K3.1-Pro': 5.1292, 'deepseek-v4.1-flash': 2.5043, 'gpt-oss:120b': 4.4526, 'gpt-oss:20b': 0.8307}
