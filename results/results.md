# Results (mad) — generated 2026-11-08 08:19:36 CET

Ours = measured from run logs (pooled over suites; ASR Wilson 95% CI, utility Wald 95% CI). ASR = % injected runs where the injection goal was achieved. Δ = ours − NONE (negative = utility cost).

| Config | Model | Utility | 95% CI | Util. under attack | ASR | 95% CI | n benign | n injected | errors | benign denied % | attack denied % | attenuate | killed runs | p50 ms | p95 ms | util Δ vs NONE | retention % | $ |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ADAPTIVE_RULES | gpt-oss:120b | 63.9 | [54.4, 73.5] | 49.6 | 0.9 | [0.4, 2.1] | 97 | 556 | 0 | 0.1 | 6.4 | 230 | 68 | 0.55 | 2.12 | – | – | 0.6095 |
| NONE | deepseek-v4.1-flash | 89.3 | [81.2, 97.4] | 95.6 | 0.0 | [0.0, 1.5] | 56 | 251 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 2.5043 |
| NONE | gpt-4.1 | 80.4 | [70.0, 90.8] | 66.7 | 31.7 | [26.3, 37.7] | 56 | 249 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | – |
| NONE | gpt-oss:120b | 55.6 | [32.6, 78.5] | 63.2 | 12.2 | [10.2, 14.5] | 18 | 878 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 0.7132 |
| NONE | gpt-oss:20b | 50.5 | [40.6, 60.5] | 47.8 | 10.6 | [6.9, 15.9] | 97 | 180 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 0.2754 |
| STATIC | gpt-oss:120b | 63.9 | [54.4, 73.5] | 53.9 | 0.9 | [0.4, 2.2] | 97 | 538 | 0 | 0.4 | 19.4 | 0 | 0 | 0.5 | 1.54 | – | – | 0.6668 |
| STATIC | gpt-oss:20b | 62.0 | [50.7, 73.3] | 53.6 | 0.0 | [0.0, 2.1] | 71 | 181 | 0 | 0.2 | 11.8 | 0 | 0 | 0.65 | 1.87 | – | – | 0.553 |

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

total 5.3246 · by provider {'anthropic': 0.0, 'commandcode': 2.5043, 'ollama': 2.8203, 'openrouter': 0.0} · Ollama by key {'A': 0.6818, 'B': 0.8057, 'unknown': 1.3328} · by model {'deepseek-v4.1-flash': 2.5043, 'gpt-oss:120b': 1.9895, 'gpt-oss:20b': 0.8307}
