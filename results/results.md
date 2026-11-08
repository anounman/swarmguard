# Results (mad) — generated 2026-11-08 09:56:44 CET

Ours = measured from run logs (pooled over suites; ASR Wilson 95% CI, utility Wald 95% CI). ASR = % injected runs where the injection goal was achieved. Δ = ours − NONE (negative = utility cost).

| Config | Model | Utility | 95% CI | Util. under attack | ASR | 95% CI | n benign | n injected | errors | benign denied % | attack denied % | attenuate | killed runs | p50 ms | p95 ms | util Δ vs NONE | retention % | $ |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ADAPTIVE | deepseek-v4.1-flash | 92.9 | [86.1, 99.6] | 84.9 | 0.0 | [0.0, 2.0] | 56 | 185 | 0 | 2.7 | 1.9 | 7 | 27 | 0.55 | 1292.77 | – | – | 3.9891 |
| ADAPTIVE | gpt-4.1 | 80.4 | [70.0, 90.8] | 79.0 | 0.0 | [0.0, 3.7] | 56 | 100 | 0 | 0.8 | 6.3 | 26 | 2 | 0.56 | 2167.04 | 0.0 | 100.0 | 5.7466 |
| ADAPTIVE | gpt-oss:120b | 67.8 | [58.0, 77.6] | 63.7 | 1.7 | [0.8, 3.5] | 87 | 405 | 0 | 1.4 | 4.3 | 97 | 54 | 0.67 | 2077.07 | 0.8 | 101.2 | 3.0536 |
| ADAPTIVE | gpt-oss:20b | 76.5 | [56.3, 96.6] | 69.8 | 0.0 | [0.0, 6.8] | 17 | 53 | 0 | 0.0 | 0.7 | 1 | 3 | 0.8 | 843.68 | – | – | 1.1641 |
| ADAPTIVE_RULES | gpt-oss:120b | 63.9 | [54.4, 73.5] | 50.8 | 0.6 | [0.3, 1.4] | 97 | 949 | 0 | 0.1 | 5.8 | 406 | 91 | 0.6 | 1.91 | -3.1 | 95.4 | 3.8477 |
| NONE | Kimi-K3.1-Pro | 100.0 | [100.0, 100.0] | 76.9 | 0.0 | [0.0, 9.0] | 16 | 39 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 5.6183 |
| NONE | deepseek-v4.1-flash | 90.9 | [84.5, 97.3] | 92.6 | 1.8 | [1.1, 3.2] | 77 | 649 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 3.6882 |
| NONE | gpt-4.1 | 80.4 | [70.0, 90.8] | 66.7 | 31.7 | [26.3, 37.7] | 56 | 249 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | – |
| NONE | gpt-oss:120b | 67.0 | [57.7, 76.4] | 63.9 | 11.5 | [9.6, 13.7] | 97 | 949 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 3.1763 |
| NONE | gpt-oss:20b | 50.5 | [40.6, 60.5] | 46.1 | 10.6 | [7.2, 15.4] | 97 | 217 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 1.3143 |
| STATIC | gpt-oss:120b | 63.9 | [54.4, 73.5] | 54.1 | 1.4 | [0.8, 2.4] | 97 | 923 | 0 | 0.4 | 16.3 | 0 | 0 | 0.58 | 1.42 | -3.1 | 95.4 | 3.5006 |
| STATIC | gpt-oss:20b | 62.0 | [50.7, 73.3] | 52.7 | 0.3 | [0.0, 1.5] | 71 | 372 | 0 | 0.2 | 14.4 | 0 | 0 | 0.68 | 1.95 | – | – | 0.553 |

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

total 35.6541 · by provider {'anthropic': 0.0, 'commandcode': 13.2956, 'ollama': 16.6119, 'openrouter': 5.7466} · Ollama by key {'A': 5.0585, 'B': 5.1476, 'unknown': 6.4058} · by model {'Kimi-K3.1-Pro': 5.6183, 'deepseek-v4.1-flash': 7.6773, 'gpt-4.1': 5.7466, 'gpt-oss:120b': 13.5782, 'gpt-oss:20b': 3.0337}
