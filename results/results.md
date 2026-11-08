# Results (mad) — generated 2026-11-08 05:46:37 CET

Ours = measured from run logs (pooled over suites; ASR Wilson 95% CI, utility Wald 95% CI). ASR = % injected runs where the injection goal was achieved. Δ = ours − NONE (negative = utility cost).

| Config | Model | Utility | 95% CI | Util. under attack | ASR | 95% CI | n benign | n injected | errors | benign denied % | attenuate | kill | p50 ms | p95 ms | util Δ vs NONE | $ |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| NONE | gpt-4.1 | 80.4 | [70.0, 90.8] | 66.7 | 31.7 | [26.3, 37.7] | 56 | 249 | 0 | – | 0 | 0 | – | – | 0.0 | – |
| NONE | gpt-oss:20b | 100.0 | [100.0, 100.0] | – | – | – | 1 | 0 | 0 | – | 0 | 0 | – | – | 0.0 | 0.0008 |
| STATIC | gpt-oss:20b | 100.0 | [100.0, 100.0] | – | – | – | 1 | 0 | 0 | – | 0 | 0 | – | – | 0.0 | 0.0004 |

## Reference (reported, not replicated)†

| Model | ASR none | ASR indiv-CaMeL | ASR multi-CaMeL | Util none | Util indiv-CaMeL | Util multi-CaMeL | Util Δ multi vs none |
|---|---|---|---|---|---|---|---|
| gpt-4.1 | 36.1† | 0.5† | 0.0† | 78.4† | 38.1† | 24.7† | -53.7† |
| gemini-2.5-pro | 24.6† | 0.4† | 0.0† | 76.3† | 42.3† | 26.8† | -49.5† |
| gpt-5.5 | 0.0† | 0.0† | 0.0† | 86.6† | 73.2† | 66.0† | -20.6† |
| gemini-2.5-flash-lite | 2.1† | 0.0† | 0.0† | 27.8† | 13.4† | 7.2† | -20.6† |
| claude-fable-5 | 1.5† | 0.0† | 0.0† | 69.1† | 53.6† | 52.6† | -16.5† |

† Reported in Peters-Gill et al. (2026), arXiv:2610.05640, Tab. III (ASR, n=949) / Tab. V (utility, n=97); models via OpenRouter; not replicated by us.
