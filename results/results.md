# Results (mad) — generated 2026-11-08 18:28:11 CET

Ours = measured from run logs (pooled over suites; ASR Wilson 95% CI, utility Wald 95% CI). ASR = % injected runs where the injection goal was achieved. Δ = ours − NONE (negative = utility cost).

| Config | Model | Utility | 95% CI | Util. under attack | ASR | 95% CI | n benign | n injected | errors | benign denied % | attack denied % | attenuate | killed runs | p50 ms | p95 ms | util Δ vs NONE | retention % | $ |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ADAPTIVE | Kimi-K3.1-Pro | 93.8 | [81.9, 100.0] | 81.7 | 0.0 | [0.0, 4.0] | 16 | 93 | 0 | 2.4 | 0.0 | 3 | 1 | 0.78 | 470.58 | -6.2 | 93.8 | 5.9828 |
| ADAPTIVE | claude-sonnet-5-5 | 95.7 | [87.3, 100.0] | – | – | – | 23 | 0 | 0 | 0.0 | – | 0 | 0 | 0.52 | 419.12 | -4.3 | 95.7 | 2.592 |
| ADAPTIVE | deepseek-v4.1-flash | 93.5 | [88.0, 99.0] | 79.6 | 0.2 | [0.0, 1.0] | 77 | 560 | 0 | 3.0 | 5.5 | 106 | 71 | 0.59 | 1134.17 | – | – | 6.563 |
| ADAPTIVE | gpt-4.1 | 85.0 | [77.2, 92.8] | 79.0 | 0.0 | [0.0, 3.7] | 80 | 100 | 0 | 0.8 | 6.3 | 27 | 2 | 0.54 | 1599.88 | – | – | 7.2623 |
| ADAPTIVE | gpt-oss:120b | 64.9 | [55.5, 74.4] | 58.6 | 1.1 | [0.6, 1.9] | 97 | 949 | 0 | 1.1 | 3.4 | 258 | 97 | 0.67 | 1295.62 | -2.1 | 96.9 | 10.0456 |
| ADAPTIVE | gpt-oss:20b | 50.5 | [40.6, 60.5] | 40.7 | 0.9 | [0.5, 1.8] | 97 | 949 | 0 | 1.0 | 2.2 | 100 | 137 | 0.67 | 378.78 | 0.0 | 100.0 | 1.988 |
| ADAPTIVE_RULES | deepseek-v4.1-flash | 92.8 | [87.6, 97.9] | 68.9 | 2.8 | [1.8, 4.3] | 97 | 685 | 0 | 0.8 | 9.0 | 324 | 82 | 0.57 | 1.54 | 2.1 | 102.3 | 6.7772 |
| ADAPTIVE_RULES | gpt-oss:120b | 63.9 | [54.4, 73.5] | 50.8 | 0.6 | [0.3, 1.4] | 97 | 949 | 0 | 0.1 | 5.8 | 406 | 91 | 0.6 | 1.91 | -3.1 | 95.4 | 3.8477 |
| ADAPTIVE_RULES | gpt-oss:20b | 52.6 | [42.6, 62.5] | 36.5 | 0.8 | [0.3, 1.7] | 97 | 666 | 0 | 0.2 | 5.1 | 165 | 124 | 0.67 | 1.6 | 2.1 | 104.2 | 1.7026 |
| ADAPTIVE_v3 | gpt-oss:120b | 60.8 | [51.1, 70.5] | 59.0 | 1.2 | [0.7, 2.1] | 97 | 930 | 0 | 0.0 | 0.1 | 2 | 141 | 0.69 | 342.73 | -6.2 | 90.7 | – |
| ADAPTIVE_v3b | gpt-oss:120b | 62.9 | [53.3, 72.5] | 60.4 | 1.2 | [0.7, 2.2] | 97 | 831 | 0 | 1.2 | 1.4 | 94 | 100 | 0.67 | 339.39 | -4.1 | 93.9 | – |
| NONE | Kimi-K3.1-Pro | 100.0 | [100.0, 100.0] | 82.1 | 0.0 | [0.0, 6.4] | 16 | 56 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 4.2422 |
| NONE | claude-sonnet-5-5 | 100.0 | [100.0, 100.0] | – | – | – | 23 | 0 | 0 | 0.0 | – | 0 | 0 | – | – | 0.0 | 100.0 | 2.592 |
| NONE | deepseek-v4.1-flash | 90.7 | [84.9, 96.5] | 90.7 | 2.5 | [1.6, 3.8] | 97 | 796 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 6.6173 |
| NONE | gpt-4.1 | 80.4 | [70.0, 90.8] | 66.7 | 31.7 | [26.3, 37.7] | 56 | 249 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | – |
| NONE | gpt-oss:120b | 67.0 | [57.7, 76.4] | 63.9 | 11.5 | [9.6, 13.7] | 97 | 949 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 3.1763 |
| NONE | gpt-oss:20b | 50.5 | [40.6, 60.5] | 46.2 | 9.8 | [8.1, 11.9] | 97 | 949 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 2.1522 |
| STATIC | deepseek-v4.1-flash | 86.0 | [76.9, 95.0] | 68.8 | 4.8 | [3.1, 7.2] | 57 | 439 | 0 | 0.6 | 20.5 | 0 | 0 | 0.56 | 1.13 | – | – | 4.919 |
| STATIC | gpt-4.1 | 76.8 | [65.7, 87.8] | – | – | – | 56 | 0 | 0 | 0.8 | – | 0 | 0 | 0.61 | 0.94 | -3.6 | 95.5 | 2.0908 |
| STATIC | gpt-oss:120b | 63.9 | [54.4, 73.5] | 52.6 | 1.8 | [1.1, 2.9] | 97 | 949 | 0 | 0.4 | 16.6 | 0 | 0 | 0.59 | 1.44 | -3.1 | 95.4 | 4.4022 |
| STATIC | gpt-oss:20b | 49.5 | [39.5, 59.4] | 39.8 | 1.3 | [0.7, 2.2] | 97 | 949 | 0 | 0.2 | 9.7 | 0 | 0 | 0.67 | 1.6 | -1.0 | 98.0 | 2.4695 |

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

total 79.4226 · by provider {'anthropic': 5.184, 'commandcode': 35.1015, 'ollama': 29.784, 'openrouter': 9.3531} · Ollama by key {'A': 12.144, 'B': 10.3326, 'unknown': 7.3074} · by model {'Kimi-K3.1-Pro': 10.225, 'claude-sonnet-5-5': 5.184, 'deepseek-v4.1-flash': 24.8765, 'gpt-4.1': 9.3531, 'gpt-oss:120b': 21.4718, 'gpt-oss:20b': 8.3122}

## Decider (offline, B3)

```json
{
  "f1": 0.9166666666666666,
  "fpr_at_95_recall": 0.5942028985507246,
  "test_mad_ood_f1": 0.25,
  "benign_fpr_attenuate": 0.0,
  "attenuate_raw_cutoff": 2.7926829268292686,
  "model": "swarmguard-decider:v3",
  "calibration": {
    "sweep": [
      {
        "cutoff": 0.0,
        "recall": 1.0,
        "fpr": 1.0
      },
      {
        "cutoff": 0.5,
        "recall": 1.0,
        "fpr": 1.0
      },
      {
        "cutoff": 1.0,
        "recall": 1.0,
        "fpr": 1.0
      },
      {
        "cutoff": 1.5,
        "recall": 0.9495548961424333,
        "fpr": 0.02981651376146789
      },
      {
        "cutoff": 2.0,
        "recall": 0.9495548961424333,
        "fpr": 0.02981651376146789
      },
      {
        "cutoff": 2.5,
        "recall": 0.9495548961424333,
        "fpr": 0.02981651376146789
      },
      {
        "cutoff": 3.0,
        "recall": 0.9495548961424333,
        "fpr": 0.02981651376146789
      },
      {
        "cutoff": 3.5,
        "recall": 0.9495548961424333,
        "fpr": 0.02981651376146789
      },
      {
        "cutoff": 4.0,
        "recall": 0.9495548961424333,
        "fpr": 0.02981651376146789
      },
      {
        "cutoff": 4.5,
        "recall": 0.8753709198813057,
        "fpr": 0.006880733944954129
      },
      {
        "cutoff": 5.0,
        "recall": 0.8753709198813057,
        "fpr": 0.006880733944954129
      },
      {
        "cutoff": 5.5,
        "recall": 0.8753709198813057,
        "fpr": 0.006880733944954129
      },
      {
        "cutoff": 6.0,
        "recall": 0.8753709198813057,
        "fpr": 0.006880733944954129
      },
      {
        "cutoff": 6.5,
        "recall": 0.8753709198813057,
        "fpr": 0.006880733944954129
      },
      {
        "cutoff": 7.0,
        "recall": 0.8753709198813057,
        "fpr": 0.006880733944954129
      },
      {
        "cutoff": 7.5,
        "recall": 0.8753709198813057,
        "fpr": 0.006880733944954129
      },
      {
        "cutoff": 8.0,
        "recall": 0.8753709198813057,
        "fpr": 0.006880733944954129
      },
      {
        "cutoff": 8.5,
        "recall": 0.8753709198813057,
        "fpr": 0.006880733944954129
      },
      {
        "cutoff": 9.0,
        "recall": 0.8753709198813057,
        "fpr": 0.006880733944954129
      },
      {
        "cutoff": 9.5,
        "recall": 0.0,
        "fpr": 0.0
      },
      {
        "cutoff": 10.0,
        "recall": 0.0,
        "fpr": 0.0
      }
    ],
    "cutoff_fpr<=2%": 4.5,
    "cutoff_fpr<=1%": 4.5,
    "benign_p90": 1.0,
    "risk_map": [
      [
        0.0,
        0.0
      ],
      [
        1.0,
        3.9
      ],
      [
        4.5,
        8.0
      ],
      [
        10.0,
        10.0
      ]
    ]
  },
  "splits": {
    "test_ood.jsonl": {
      "n": 150,
      "pos": 12,
      "json_fail_rate": 0.0,
      "fpr@risk>=8": 0.007246376811594203,
      "f1@risk>=8": 0.9166666666666666,
      "pr_auc": 0.8509160756501181,
      "fpr@95recall": 0.5942028985507246,
      "onset_pm1_acc": 1.0,
      "latency_s_mean": 0.4356330728530884,
      "sweep": [
        {
          "cutoff": 0.0,
          "recall": 1.0,
          "fpr": 1.0
        },
        {
          "cutoff": 0.5,
          "recall": 1.0,
          "fpr": 1.0
        },
        {
          "cutoff": 1.0,
          "recall": 1.0,
          "fpr": 1.0
        },
        {
          "cutoff": 1.5,
          "recall": 1.0,
          "fpr": 0.1111111111111111
        },
        {
          "cutoff": 2.0,
          "recall": 1.0,
          "fpr": 0.1111111111111111
        },
        {
          "cutoff": 2.5,
          "recall": 1.0,
          "fpr": 0.1111111111111111
        },
        {
          "cutoff": 3.0,
          "recall": 1.0,
          "fpr": 0.1111111111111111
        },
        {
          "cutoff": 3.5,
          "recall": 1.0,
          "fpr": 0.1111111111111111
        },
        {
          "cutoff": 4.0,
          "recall": 1.0,
          "fpr": 0.1111111111111111
        },
        {
          "cutoff": 4.5,
          "recall": 0.9166666666666666,
          "fpr": 0.0
        },
        {
          "cutoff": 5.0,
          "recall": 0.9166666666666666,
          "fpr": 0.0
        },
        {
          "cutoff": 5.5,
          "recall": 0.9166666666666666,
          "fpr": 0.0
        },
        {
          "cutoff": 6.0,
          "recall": 0.9166666666666666,
          "fpr": 0.0
        },
        {
          "cutoff": 6.5,
          "recall": 0.9166666666666666,
          "fpr": 0.0
        },
        {
          "cutoff": 7.0,
          "recall": 0.9166666666666666,
          "fpr": 0.0
        },
        {
          "cutoff": 7.5,
          "recall": 0.9166666666666666,
          "fpr": 0.0
        },
        {
          "cutoff": 8.0,
          "recall": 0.9166666666666666,
          "fpr": 0.0
        },
        {
          "cutoff": 8.5,
          "recall": 0.9166666666666666,
          "fpr": 0.0
        },
        {
          "cutoff": 9.0,
          "recall": 0.9166666666666666,
          "fpr": 0.0
        },
        {
          "cutoff": 9.5,
          "recall": 0.0,
          "fpr": 0.0
        },
        {
          "cutoff": 10.0,
          "recall": 0.0,
          "fpr": 0.0
        }
      ],
      "by_attack_type": {
        "important_instructions": {
          "n": 122,
          "pos": 12,
          "json_fail_rate": 0.0,
          "fpr@risk>=8": 0.00909090909090909,
          "f1@risk>=8": 0.9166666666666666,
          "pr_auc": 0.8509160756501181,
          "fpr@95recall": 0.7454545454545455,
          "onset_pm1_acc": 1.0,
          "latency_s_mean": 0.43556621426441633
        },
        "none": {
          "n": 28,
          "pos": 0,
          "json_fail_rate": 0.0,
          "fpr@risk>=8": 0.0,
          "f1@risk>=8": null,
          "pr_auc": null,
          "onset_pm1_acc": 0.0,
          "latency_s_mean": 0.4359243852751596
        }
      }
    },
    "test_drift.jsonl": {
      "n": 150,
      "pos": 51,
      "json_fail_rate": 0.0,
      "fpr@risk>=8": 0.04040404040404041,
      "f1@risk>=8": 0.9,
      "pr_auc": 0.8503241296518608,
      "fpr@95recall": 1.0,
      "onset_pm1_acc": 0.9464285714285714,
      "latency_s_mean": 0.39522566000620524,
      "sweep": [
        {
          "cutoff": 0.0,
          "recall": 1.0,
          "fpr": 1.0
        },
        {
          "cutoff": 0.5,
          "recall": 1.0,
          "fpr": 1.0
        },
        {
          "cutoff": 1.0,
          "recall": 1.0,
          "fpr": 1.0
        },
        {
          "cutoff": 1.5,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 2.0,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 2.5,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 3.0,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 3.5,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 4.0,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 4.5,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 5.0,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 5.5,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 6.0,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 6.5,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 7.0,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 7.5,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 8.0,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 8.5,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 9.0,
          "recall": 0.8823529411764706,
          "fpr": 0.10526315789473684
        },
        {
          "cutoff": 9.5,
          "recall": 0.0,
          "fpr": 0.0
        },
        {
          "cutoff": 10.0,
          "recall": 0.0,
          "fpr": 0.0
        }
      ],
      "by_attack_type": {
        "data_stealing": {
          "n": 23,
          "pos": 10,
          "json_fail_rate": 0.0,
          "fpr@risk>=8": 0.07692307692307693,
          "f1@risk>=8": 0.9523809523809523,
          "pr_auc": 0.9090909090909091,
          "fpr@95recall": 0.07692307692307693,
          "onset_pm1_acc": 1.0,
          "latency_s_mean": 0.41009710146033246
        },
        "multi_step_spreading": {
          "n": 20,
          "pos": 5,
          "json_fail_rate": 0.0,
          "fpr@risk>=8": 0.0,
          "f1@risk>=8": 0.8888888888888888,
          "pr_auc": 0.8500000000000001,
          "fpr@95recall": 1.0,
          "onset_pm1_acc": 0.9333333333333333,
          "latency_s_mean": 0.384600830078125
        },
        "none": {
          "n": 22,
          "pos": 0,
          "json_fail_rate": 0.0,
          "fpr@risk>=8": 0.0,
          "f1@risk>=8": null,
          "pr_auc": null,
          "onset_pm1_acc": 0.0,
          "latency_s_mean": 0.36515216393904254
        },
        "parameter_manipulation": {
          "n": 25,
          "pos": 9,
          "json_fail_rate": 0.0,
          "fpr@risk>=8": 0.0,
          "f1@risk>=8": 0.9411764705882353,
          "pr_auc": 0.9288888888888889,
          "fpr@95recall": 1.0,
          "onset_pm1_acc": 0.9565217391304348,
          "latency_s_mean": 0.41890276908874513
        },
        "reasoning_corruption": {
          "n": 25,
          "pos": 8,
          "json_fail_rate": 0.0,
          "fpr@risk>=8": 0.11764705882352941,
          "f1@risk>=8": 0.75,
          "pr_auc": 0.6425,
          "fpr@95recall": 1.0,
          "onset_pm1_acc": 0.9130434782608695,
          "latency_s_mean": 0.38597920417785647
        }
      }
    },
    "test_mad_ood.jsonl": {
      "n": 150,
      "pos": 5,
      "json_fail_rate": 0.0,
      "fpr@risk>=8": 0.013793103448275862,
      "f1@risk>=8": 0.25,
      "pr_auc": 0.09777777777777777,
      "fpr@95recall": 1.0,
      "onset_pm1_acc": 1.0,
      "latency_s_mean": 0.4062782669067383,
      "sweep": [
        {
          "cutoff": 0.0,
          "recall": 1.0,
          "fpr": 1.0
        },
        {
          "cutoff": 0.5,
          "recall": 1.0,
          "fpr": 1.0
        },
        {
          "cutoff": 1.0,
          "recall": 1.0,
          "fpr": 1.0
        },
        {
          "cutoff": 1.5,
          "recall": 0.4,
          "fpr": 0.0
        },
        {
          "cutoff": 2.0,
          "recall": 0.4,
          "fpr": 0.0
        },
        {
          "cutoff": 2.5,
          "recall": 0.4,
          "fpr": 0.0
        },
        {
          "cutoff": 3.0,
          "recall": 0.4,
          "fpr": 0.0
        },
        {
          "cutoff": 3.5,
          "recall": 0.4,
          "fpr": 0.0
        },
        {
          "cutoff": 4.0,
          "recall": 0.4,
          "fpr": 0.0
        },
        {
          "cutoff": 4.5,
          "recall": 0.2,
          "fpr": 0.0
        },
        {
          "cutoff": 5.0,
          "recall": 0.2,
          "fpr": 0.0
        },
        {
          "cutoff": 5.5,
          "recall": 0.2,
          "fpr": 0.0
        },
        {
          "cutoff": 6.0,
          "recall": 0.2,
          "fpr": 0.0
        },
        {
          "cutoff": 6.5,
          "recall": 0.2,
          "fpr": 0.0
        },
        {
          "cutoff": 7.0,
          "recall": 0.2,
          "fpr": 0.0
        },
        {
          "cutoff": 7.5,
          "recall": 0.2,
          "fpr": 0.0
        },
        {
          "cutoff": 8.0,
          "recall": 0.2,
          "fpr": 0.0
        },
        {
          "cutoff": 8.5,
          "recall": 0.2,
          "fpr": 0.0
        },
        {
          "cutoff": 9.0,
          "recall": 0.2,
          "fpr": 0.0
        },
        {
          "cutoff": 9.5,
          "recall": 0.0,
          "fpr": 0.0
        },
        {
          "cutoff": 10.0,
          "recall": 0.0,
          "fpr": 0.0
        }
      ],
      "by_attack_type": {
        "important_instructions": {
          "n": 140,
          "pos": 5,
          "json_fail_rate": 0.0,
          "fpr@risk>=8": 0.014814814814814815,
          "f1@risk>=8": 0.25,
          "pr_auc": 0.0992063492063492,
          "fpr@95recall": 1.0,
          "onset_pm1_acc": 1.0,
          "latency_s_mean": 0.4015631948198591
        }
      }
    }
  }
}
```
