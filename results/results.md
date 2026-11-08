# Results (mad) — generated 2026-11-08 15:16:06 CET

Ours = measured from run logs (pooled over suites; ASR Wilson 95% CI, utility Wald 95% CI). ASR = % injected runs where the injection goal was achieved. Δ = ours − NONE (negative = utility cost).

| Config | Model | Utility | 95% CI | Util. under attack | ASR | 95% CI | n benign | n injected | errors | benign denied % | attack denied % | attenuate | killed runs | p50 ms | p95 ms | util Δ vs NONE | retention % | $ |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ADAPTIVE | Kimi-K3.1-Pro | 93.8 | [81.9, 100.0] | 67.9 | 0.0 | [0.0, 12.1] | 16 | 28 | 0 | 2.4 | 0.0 | 3 | 0 | 0.75 | 1132.13 | -6.2 | 93.8 | 2.3028 |
| ADAPTIVE | deepseek-v4.1-flash | 93.5 | [88.0, 99.0] | 79.0 | 0.0 | [0.0, 0.8] | 77 | 453 | 0 | 3.0 | 4.3 | 52 | 64 | 0.59 | 1225.27 | – | – | 2.7435 |
| ADAPTIVE | gpt-4.1 | 80.4 | [70.0, 90.8] | 79.0 | 0.0 | [0.0, 3.7] | 56 | 100 | 0 | 0.8 | 6.3 | 26 | 2 | 0.56 | 2167.04 | 0.0 | 100.0 | 5.7466 |
| ADAPTIVE | gpt-oss:120b | 64.9 | [55.5, 74.4] | 58.0 | 1.1 | [0.6, 2.0] | 97 | 920 | 0 | 1.1 | 3.5 | 258 | 96 | 0.67 | 1305.3 | -2.1 | 96.9 | 8.8485 |
| ADAPTIVE | gpt-oss:20b | 50.5 | [40.6, 60.5] | 41.4 | 1.2 | [0.6, 2.2] | 97 | 773 | 0 | 1.0 | 2.8 | 96 | 120 | 0.69 | 435.69 | 0.0 | 100.0 | 1.6551 |
| ADAPTIVE_RULES | deepseek-v4.1-flash | 92.8 | [87.6, 97.9] | 58.9 | 3.3 | [1.9, 5.8] | 97 | 333 | 0 | 0.8 | 8.4 | 162 | 67 | 0.55 | 1.54 | 2.1 | 102.3 | 2.7083 |
| ADAPTIVE_RULES | gpt-oss:120b | 63.9 | [54.4, 73.5] | 50.8 | 0.6 | [0.3, 1.4] | 97 | 949 | 0 | 0.1 | 5.8 | 406 | 91 | 0.6 | 1.91 | -3.1 | 95.4 | 3.8477 |
| ADAPTIVE_v3 | gpt-oss:120b | 60.8 | [51.1, 70.5] | 42.3 | 2.4 | [1.3, 4.2] | 97 | 466 | 0 | 0.0 | 0.2 | 2 | 117 | 0.71 | 343.1 | -6.2 | 90.7 | – |
| ADAPTIVE_v3b | gpt-oss:120b | 62.9 | [53.3, 72.5] | 41.7 | 2.9 | [1.6, 5.2] | 97 | 348 | 0 | 1.2 | 2.5 | 87 | 83 | 0.67 | 361.1 | -4.1 | 93.9 | – |
| NONE | Kimi-K3.1-Pro | 100.0 | [100.0, 100.0] | 82.1 | 0.0 | [0.0, 6.4] | 16 | 56 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 4.2422 |
| NONE | deepseek-v4.1-flash | 90.7 | [84.9, 96.5] | 90.7 | 2.5 | [1.6, 3.8] | 97 | 796 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 6.6173 |
| NONE | gpt-4.1 | 80.4 | [70.0, 90.8] | 66.7 | 31.7 | [26.3, 37.7] | 56 | 249 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | – |
| NONE | gpt-oss:120b | 67.0 | [57.7, 76.4] | 63.9 | 11.5 | [9.6, 13.7] | 97 | 949 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 3.1763 |
| NONE | gpt-oss:20b | 50.5 | [40.6, 60.5] | 46.0 | 10.7 | [8.8, 13.0] | 97 | 830 | 0 | 0.0 | 0.0 | 0 | 0 | – | – | 0.0 | 100.0 | 1.8712 |
| STATIC | deepseek-v4.1-flash | 86.0 | [76.9, 95.0] | 69.7 | 4.8 | [3.2, 7.3] | 57 | 433 | 0 | 0.6 | 20.5 | 0 | 0 | 0.56 | 1.14 | – | – | 3.1932 |
| STATIC | gpt-4.1 | 76.8 | [65.7, 87.8] | – | – | – | 56 | 0 | 0 | 0.8 | – | 0 | 0 | 0.61 | 0.94 | -3.6 | 95.5 | 2.0908 |
| STATIC | gpt-oss:120b | 63.9 | [54.4, 73.5] | 52.6 | 1.8 | [1.1, 2.9] | 97 | 949 | 0 | 0.4 | 16.6 | 0 | 0 | 0.59 | 1.44 | -3.1 | 95.4 | 4.4022 |
| STATIC | gpt-oss:20b | 54.7 | [44.1, 65.2] | 42.8 | 1.1 | [0.5, 2.1] | 86 | 759 | 0 | 0.2 | 11.5 | 0 | 0 | 0.68 | 1.73 | 4.2 | 108.3 | 1.8297 |

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

total 55.2777 · by provider {'anthropic': 0.0, 'commandcode': 21.8073, 'ollama': 25.633, 'openrouter': 7.8374} · Ollama by key {'A': 9.7835, 'B': 8.5421, 'unknown': 7.3074} · by model {'Kimi-K3.1-Pro': 6.545, 'deepseek-v4.1-flash': 15.2623, 'gpt-4.1': 7.8374, 'gpt-oss:120b': 20.2747, 'gpt-oss:20b': 5.3583}

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
