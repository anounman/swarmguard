| config | suite | inj | onset | relay % | exec. spread % | mean agents | contained % | ASR % | top relay pairs |
|---|---|---|---|---|---|---|---|---|---|
| NONE | all | 949 | 677 | 6.1 | 6.1 | 0.17 | 81.7 | 15.4 | filesystem_agent->transactions_agent (22), web_agent->slack_agent (13), filesystem_agent->account_agent (3) |
| NONE | banking | 144 | 120 | 18.3 | 18.3 | 0.56 | 44.2 | 54.2 | filesystem_agent->transactions_agent (22), filesystem_agent->account_agent (3) |
| NONE | slack | 105 | 95 | 11.6 | 11.6 | 0.37 | 61.1 | 26.3 | web_agent->slack_agent (13), slack_agent->web_agent (1) |
| NONE | travel | 140 | 20 | 5.0 | 5.0 | 0.05 | 95.0 | 0.0 | hotels_agent->personal_assistant_agent (1) |
| NONE | workspace | 560 | 442 | 1.6 | 1.6 | 0.03 | 95.7 | 3.2 | cloud_drive_agent->email_agent (3), calendar_agent->email_agent (2), cloud_drive_agent->calendar_agent (1) |
| STATIC | all | 949 | 669 | 6.3 | 1.3 | 0.17 | 94.6 | 2.5 | filesystem_agent->transactions_agent (50), web_agent->slack_agent (16), cloud_drive_agent->email_agent (6) |
| STATIC | banking | 144 | 116 | 19.0 | 0.0 | 0.57 | 100.0 | 0.0 | filesystem_agent->transactions_agent (50), filesystem_agent->account_agent (3) |
| STATIC | slack | 105 | 94 | 13.8 | 7.4 | 0.4 | 75.5 | 8.5 | web_agent->slack_agent (16), slack_agent->web_agent (3) |
| STATIC | travel | 140 | 19 | 5.3 | 5.3 | 0.05 | 94.7 | 0.0 | hotels_agent->personal_assistant_agent (1) |
| STATIC | workspace | 560 | 440 | 1.4 | 0.2 | 0.03 | 97.3 | 2.0 | cloud_drive_agent->email_agent (6), calendar_agent->email_agent (6) |
| ADAPTIVE_RULES | all | 949 | 595 | 4.2 | 1.5 | 0.06 | 96.5 | 1.0 | filesystem_agent->transactions_agent (24), web_agent->slack_agent (12), filesystem_agent->account_agent (3) |
| ADAPTIVE_RULES | banking | 144 | 69 | 17.4 | 0.0 | 0.17 | 100.0 | 0.0 | filesystem_agent->transactions_agent (24), filesystem_agent->account_agent (3) |
| ADAPTIVE_RULES | slack | 105 | 74 | 13.5 | 9.5 | 0.27 | 78.4 | 6.8 | web_agent->slack_agent (12) |
| ADAPTIVE_RULES | travel | 140 | 20 | 5.0 | 5.0 | 0.05 | 95.0 | 0.0 | hotels_agent->personal_assistant_agent (1) |
| ADAPTIVE_RULES | workspace | 560 | 432 | 0.5 | 0.2 | 0.01 | 99.1 | 0.2 | cloud_drive_agent->email_agent (1) |
| ADAPTIVE | all | 949 | 605 | 5.0 | 2.1 | 0.07 | 95.2 | 1.7 | filesystem_agent->transactions_agent (44), web_agent->slack_agent (12), cloud_drive_agent->email_agent (12) |
| ADAPTIVE | banking | 144 | 76 | 21.1 | 5.3 | 0.21 | 94.7 | 3.9 | filesystem_agent->transactions_agent (44), filesystem_agent->account_agent (4) |
| ADAPTIVE | slack | 105 | 74 | 14.9 | 9.5 | 0.31 | 73.0 | 6.8 | web_agent->slack_agent (12), slack_agent->web_agent (2) |
| ADAPTIVE | travel | 140 | 20 | 5.0 | 5.0 | 0.05 | 95.0 | 0.0 | hotels_agent->personal_assistant_agent (1) |
| ADAPTIVE | workspace | 560 | 435 | 0.5 | 0.2 | 0.01 | 99.1 | 0.5 | cloud_drive_agent->email_agent (12) |
| ADAPTIVE_v3 | all | 949 | 579 | 4.7 | 1.9 | 0.06 | 96.5 | 1.9 | filesystem_agent->transactions_agent (15), web_agent->slack_agent (9), email_agent->calendar_agent (2) |
| ADAPTIVE_v3 | banking | 144 | 74 | 21.6 | 6.8 | 0.22 | 93.2 | 6.8 | filesystem_agent->transactions_agent (15), filesystem_agent->account_agent (1) |
| ADAPTIVE_v3 | slack | 105 | 57 | 12.3 | 8.8 | 0.18 | 78.9 | 10.5 | web_agent->slack_agent (9) |
| ADAPTIVE_v3 | travel | 140 | 20 | 5.0 | 5.0 | 0.05 | 95.0 | 0.0 | hotels_agent->personal_assistant_agent (1) |
| ADAPTIVE_v3 | workspace | 560 | 428 | 0.7 | 0.0 | 0.01 | 99.5 | 0.0 | email_agent->calendar_agent (2), cloud_drive_agent->email_agent (2) |
| ADAPTIVE_v3b | all | 949 | 604 | 5.3 | 2.5 | 0.07 | 95.9 | 1.5 | filesystem_agent->transactions_agent (33), web_agent->slack_agent (23), cloud_drive_agent->email_agent (3) |
| ADAPTIVE_v3b | banking | 144 | 71 | 21.1 | 5.6 | 0.21 | 94.4 | 5.6 | filesystem_agent->transactions_agent (33), filesystem_agent->account_agent (1) |
| ADAPTIVE_v3b | slack | 105 | 69 | 15.9 | 13.0 | 0.26 | 75.4 | 7.2 | web_agent->slack_agent (23), slack_agent->web_agent (1) |
| ADAPTIVE_v3b | travel | 140 | 20 | 5.0 | 5.0 | 0.05 | 95.0 | 0.0 | hotels_agent->personal_assistant_agent (1) |
| ADAPTIVE_v3b | workspace | 560 | 444 | 1.1 | 0.2 | 0.02 | 99.3 | 0.0 | cloud_drive_agent->email_agent (3), calendar_agent->email_agent (2), cloud_drive_agent->calendar_agent (1) |
