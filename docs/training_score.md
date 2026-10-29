# Training score

When you reveal the answer in training mode, the dashboard shows a **score**: how many of the key points of this alert your answers mention. It helps you see which facts you left out. The **Investigation** tab also shows your average score over the alerts you have revealed.

## How it works

`soc_lab/scoring.py` builds a checklist from the alert's own data, so it works on any dataset, including generated ones and real-format logs:

| Question | Point checked |
| --- | --- |
| Rule | The rule ID (for example R004) |
| Scope | The accounts and source addresses (up to three of each) |
| Counts | The number of failed logons, and the number of different accounts when there are several |
| Success | That a logon succeeded and for which account, or that none did |
| Source | Internal or external |
| Time | Within or outside business hours |
| Account events | Each lockout, unlock and password change that appears, or that there were none |
| Account type | Service account or a person's account |
| Benign | At least one concrete innocent explanation |
| Missing | Who to confirm with (user, service desk, ticket, team, manager) |
| Verdict | The expected verdict: *attack*, *benign* or *uncertain* (from the ground truth, or else from the tool's conclusion); plus the expected status when the ground truth is known |
| Severity | A severity level |
| MITRE | The alert's technique ID (for example T1110.003) |
| Action | Escalate, close or verify, as the scenario expects; for attacks, also a containment proposal |
| Summary | At least three sentences, naming the main entity |

Answers are compared in lower case and without accents, with word lists in English and Portuguese ("não" and "nao" count the same).

## Limits

This is **keyword matching, not a judgement of your reasoning**:

- A correct answer worded differently can miss a point (for example "fifteen" instead of "15").
- A point can pass on a sentence that says the opposite: "this is not an attack" still contains "attack".
- A high score means you covered the facts, not that your analysis is right. Always read the reference answers and the ground truth as well.

Saved answers are not changed by the score; it is recalculated each time from what you wrote.
