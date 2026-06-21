---
title: "Threat Index"
date: 2026-12-08 09:00:00 -0500
categories: [HackTheBox, Challenges, Coding]
tags: [hackthebox, challenge, coding, string-processing, flask, automation]
description: "A Very Easy Coding challenge: scan a data stream for 18 weighted threat keywords and output the total threat score. The whole solve is one weighted str.count expression, submitted programmatically to the challenge's /run endpoint."
---

## Overview

`Threat Index` is a Very Easy HackTheBox **Coding** challenge. Like all challenges in that category, it is a small Flask web app serving a Monaco code editor: you write a short program, hit "Run", and the server executes your code against a set of hidden test cases. Pass every case and the response carries the flag. The task here is pure string processing — tally weighted keyword hits in a data stream — so the entire solution is a single expression, submitted to the app's `/run` endpoint without ever opening a browser.

## The technique

The challenge feeds your program one line on standard input: a "data stream" of lowercase letters and digits exfiltrated from a TOR node. Eighteen threat keywords each carry a weight, and the **threat score** is:

```
threat score = Σ (occurrences of keyword × keyword weight)
```

| keyword | weight | | keyword | weight |
|---|---|---|---|---|
| scan | 1 | | execute | 11 |
| response | 2 | | deploy | 12 |
| control | 3 | | malware | 13 |
| callback | 4 | | exploit | 14 |
| implant | 5 | | payload | 15 |
| zombie | 6 | | backdoor | 16 |
| trigger | 7 | | zeroday | 17 |
| infected | 8 | | botnet | 18 |
| compromise | 9 | | | |
| inject | 10 | | | |

The keywords are mutually **non-overlapping** — no keyword is a substring of another, and none can overlap a copy of itself — so the number of times each appears is exactly what Python's `str.count` returns (it counts non-overlapping, left-to-right occurrences). That removes any need for a suffix automaton or longest-match bookkeeping; the solver is one line.

The published example `payloadrandompayloadhtbzerodayrandombytesmalware` scores `2×15 + 17 + 13 = 60` (`payload` twice, `zeroday`, `malware`; the rest is noise).

## Solution

A Coding challenge with no download is solved entirely against its HTTP endpoint. The browser's "Run" button issues `POST /run` with `{"code": <source>, "language": "python"}`; the JSON reply sets `challengeCompleted: true` and carries the flag once your stdout matches every hidden stream.

The program submitted to the server reads one stream line and prints the weighted score:

```python
WEIGHTS = {"scan":1,"response":2,"control":3,"callback":4,"implant":5,"zombie":6,
"trigger":7,"infected":8,"compromise":9,"inject":10,"execute":11,"deploy":12,
"malware":13,"exploit":14,"payload":15,"backdoor":16,"zeroday":17,"botnet":18}
s = input().strip()
print(sum(s.count(k) * w for k, w in WEIGHTS.items()))
```

Wrap it in a one-shot driver that submits the source and reads back the flag:

```python
import json, urllib.request

SOLUTION = r'''
WEIGHTS = {"scan":1,"response":2,"control":3,"callback":4,"implant":5,"zombie":6,
"trigger":7,"infected":8,"compromise":9,"inject":10,"execute":11,"deploy":12,
"malware":13,"exploit":14,"payload":15,"backdoor":16,"zeroday":17,"botnet":18}
s = input().strip()
print(sum(s.count(k) * w for k, w in WEIGHTS.items()))
'''

req = urllib.request.Request("http://<rhost>:<rport>/run",
    data=json.dumps({"code": SOLUTION, "language": "python"}).encode(),
    headers={"Content-Type": "application/json"})
data = json.loads(urllib.request.urlopen(req, timeout=60).read())
if data.get("challengeCompleted"):
    print("FLAG:", data["flag"])   # HTB{...}
```

Running it submits the solver, the server runs it across the hidden streams, and the reply comes back `challengeCompleted: true` with the flag.

## Why it worked

The grader's contract for every Coding challenge is the same: your submitted code reads each test case from **stdin** and writes the answer to **stdout**, and the server diffs your output against the expected value. Because the 18 keywords never overlap, the "occurrences" in the scoring formula collapse to independent per-keyword counts, and the sum of `count × weight` is the answer the grader expects for every stream — so one correct expression clears all hidden cases at once.

## Fix / defense

There is no security bug here — it is an algorithm exercise. The transferable lesson is recognition: a challenge with no downloadable file that serves a Werkzeug/Flask page with a Monaco editor is an `/run`-driven Coding task. Grep the page for the `fetch("/run", ...)` body shape, write the algorithm, and submit it with `urllib` — the live target is only ever touched through that one endpoint.
