---
layout: post
title: "HackTheBox Challenge: Triple Knock"
date: 2027-10-07 09:00:00 -0500
categories: [HackTheBox, Challenges, Coding]
tags: [hackthebox, challenge, coding, sliding-window, log-analysis, flask, algorithm]
---

Triple Knock is an Easy challenge in HackTheBox's **Coding** category. There is no
binary to reverse and no service to exploit — you are handed a programming problem and
a code editor, and the flag drops once your program passes every hidden test case. The
puzzle here is a classic "detect N events inside a time window" log-analysis problem
dressed up as a credential-stuffing investigation.

## Overview

- **Category:** Coding · **Difficulty:** Easy
- **Harness:** a Flask app serving a Monaco editor; you `POST` source to `/run` and the
  server runs it against hidden tests, returning the flag on a full pass.
- **Problem:** flag any user account that made **3 failed logins within a 10-minute window**.

## The technique

HTB **Coding** challenges look like a `nc host port` puzzle, but the port is *silent* —
it sends no banner and waits. That is because it is not a raw socket service at all: it
is a **Flask web app** with a Monaco code editor. `curl` the root and the page reveals
itself; submissions go to `POST /run`.

```bash
curl -s http://TARGET/                       # Flask + Monaco editor page
curl -s -X POST http://TARGET/run \
  -H 'Content-Type: application/json' \
  -d '{"code":"print(1)","language":"python"}'
```

A useful shortcut: submitting placeholder code returns a `result` object that **leaks
one full sample test case** — both the `input` it fed and the `expected` output — so you
can reverse the exact input shape before finishing the prose:

```json
{"result":{"cause":"Wrong answer","expected":"user_1","input":"20 2\nuser_1 14/09 10:07 [failure]\n...","output":"1"}}
```

The problem itself: the first line is `S N` (S = number of log entries, N = number of
users, unused). Each of the next S lines is `user_id DD/MM HH:MM [success|failure]`. The
year is constant and every month is treated as 30 days. A user is "targeted" — a triple
knock — when they have **3 failed logins within a 10-minute window**. Print the targeted
user IDs, space-separated, in lexicographical order.

This is the canonical **sliding-window** pattern:

1. Encode each timestamp as a single monotone integer. Since all months are 30 days and
   the year is fixed, total minutes since an arbitrary epoch is
   `(((mm-1)*30 + dd-1) * 1440) + hh*60 + mi`. Now timestamps subtract like plain numbers.
2. Group failures per user and sort each user's times.
3. Slide a width-3 window over the sorted times. If any 3 consecutive failures span
   `≤ 10` minutes, the user is targeted. Consecutive triples are sufficient — if 4+
   failures fall inside the window, some consecutive triple inside it will too.

## Solution

The program reads stdin, applies the sliding window, and prints the sorted list.

`solve_code.py` (the source submitted to the harness):

```python
import sys

def main():
    data = sys.stdin.read().split('\n')
    s = int(data[0].split()[0])
    fails = {}
    for i in range(1, s + 1):
        uid, date, clock, status = data[i].split()
        if status == '[failure]':
            dd, mm = date.split('/')
            hh, mi = clock.split(':')
            t = (((int(mm) - 1) * 30) + (int(dd) - 1)) * 1440 + int(hh) * 60 + int(mi)
            fails.setdefault(uid, []).append(t)
    targeted = []
    for uid, times in fails.items():
        times.sort()
        for j in range(len(times) - 2):
            if times[j + 2] - times[j] <= 10:
                targeted.append(uid)
                break
    print(' '.join(sorted(targeted)))

main()
```

Posting it to `/run` returns `challengeCompleted: true` with the flag on the first
submission. A small driver makes the solve reproducible:

```python
import json, sys, urllib.request

SOLUTION = open("solve_code.py").read()

def main():
    target = sys.argv[1]
    body = json.dumps({"code": SOLUTION, "language": "python"}).encode()
    req = urllib.request.Request(f"http://{target}/run", data=body,
                                 headers={"Content-Type": "application/json"})
    resp = json.load(urllib.request.urlopen(req, timeout=20))
    print("FLAG:", resp["flag"]) if resp.get("challengeCompleted") else print(resp["result"])

main()
```

```
$ python3 solve.py TARGET:PORT
FLAG: HTB{...}
```

## Why it worked

The monotone-minute encoding removes all date arithmetic, so "within a 10-minute window"
collapses into integer subtraction. Sorting plus a consecutive-triple window is
`O(n log n)` and exact — it never misses a window and the `break` flags each user only
once.

## Fix / defense

The challenge mirrors a real **detection rule**: "N failed authentications from one
principal inside a short window" is exactly how a SOC flags credential-stuffing and
password-spray bursts (Windows 4625 storms, an IdP's failed-login counter). The practical
defenses are the familiar ones — account lockout or exponential backoff after repeated
failures, per-source rate limiting, and alerting on the burst rather than the individual
failed login.
