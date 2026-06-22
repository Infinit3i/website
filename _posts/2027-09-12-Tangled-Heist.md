---
title: "Tangled Heist"
date: 2027-09-12 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, ldap, kerberos, active-directory, asrep-roasting, pcap, tshark, hashcat, cwe-319, cwe-287]
description: "A single packet capture records an attacker walking an Active Directory over cleartext LDAP — bind, recon, attribute tampering, and a backdoor account — while one leaked Kerberos AS-REP gets roasted offline. Eleven questions, all answered straight from the wire."
---

## Overview

Tangled Heist is an Easy forensics challenge built around one artifact: `capture.pcap`. It records an
attacker at `10.10.10.43` authenticating to a Domain Controller (`10.10.10.100`, *rebcorp.htb* / SRV195)
over **LDAP** and enumerating, then tampering with, Active Directory. Because plain LDAP is
[cleartext](https://cwe.mitre.org/data/definitions/319.html), every action — the bind identity, the search
filters, the attribute writes, the persistence account — is readable in the packets. One Kerberos AS-REP
also leaked, which we crack offline. Answer all eleven docker questions to get the flag.

## The technique

The capture is almost entirely TCP carrying **LDAP** (97 frames) plus two **Kerberos** frames. LDAP
operations have an obvious structure that `tshark`/Wireshark dissects cleanly:

| protocolOp | meaning | what it leaks |
|---|---|---|
| 0 / 1 | bindRequest / bindResponse | the NTLM auth (username, domain, host) |
| 3 | searchRequest | the attacker's enumeration filter + baseObject |
| 4 | searchResEntry | every returned attribute (`badPwdCount`, `userAccountControl`, group members) |
| 6 | modifyRequest | attribute tampering |
| 8 | addRequest | new objects (a backdoor user) |

So the whole intrusion is reconstructed by filtering on those op codes. The only "exploit" step is a
textbook AS-REP roast against an account configured with *"Do not require Kerberos pre-authentication"*.

## Solution

### Who logged in (cleartext NTLM over LDAP)

```bash
tshark -r capture.pcap -Y "ntlmssp.auth.username" -T fields \
  -e ntlmssp.auth.username -e ntlmssp.auth.domain -e ntlmssp.auth.hostname
# Copper   rebcorp.htb   MSEDGEWIN10
```

Compromised user **Copper**, domain **rebcorp.htb**.

### What was enumerated

```bash
tshark -r capture.pcap -Y "ldap.protocolOp == 3" -T fields -e ldap.baseObject -e ldap.filter
# ... (objectClass=group)   (objectClass=domain)   (objectClass=trustedDomain) ...
```

The `searchResEntry` responses (op 4) hold the answers to several questions:

- **Ranger's failed logins** — the `badPwdCount` attribute on `CN=Ranger` = `14`.
- **Disabled user** — `userAccountControl == 514` (`ACCOUNTDISABLE | NORMAL_ACCOUNT`). Three accounts
  match; ignore the defaults `Guest` and `krbtgt`, leaving **Radiation**.
- **Non-standard groups** — list every group CN and drop the well-known AD built-ins. Five custom groups
  remain: `Agents, Enclave, Raiders, Scavengers, Watchers` → `5`.
- **DC distinguished name** — `CN=SRV195,OU=Domain Controllers,DC=rebcorp,DC=htb`.

### The tampering and the backdoor

```bash
tshark -r capture.pcap -Y "ldap.protocolOp == 6" -V   # modifyRequest
tshark -r capture.pcap -Y "ldap.protocolOp == 8" -V   # addRequest
```

A `modifyRequest` on `CN=Wraith` writes the free-text `wWWHomePage` attribute to
`http://rebcorp.htb/qPvAdQ.php` (a classic payload-stash field). An `addRequest` then creates `CN=B4ck`,
and a follow-up `modifyRequest` adds B4ck as a `member` of the `Enclave` group → persistence as
`B4ck,Enclave`.

### Roasting the leaked AS-REP

Hurricane has pre-authentication disabled, so the DC returned an AS-REP whose enc-part is encrypted with
Hurricane's password-derived key — crackable offline. **Two traps cost real time here:**

1. `tshark -V` **truncates** long byte fields with `[…]`; copying the cipher from verbose output yields a
   short, uncrackable hash. Always extract with `-T fields`.
2. An AS-REP has *two* enc-parts: the ticket enc-part (etype 18 AES, encrypted with the **krbtgt** key —
   useless) and the KDC-REP enc-part (etype 23 RC4, encrypted with the **user's** key — the roast target).
   Use `kerberos.encryptedKDCREPData_cipher`.

```bash
FULL=$(tshark -r capture.pcap -Y "kerberos.msg_type == 11" -T fields -e kerberos.encryptedKDCREPData_cipher)
# hashcat 18200 format: $krb5asrep$23$user@REALM:<first 16 bytes = checksum>$<rest>
printf '$krb5asrep$23$Hurricane@REBCORP.HTB:%s$%s\n' "${FULL:0:32}" "${FULL:32}" > hurricane.asrep
hashcat -m 18200 hurricane.asrep /usr/share/wordlists/rockyou.txt
# -> april18
```

(Note: john's `krb5asrep` format rejected this string with "No password hashes loaded"; hashcat 18200
parsed it without complaint.)

### Driving the Q&A

The docker presents the eleven questions over a socket; a short script maps each prompt to its
pcap-derived answer and submits them in one connection (the instance rate-limits after a handful of wrong
answers, so answer all eleven in a single session):

```python
RULES = [
    ("compromised",   "Copper"),
    ("distinguished", "CN=SRV195,OU=Domain Controllers,DC=rebcorp,DC=htb"),
    ("manage",        "rebcorp.htb"),
    ("ranger",        "14"),
    ("ldap query",    "(objectClass=group)"),
    ("non-standard",  "5"),
    ("disabled",      "Radiation"),
    ("field name",    "wWWHomePage"),
    ("value",         "http://rebcorp.htb/qPvAdQ.php"),
    ("persistence",   "B4ck,Enclave"),
    ("password",      "april18"),
]
```

All eleven correct → `HTB{...}` (redacted).

## Why it worked

Plain LDAP on port 389 is unauthenticated-at-the-transport and **unencrypted**
([CWE-319](https://cwe.mitre.org/data/definitions/319.html)), so a single capture is a complete audit log
of an attacker's directory recon *and* their writes. AS-REP roasting works because an account with
pre-authentication disabled lets anyone request a ticket whose response is encrypted under the user's key,
turning a weak password into an offline-crackable hash — a missing-authentication weakness
([CWE-287](https://cwe.mitre.org/data/definitions/287.html)).

## Fix / defense

- **Encrypt LDAP** — require LDAPS / StartTLS or LDAP signing + channel binding so recon and modifications
  aren't visible (or tamperable) on the wire.
- **Kill AS-REP roasting** — never set *"Do not require Kerberos pre-authentication"*; audit
  `userAccountControl` for the `0x400000` bit and give any such accounts long random passwords.
- **Monitor AD writes** — alert on `wWWHomePage`/SPN/`member` changes and new account creation (Directory
  Service events 5136 / 4720 / 4728); the whole chain is loud in the logs.
- **Lock down free-text attributes** — `wWWHomePage`, `info`, and `description` are favourite payload
  stash spots.
