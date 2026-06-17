---
title: "Photon Lockdown"
date: 2026-09-15 09:00:00 -0500
categories: [HackTheBox, Challenges, Hardware]
tags: [hackthebox, challenge, hardware, firmware, squashfs, hardcoded-credentials, reverse-engineering]
description: "An Optical Network Terminal's firmware is handed over for analysis; its root filesystem is a squashfs image, and the device's superuser password sits in cleartext inside the factory-default config — a textbook hard-coded-credentials flaw extracted with nothing but unsquashfs and grep."
---

## Overview

`Photon Lockdown` is a Very Easy HackTheBox **Hardware** challenge. You're given a copy of an Optical Network Terminal (ONT) firmware image and asked to extract its hard-coded credentials. There's no live target — the whole thing is solved offline. The device's root filesystem ships as a squashfs blob, and the built-in admin password is stored in cleartext in the factory-default config, a classic [use of hard-coded credentials](https://cwe.mitre.org/data/definitions/798.html) ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)).

## The technique

Embedded devices — routers, ONTs, IP cameras — almost always pack their entire Linux root filesystem into a single read-only **squashfs** image. Vendors frequently bake a built-in superuser credential into the firmware's default config so that a factory reset still leaves a working admin login. Because the firmware image is just a filesystem, anyone who can download it can mount it and read that password directly: no device, no network, no exploit.

The solve is three moves: identify the filesystem, extract it, grep the config tree for secrets.

## Solution

The challenge archive holds the ONT firmware:

```bash
unzip -P hackthebox files.zip
file ONT/rootfs
```

```
ONT/rootfs: Squashfs filesystem, little endian, version 4.0, zlib compressed
```

Explode the squashfs into a normal directory tree:

```bash
unsquashfs -d squashfs-root ONT/rootfs
```

> If the image were a wrapped/multi-part firmware rather than a bare squashfs, `binwalk -eM firmware.bin` would carve and recursively extract every embedded filesystem instead.

Now search the config tree for hard-coded secrets:

```bash
grep -aoE 'HTB\{[^}]+\}' squashfs-root/etc/config_default.xml
```

The superuser credential lives in the factory-default config:

```xml
<Value Name="SUSER_NAME"     Value="admin"/>
<Value Name="SUSER_PASSWORD" Value="HTB{...}"/>
```

`SUSER` is *superuser* — on Realtek/Broadcom ONT firmware the built-in admin credential is stored in cleartext in `/etc/config_default.xml`. That password is the flag.

## Why it worked

The vendor wants a factory reset to still leave a usable admin account, so the credential is hard-coded into the firmware config rather than provisioned per device. Since the firmware image is just a filesystem, anybody holding it can mount it and read the password straight off disk. After extracting any firmware rootfs, the high-value places to look are `/etc/config_default.xml`, `/etc/shadow`, `/etc/passwd`, `/etc/*.conf`, NVRAM defaults, and the `/etc/init.d` scripts — and `grep -a` forces binary/non-UTF8 config blobs to be searched as text so nothing is missed.

## Fix / defense

- Never ship admin passwords inside firmware config.
- Provision a unique per-device credential at first boot.
- Store only salted password hashes, never cleartext.
- Force a password change during initial device setup.
