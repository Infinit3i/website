---
layout: post
title: "Strike Back"
date: 2028-01-17 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, cobalt-strike, c2, minidump, dfir]
---

## Overview

Strike Back is a Medium **Forensics** challenge: you get a packet capture and a process
**minidump** of a compromised host. The traffic is an encrypted **Cobalt Strike** beacon,
and the twist is that the beacon's own memory dump hands you the session keys — decrypt the
C2, reassemble the file the attacker exfiltrated, and read the flag out of it.

## Recognising the beacon

`freesteam.exe` is fetched over HTTP in the capture and then beacons to `/match` (tasks)
and `/submit.php?id=…` (POST callbacks). Strings in the minidump give it away as Cobalt
Strike:

```
IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')
powershell -nop -exec bypass -EncodedCommand "%s"
could not run command (w/ token) because of its length of %d bytes!
```

## Pulling the keys out of the dump

Cobalt Strike encrypts each session with a random AES-128 key and an HMAC-SHA256 key —
both of which live in the beacon process memory. Didier Stevens' `cs-extract-key.py`
finds them (it validates candidates against a real callback body):

```bash
python3 cs-extract-key.py -c <first_POST_body_hex> freesteam.dmp
# AES : 3ae7f995a2392c86e3fa8b6fbc3d953a
# HMAC: bf2d35c0e9b64bc46e6d513c1d0f6ffe
```

## Decrypting the callbacks

Each POST body is a stream of framed packets `[4-byte size][ciphertext][16-byte HMAC]`.
Verify the HMAC, then AES-128-**CBC** decrypt with the fixed IV `abcdefghijklmnop`:

```python
from Crypto.Cipher import AES
import struct, hmac, hashlib

def packets(body, AESK, HMACK, IV=b'abcdefghijklmnop'):
    off = 0
    while off + 4 <= len(body):
        size = struct.unpack('>I', body[off:off+4])[0]
        if not size or off+4+size > len(body): break
        enc = body[off+4:off+4+size]; off += 4 + size
        ct, mac = enc[:-16], enc[-16:]
        assert hmac.new(HMACK, ct, hashlib.sha256).digest()[:16] == mac
        pt = AES.new(AESK, AES.MODE_CBC, IV).decrypt(ct)
        dlen = struct.unpack('>I', pt[4:8])[0]
        yield pt[8:8+dlen]                       # [4B callback_type][payload]
```

The decrypted callbacks show the attacker's whole session: `whoami`, a hashdump, mimikatz
output, a Desktop listing, and a file download.

## Reassembling the exfil

The file leaves as `CALLBACK_FILE_WRITE` (type 8) chunks — `[type][file_id][chunk]` —
spread across the big exfil POST. Concatenate them:

```python
filebuf = b''
for data in packets(big_post_body, AESK, HMACK):
    if struct.unpack('>I', data[:4])[0] == 8:
        filebuf += data[8:]
open('orders.pdf', 'wb').write(filebuf)           # %PDF-1.4 -> pdftotext -> HTB{...}
```

## Why it worked

Cobalt Strike traffic is only as secret as the per-session keys, and those sit in the
beacon's own memory. A process dump gives them up, so the entire capture — commands,
credentials, and exfiltrated files — becomes cleartext. It's the memory-forensics analogue
of pulling TLS keys to decrypt a pcap.

## Fix / defense

For an attacker: beacon process memory is the crown jewel — protect it. For a defender:
this is exactly why capturing a beacon's memory is so valuable — dump it and every byte of
its C2 is recoverable.
