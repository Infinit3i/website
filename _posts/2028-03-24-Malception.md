---
layout: post
title: "Malception"
date: 2028-03-24 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, forensics, pcap, ransomware, xor, known-plaintext, rsa, aes, pbkdf2, dotnet]
description: "A ransomware infection captured in a pcap. The layered RSA-wrapped AES file encryption collapses on one mistake: a short repeating-XOR key protects both the RSA private key and the victim's file path. The path is known plaintext, so eight recovered key bytes unravel everything."
---

## Overview

Malception is a Medium reversing challenge that hands you a single packet capture of a
ransomware infection and asks you to recover the encrypted files. The malware layers proper
cryptography — a per-file AES-CBC content key, wrapped by RSA — but reuses **one short
repeating-XOR key** to obscure both the RSA private key *and* the victim's file path. Because
the file path is predictable, that repeating key is recoverable by [known-plaintext](https://cwe.mitre.org/data/definitions/323.html),
and the whole scheme unravels top to bottom. The flag lives inside one of the two decrypted files.

## The technique

The pcap contains a mix of DNS, TLS, SMB, Kerberos and — the interesting part — plain HTTP and
two raw TCP channels. A victim downloads an executable over HTTP, which pulls a small key over
one TCP port and then exfiltrates encrypted files over another. Each encrypted file is sent as a
tiny length-prefixed protocol, and the encryption for each file looks like this:

- `RSA_encrypt(md5(GUID))` — a fresh random hash, wrapped with a fresh 1024-bit RSA key
- `XOR(private_key_xml, cmdkey)` — the RSA **private** key, only XOR-obscured
- `XOR("C:\Users\rick.a\Documents\...\<name>.enc", cmdkey)` — the file path, same key
- `AES_CBC(file_content)` — the content, keyed off the MD5 hash

The fatal flaw: the `cmdkey` used to hide the private key is the *same* 8-byte repeating key used
to hide the file path — and a Windows profile path (`C:\Users\<user>\Documents\`) is free
[known plaintext](https://cwe.mitre.org/data/definitions/323.html). Recover the key from the path,
and you can peel the XOR off the private key, decrypt the RSA-wrapped hash, derive the AES key, and
read the files.

## Solution

First carve the dropper and the exfil streams out of the capture:

```bash
tshark -r capture.pcapng -q -z conv,tcp        # find the odd ports (31337 handshake, 31338 exfil)
tshark -r capture.pcapng --export-objects http,./out   # pull the downloaded PE
```

The two files are exfiltrated over TCP 31338 (one connection per file). Each connection is a series
of messages framed as **ASCII-decimal length + newline + that many raw bytes**. Pull the client
bytes for each connection to hex:

```bash
tshark -r capture.pcapng -Y "tcp.srcport==49829 && tcp.dstport==31338 && tcp.len>0" -T fields -e data | tr -d '\n' > c49829.hex
tshark -r capture.pcapng -Y "tcp.srcport==49830 && tcp.dstport==31338 && tcp.len>0" -T fields -e data | tr -d '\n' > c49830.hex
```

The whole decryption is one script. Recover the repeating key from the known path prefix, XOR out
the private key, RSA-decrypt the wrapped hash, then reproduce the .NET
[`Rfc2898DeriveBytes`](https://learn.microsoft.com/dotnet/api/system.security.cryptography.rfc2898derivebytes)
(PBKDF2-HMAC-SHA1, count=2) key/IV derivation — the key is the first 32 bytes and the IV is the
*next* 16 bytes of one continuous KDF stream.

Create `solve.py`:

```python
import binascii, base64
import xml.etree.ElementTree as ET
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2

SALT = bytes([21,204,127,153,3,237,10,26,19,103,23,31,55,49,32,57])

def parse_msgs(data):                                          # ascii-len + \n + bytes
    out=[]; i=0
    while i<len(data):
        j=data.index(b'\n',i); n=int(data[i:j]); s=j+1
        out.append(data[s:s+n]); i=s+n
    return out

def rsa_from_xml(x):
    r=ET.fromstring(x); g=lambda t:int.from_bytes(base64.b64decode(r.find(t).text),'big')
    return RSA.construct((g('Modulus'),g('Exponent'),g('D'),g('P'),g('Q')))

known = b"C:\\Users\\rick.a\\Documents\\"                       # predictable = known plaintext

for hexfn,out in [('c49829.hex','secret.jpg'),('c49830.hex','Official.pdf')]:
    m = parse_msgs(binascii.unhexlify(open(hexfn).read().strip()))
    ck = bytes(m[1][i] ^ known[i] for i in range(8))           # recover 8-byte command key
    xor = lambda b: bytes(b[i] ^ ck[i % 8] for i in range(len(b)))
    d0  = xor(m[0])
    a   = d0.find(b'<RSAKeyValue>'); b = d0.find(b'</RSAKeyValue>') + 14
    priv = rsa_from_xml(d0[a:b])                               # private key was only XOR-obscured
    h   = PKCS1_v1_5.new(priv).decrypt(m[0][:a], None)         # 16-byte MD5(GUID)
    mat = PBKDF2(base64.b64encode(h), SALT, dkLen=48, count=2) # key=first 32, iv=next 16
    pt  = AES.new(mat[:32], AES.MODE_CBC, mat[32:48]).decrypt(m[2])
    open(out,'wb').write(pt[:-pt[-1]])
    print("wrote", out)
```

Run it and read the flag out of the decrypted PDF:

```bash
python3 solve.py
pdftotext Official.pdf - | grep -i HTB    # HTB{...}
```

The two recovered files are a JPEG and a PDF; the flag is text inside the PDF.

## Why it worked

Layered AES + RSA is only as strong as the key protecting the keys. Here that "key of keys" is a
short repeating XOR value applied to *both* a secret (the RSA private key) and attacker-guessable
data (the file path). A path derived from the Windows profile layout is not secret — it is
[free known plaintext](https://cwe.mitre.org/data/definitions/323.html). XORing the known prefix
against its ciphertext recovers the eight key bytes directly, and from there every layer above
falls: private key → wrapped hash → AES key → files.

## Fix / defense

- Never protect a secret with a key you also apply to attacker-guessable data (a filename, header,
  or username).
- Never obscure a private key with a repeating XOR — wrap it with a proper KEM / authenticated
  scheme using a random, single-use key.
- Derive an independent random key per artifact; never reuse one keystream across two data items.
- From a defender's seat: the same full-packet visibility that made recovery possible is what lets
  you spot exfil on odd ports (31337/31338) — egress filtering would have cut the channel.
