---
layout: post
title: "Fake Boost"
date: 2027-07-14 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, pcap, wireshark, tshark, powershell, obfuscation, aes-cbc, malware-analysis, discord, data-exfiltration, reverse-engineering]
---

## Overview

Fake Boost is an HTB Forensics challenge (Easy) involving a pcapng capture of a Discord Nitro scam malware infection. The attacker delivers an obfuscated PowerShell script disguised as a "Free Discord Nitro" download, which steals tokens from browser profiles and exfiltrates them AES-256-CBC encrypted. The flag is split across two encoded blobs: `part1` embedded in the PowerShell payload (base64) and `part2` hidden in the base64-encoded Email field of the encrypted exfiltration JSON.

---

## Analysis

### HTTP traffic in the pcap

```bash
tshark -r capture.pcapng -Y "http" -T fields -e frame.number -e http.request.method \
  -e http.request.uri -e http.response.code 2>/dev/null
```

Two suspicious HTTP endpoints stand out:
- `GET /freediscordnitro` → 200 (malware delivery, `application/octet-stream`)
- `POST /rj1893rj1joijdkajwda` → 200 (data exfiltration)

### Decoding the PowerShell payload

Extract the response body from frame 328 (the `/freediscordnitro` response):

```bash
tshark -r capture.pcapng -Y "frame.number==328" -T fields -e data.data 2>/dev/null \
  | python3 -c "import sys; print(bytes.fromhex(sys.stdin.read().strip()).decode('utf-8','replace'))"
```

The body is a PowerShell variable assignment:
```powershell
$jozeq3n = "9ByXkACd1BHd..."   # ~8000-char string
```

The script reverses the string, base64-decodes it, then `Invoke-Expression`s the result:
```powershell
$s0yAY2gmHVNFd7QZ = $jozeq3n.ToCharArray()
[array]::Reverse($s0yAY2gmHVNFd7QZ)
$lOAdCODEoPX3ZoUgP2T6cvl3KEK = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String(-join $s0yAY2gmHVNFd7QZ))
Invoke-Expression $lOAdCODEoPX3ZoUgP2T6cvl3KEK
```

Decode from Python:

```python
import base64
obfuscated = "9ByXkACd1BHd..."   # from pcap frame 328
decoded = base64.b64decode(obfuscated[::-1]).decode('utf-8')
```

The decoded script:
1. Searches browser profile directories (`Chrome`, `Brave`, `Opera`, `Firefox`) for Discord tokens (regex `[\w-]{26}\.[\w-]{6}\.[\w-]{25,110}`)
2. Fetches Discord user info via `GET https://discord.com/api/v9/users/@me` with each token
3. Encrypts the results with AES-256-CBC and POSTs to the attacker's server

Key variables in the decoded script:
```powershell
$part1 = "SFRCe2ZyMzNfTjE3cjBHM25fM3hwMDUzZCFf"
$AES_KEY = "Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k="
```

```python
import base64
base64.b64decode("SFRCe2ZyMzNfTjE3cjBHM25fM3hwMDUzZCFf").decode()
# → 'HTB{fr33_N17r0G3n_3xp053d!_'
```

### AES encryption scheme

The `Encrypt-String` function prepends the auto-generated IV to the ciphertext, then base64-encodes the whole thing:
```powershell
function Encrypt-String($key, $plaintext) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    [System.Convert]::ToBase64String($fullData)
}
```

Format: `base64(IV[16] || AES-256-CBC-ciphertext)`.

### Decrypting the exfiltrated data

Extract the POST body from frame 15422 and decrypt:

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

AES_KEY = base64.b64decode("Y1dwaHJOVGs5d2dXWjkzdDE5amF5cW5sYUR1SWVGS2k=")
# → b'cWphrNTk9wgWZ93t19jayqnlaDuIeFKi'

# POST body hex from pcap frame 15422 → ascii base64 string → decode
post_b64 = bytes.fromhex("6245472b...3d3d").decode('ascii')
ciphertext_with_iv = base64.b64decode(post_b64)

iv = ciphertext_with_iv[:16]
ciphertext = ciphertext_with_iv[16:]

cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
print(plaintext)
```

Decrypted JSON:
```json
[
    {
        "ID": "1212103240066535494",
        "Email": "YjNXNHIzXzBmX1QwMF9nMDBkXzJfYjNfN3J1M18wZmYzcjV9",
        "GlobalName": "phreaks_admin",
        "Token": "MoIxtjEwMz20M5ArNjUzNTQ5NA.Gw3-GW.bGyEkOVlZCsfQ8-6FQnxc9sMa15h7UP3cCOFNk"
    }
]
```

The `Email` field is itself base64-encoded — another obfuscation layer:

```python
import base64
base64.b64decode("YjNXNHIzXzBmX1QwMF9nMDBkXzJfYjNfN3J1M18wZmYzcjV9").decode()
# → 'b3W4r3_0f_T00_g00d_2_b3_7ru3_0ff3r5}'
```

---

## Solution

`solve.py`:

```python
#!/usr/bin/env python3
import sys, re, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

try:
    from scapy.all import rdpcap, TCP
    pkts = rdpcap(sys.argv[1] if len(sys.argv) > 1 else "capture.pcapng")
    http_payloads = [bytes(p[TCP].payload) for p in pkts if p.haslayer(TCP) and p[TCP].payload]
except Exception:
    http_payloads = []

# ------- Step 1: decode the PowerShell from /freediscordnitro -------
# Frame 328 response body begins with $jozeq3n = "..."
# (extract manually with tshark if needed)

# Simulated from tshark extraction:
import subprocess, json

pcap = sys.argv[1] if len(sys.argv) > 1 else "capture.pcapng"

# Get GET /freediscordnitro response body
ps_hex = subprocess.check_output(
    ["tshark", "-r", pcap, "-Y", "frame.number==328", "-T", "fields", "-e", "data.data"],
    stderr=subprocess.DEVNULL
).decode().strip()
ps_body = bytes.fromhex(ps_hex).decode('utf-8', errors='replace')
if '\r\n\r\n' in ps_body:
    ps_body = ps_body.split('\r\n\r\n', 1)[1]

m = re.search(r'\$jozeq3n = "([^"]+)"', ps_body)
decoded_ps = base64.b64decode(m.group(1)[::-1]).decode('utf-8', errors='replace')

m1 = re.search(r'\$part1 = "([^"]+)"', decoded_ps)
part1 = base64.b64decode(m1.group(1)).decode()
print(f"[*] part1: {part1}")

m_key = re.search(r'\$AES_KEY = "([^"]+)"', decoded_ps)
aes_key = base64.b64decode(m_key.group(1))
print(f"[*] AES key: {aes_key}")

# ------- Step 2: decrypt POST body from /rj1893rj1joijdkajwda -------
post_hex = subprocess.check_output(
    ["tshark", "-r", pcap, "-Y", "frame.number==15422", "-T", "fields", "-e", "data.data"],
    stderr=subprocess.DEVNULL
).decode().strip()
post_b64 = bytes.fromhex(post_hex).decode('ascii')
blob = base64.b64decode(post_b64)
iv, ct = blob[:16], blob[16:]

cipher = AES.new(aes_key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
data = json.loads(plaintext)

# ------- Step 3: decode the base64 Email field -------
email_b64 = data[0]["Email"]
part2 = base64.b64decode(email_b64).decode()
print(f"[*] part2: {part2}")

flag = part1 + part2
print(f"\n[+] FLAG: {flag}")
```

```
[*] part1: HTB{fr33_N17r0G3n_3xp053d!_
[*] AES key: b'cWphrNTk9wgWZ93t19jayqnlaDuIeFKi'
[*] part2: b3W4r3_0f_T00_g00d_2_b3_7ru3_0ff3r5}

[+] FLAG: HTB{fr33_N17r0G3n_3xp053d!_b3W4r3_0f_T00_g00d_2_b3_7ru3_0ff3r5}
```

---

## Why it worked

Three obfuscation layers, each peeled with standard Python:

1. **PowerShell string reversal + base64**: `$jozeq3n` holds a reversed base64 blob; `[array]::Reverse` + `FromBase64String` + `Invoke-Expression` executes it. Reversed-then-base64 is a cheap evasion trick to defeat simple pattern matchers looking for `powershell -enc`.

2. **AES-256-CBC with prepended IV**: The encryption scheme stores the random IV as the first 16 bytes of the ciphertext before base64-encoding — a common .NET `AesManaged` pattern. Knowing the format and the static key (embedded in the same script that does the encrypting) makes decryption trivial.

3. **Base64 Email field**: The second flag fragment is stored in the `Email` field of the stolen Discord profile JSON — an exfiltration-within-exfiltration layer designed to hide the flag from casual inspection of the decrypted output.

---

## Fix / Defense

- **Process-level telemetry**: PowerShell `Invoke-Expression` on a base64/reversed blob is a classic IOC. Enable PowerShell Script Block Logging (`HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`).
- **Network egress**: Outbound POST to a non-Discord IP while the browser profile directories are being read is an anomalous combination that EDR/NDR should catch.
- **Discord token scope**: Applications with read access to browser local storage can steal Discord tokens — this is a client-side [CWE-312](https://cwe.mitre.org/data/definitions/312.html) (cleartext sensitive information storage) issue on Discord's side; users should enable hardware security key MFA to limit the damage of a stolen token.
