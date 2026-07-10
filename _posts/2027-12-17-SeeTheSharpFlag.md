---
title: "SeeTheSharpFlag"
date: 2027-12-17 09:00:00 -0500
categories: [HackTheBox, Challenges, Mobile]
tags: [hackthebox, challenge, mobile, xamarin, android, apk, reversing, dotnet, aes, cwe-321]
description: "A medium Mobile challenge: a Xamarin.Android password app whose C# assembly is LZ4-compressed with an XALZ header. Decompress it, decompile with ilspycmd, and the 'password' is just an AES-CBC decrypt of a hardcoded key, IV, and ciphertext — so the plaintext is the flag."
---

## Overview

`SeeTheSharpFlag` is a medium HackTheBox **Mobile** challenge. You get a single Android APK
(`com.companyname.seethesharpflag-x86.apk`) for a password-verification app: type the right password
and it says the message is correct. The name is the hint — it is a **Xamarin** app, so the logic is C#
compiled to a .NET assembly bundled inside the APK. The catch is that the assembly is stored
LZ4-compressed with an `XALZ` header, which trips up decompilers until you unwrap it. Once decompiled,
the check turns out to be an AES decrypt of a hardcoded ciphertext with a hardcoded key and IV, and the
decrypted plaintext *is* the flag.

## The technique

Xamarin.Android compiles your C# to a normal .NET PE assembly, which it ships inside the APK under
`assemblies/`. Modern Xamarin, however, stores those DLLs **LZ4-compressed with a custom `XALZ` header**,
so the file magic is `XALZ` rather than the usual `MZ`. Point `ilspycmd` or dnSpy at it directly and you
get `BadImageFormatException: Image is too small` — the tool is reading a compressed blob, not a PE.

The container format is simple:

```
"XALZ"  (4 bytes magic)
uint32  descriptor index
uint32  uncompressed length
...     LZ4 BLOCK compressed payload
```

Strip the 12-byte header, LZ4-block-decompress the rest using the stored uncompressed length, and you
recover the real PE. From there it decompiles to ordinary C#, and the password check is trivially
invertible because the app carries its own secret — the classic
[client-side hardcoded cryptographic key](https://cwe.mitre.org/data/definitions/321.html)
([CWE-321](https://cwe.mitre.org/data/definitions/321.html)).

## Solution

Unzip the APK and locate the app assembly (`assemblies/SeeTheSharpFlag.dll`). Its header is `XALZ`, so
decompress it to a real DLL and decompile:

```bash
unzip -o com.companyname.seethesharpflag-x86.apk -d apk_x >/dev/null
xxd apk_x/assemblies/SeeTheSharpFlag.dll | head -1   # 5841 4c5a ... = "XALZ"
```

Create `unxalz.py`:

```python
import struct, lz4.block
d = open('apk_x/assemblies/SeeTheSharpFlag.dll', 'rb').read()
assert d[:4] == b'XALZ'
idx, ulen = struct.unpack('<II', d[4:12])
open('SeeTheSharpFlag_dec.dll', 'wb').write(lz4.block.decompress(d[12:], uncompressed_size=ulen))
```

```bash
python3 unxalz.py
ilspycmd SeeTheSharpFlag_dec.dll | grep -iA6 'Button_Clicked'
```

The decompiled `MainPage.Button_Clicked` reads three base64 literals — a ciphertext buffer, an AES key,
and an IV — decrypts with `AesManaged` (whose default is AES/CBC/PKCS7), and string-compares the result
to the user's input. Everything needed to invert it is right there, so decrypt offline.

Create `solve.py`:

```python
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ct  = base64.b64decode("sjAbajc4sWMUn6CHJBSfQ39p2fNg2trMVQ/MmTB5mno=")
key = base64.b64decode("6F+WgzEp5QXodJV+iTli4Q==")
iv  = base64.b64decode("DZ6YdaWJlZav26VmEEQ31A==")

pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
print(unpad(pt, 16).decode())
```

```bash
python3 solve.py
# HTB{...}
```

The printed plaintext is both the correct password and the flag.

## Why it worked

The app is not a trust boundary. It ships the AES key, the IV, and the ciphertext, so the "verification"
is a decrypt that anyone holding the APK can run offline — the only speed bump is the `XALZ` wrapper, and
that is packaging, not protection. Compressing the assembly hides nothing once you know the 12-byte header
layout. This is the same root cause as vault/photo-hider apps that XOR files with an APK-baked key: a
secret stored in the client is a recovered secret.

## Fix / defense

Never store the verification secret client-side. Derive keys from a user secret through a KDF
(PBKDF2/scrypt/Argon2) instead of embedding them, or bind them to the Android Keystore / hardware-backed
StrongBox so the app can use a key without ever revealing its bytes to a static analyst. If a value must
be checked, check it server-side against something the client never holds.
