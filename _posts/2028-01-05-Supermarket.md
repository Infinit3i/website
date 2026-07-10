---
layout: post
title: "HTB Challenge: Supermarket"
date: 2028-01-05 09:00:00 -0500
categories: [HackTheBox, Challenges, Mobile]
tags: [hackthebox, challenge, mobile, android, jni, unicorn, aes, reversing, cwe-321, cwe-656]
---

A tiny Android shopping app asks for a "discount code" and gives you half price if you
get it right. The whole check runs on the phone: it AES-decrypts a baked-in ciphertext
with a baked-in key and compares the result to what you typed. The catch — the key,
ciphertext, and algorithm all live inside a **native `.so`**, each byte hidden by an XOR
of two `.rodata` values, so `strings` finds nothing. We recover them by **emulating the
native library with Unicorn**, then decrypt. The plaintext is the discount code and the
flag.

## Overview

- **Category:** Mobile · **Difficulty:** Medium
- **Vuln class:** [CWE-321](https://cwe.mitre.org/data/definitions/321.html) (Use of a
  Hard-coded Cryptographic Key) with native-code obfuscation standing in for real
  confidentiality ([CWE-656](https://cwe.mitre.org/data/definitions/656.html), reliance on
  security through obscurity).
- **Path:** decompile the APK → find the client-side AES check → recover the native
  key/ciphertext by emulation → AES-decrypt → flag.

## The technique

Decompiling `supermarket.apk` with jadx, the discount check in
`MainActivity.onTextChanged` is entirely client-side:

```java
String stringFromJNI = mainActivity.stringFromJNI();          // base64 ciphertext
SecretKeySpec key = new SecretKeySpec(
        mainActivity.stringFromJNI2().getBytes(),             // AES key
        mainActivity.stringFromJNI3());                       // "AES"
Cipher cipher = Cipher.getInstance(mainActivity.stringFromJNI3());
cipher.init(Cipher.DECRYPT_MODE, key);
if (obj.equals(new String(cipher.doFinal(Base64.decode(stringFromJNI, 0)), "utf-8"))) {
    // correct discount code
}
```

So the correct discount code is simply `AES_decrypt(Base64(stringFromJNI()), stringFromJNI2())`,
and Java's `Cipher.getInstance("AES")` defaults to **AES/ECB/PKCS5Padding**. There is no
server; the app is not a trust boundary.

The three secrets are `native` methods implemented in `lib/*/libsupermarket.so`. A `strings`
dump of the `.so` shows nothing useful: each getter builds its return value **one byte at a
time**, computing every character as `XOR(byte_a, byte_b)` where `a` and `b` come from two
different, scattered `.rodata` addresses. Both operands ship in the binary, so it is
obfuscation, not protection — but reconstructing the shuffled byte order by hand is
error-prone. It is far cleaner to **emulate** the native code and read what it produces.

## Solution

The solver maps the `.so` into a Unicorn ARM64 CPU, fakes a `JNIEnv*`, runs each getter, and
captures the pointer handed to `NewStringUTF`. Two details make it work: we stub the imported
libc functions, and we hand-implement libc++'s `__grow_by` for the long ciphertext string
(its GOT is unrelocated in an isolated `.so`, so the real call would jump to address 0).

Create `solve.py`:

```python
import sys, struct, base64
from unicorn import *
from unicorn.arm64_const import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

SO = sys.argv[1] if len(sys.argv) > 1 else "libs/lib/arm64-v8a/libsupermarket.so"
data = open(SO, "rb").read()

IMP = {0xe610:"strlen_chk",0xe690:"memmove_chk",0xe6e0:"stack_chk_fail",
       0xe7f0:"memmove",0xe870:"strlen",0xe8b0:"malloc",0xe8c0:"memcpy",
       0xe8d0:"memset",0xe900:"free",0xe5b0:"cxa_finalize",0xe930:"cxa_atexit",
       0xe940:"grow_by"}
ENTRIES = [(0xe98c,"algo"),(0xea2c,"key"),(0xeec4,"cipher_b64")]

uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
uc.mem_map(0, 0x60000);        uc.mem_write(0, data)
uc.mem_map(0x200000, 0x100000)                    # stack
uc.mem_map(0x400000, 0x100000)                    # heap
heap = [0x400100]
ENV, VT, NSU = 0x500000, 0x501000, 0xC0DE0000
uc.mem_map(ENV, 0x10000)
uc.mem_map(NSU, 0x1000); uc.mem_write(NSU, b"\xc0\x03\x5f\xd6")   # ret
uc.mem_write(ENV, struct.pack("<Q", VT))
for off in range(0, 0x800, 8):                    # NewStringUTF = JNIEnv idx 167 (off 0x538)
    uc.mem_write(VT + off, struct.pack("<Q", NSU))
res = {}

def cstr(a):
    o = b""
    while (c := uc.mem_read(a, 1)) != b"\x00":
        o += c; a += 1
    return o

def hook(uc, addr, size, u):
    a = addr & 0xffffffff
    if a == (NSU & 0xffffffff):                    # NewStringUTF(env, char*) -> grab x1
        res["s"] = cstr(uc.reg_read(UC_ARM64_REG_X1)); uc.emu_stop(); return
    if a not in IMP: return
    n = IMP[a]; lr = uc.reg_read(UC_ARM64_REG_LR)
    x0,x1,x2 = (uc.reg_read(r) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2))
    ret = 0
    if n == "grow_by":                             # SSO->heap; layout {cap@0,size@8,data@16}
        obj = x0; old_sz = uc.reg_read(UC_ARM64_REG_X3); n_copy = uc.reg_read(UC_ARM64_REG_X4)
        sso = bytes(uc.mem_read(obj+1, n_copy)); cap = 512; buf = heap[0]
        heap[0] = (buf+cap+15) & ~15
        uc.mem_write(buf, b"\x00"*cap); uc.mem_write(buf, sso)
        uc.mem_write(obj+0, struct.pack("<Q",(cap<<1)|1))   # cap, is_long = bit0
        uc.mem_write(obj+8, struct.pack("<Q",old_sz))
        uc.mem_write(obj+16, struct.pack("<Q",buf))
        uc.reg_write(UC_ARM64_REG_PC, lr); return
    if n == "malloc": ret = heap[0]; heap[0] = (heap[0]+x0+15) & ~15
    elif n in ("memcpy","memmove","memmove_chk"): uc.mem_write(x0, bytes(uc.mem_read(x1,x2))); ret = x0
    elif n == "memset": uc.mem_write(x0, bytes([x1&0xff])*x2); ret = x0
    elif n in ("strlen","strlen_chk"): ret = len(cstr(x0))
    elif n == "stack_chk_fail": uc.emu_stop(); return
    uc.reg_write(UC_ARM64_REG_X0, ret); uc.reg_write(UC_ARM64_REG_PC, lr)

uc.hook_add(UC_HOOK_CODE, hook)

def run(entry):
    res.clear()
    uc.reg_write(UC_ARM64_REG_SP, 0x280000)
    uc.reg_write(UC_ARM64_REG_X0, ENV); uc.reg_write(UC_ARM64_REG_X1, 0x555000)
    uc.reg_write(UC_ARM64_REG_LR, 0xFEE1DEAD)
    try: uc.reg_write(UC_ARM64_REG_TPIDR_EL0, ENV+0x2000)
    except Exception: pass
    uc.emu_start(entry, 0, count=2_000_000)
    return res["s"]

vals = {name: run(e) for e, name in ENTRIES}
algo, key, ct_b64 = vals["algo"].decode(), vals["key"], vals["cipher_b64"].decode()
print(f"[native] algo={algo!r}  key={key!r}  ct(b64)={ct_b64!r}")
pt = AES.new(key, AES.MODE_ECB).decrypt(base64.b64decode(ct_b64))
print("FLAG:", unpad(pt, 16).decode())
```

Run it against the extracted library:

```bash
unzip -o -P hackthebox files.zip -d files
unzip -o files/supermarket.apk 'lib/*' -d libs
python3 solve.py libs/lib/arm64-v8a/libsupermarket.so
```

```
[native] algo='AES'  key=b'2mubW7SBIsaFkTXE'  ct(b64)='FqVu3UluTNtSELauTRPFvq9wBdfXmbzbOgq4NS/KasE='
FLAG: HTB{...}
```

## Why it worked

The app keeps a secret and checks it in a place the user fully controls — the client.
Pushing the key and ciphertext into native code and XOR-splitting the bytes across `.rodata`
only raises the cost of *reading* the secret; it never removes it. Because both XOR operands,
the key, and the ciphertext all ship in the APK, offline emulation of the native code recovers
everything with no device, no root, and no Frida. The one implementation snag —
libc++'s Small String Optimization — is what forces the `__grow_by` stub: strings up to 22
bytes stay inline (the 16-byte key), while the ~44-character base-64 ciphertext becomes a
heap string whose growth helper is an unresolved import.

## Fix / defense

- **Validate secrets on a server, not the client.** The phone should learn only pass or fail,
  never hold the answer.
- **Never hard-code cryptographic keys.** Derive them from a user secret with a KDF
  (PBKDF2 / scrypt / Argon2), or bind them to the Android Keystore / StrongBox so raw key
  bytes are never extractable by a static analyst.
- Treat native code and `.rodata` XOR as obfuscation, not confidentiality
  ([CWE-656](https://cwe.mitre.org/data/definitions/656.html)). Anything shipped in the app
  bundle is effectively public.
