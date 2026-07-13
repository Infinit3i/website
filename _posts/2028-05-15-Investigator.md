---
layout: post
title: "Investigator"
date: 2028-05-15 09:00:00 -0500
categories: [HackTheBox, Challenges, Mobile]
tags: [hackthebox, challenge, mobile, android-forensics, adb-backup, whatsapp, crypt14, password-cracking, cwe-916, cwe-521]
description: "An Android backup whose lock-screen password unlocks everything — and whose 'obvious' WhatsApp flag is a decoy. The real one hides in the encrypted crypt14 store, unlocked with the app's own key."
---

## Overview

Investigator is a **Medium** HackTheBox **Mobile** challenge (Android forensics). You get an
encrypted Android backup (`backup.ab`) plus a `/system` dump. The path: crack the 5-letter
lock-screen password from `password.key`, reuse it to decrypt the AES-256 backup, then avoid the
decoy flag planted in the plaintext WhatsApp database and decrypt the *real* WhatsApp store —
`msgstore.db.crypt14` — with the app's own key.

## The technique

Three weaknesses chain together:

- The Android lock-screen credential is stored as an **unstretched** hash
  ([CWE-916](https://cwe.mitre.org/data/definitions/916.html)) — `SHA1(pw+salt) || MD5(pw+salt)`
  with the salt sitting in a world-readable SQLite DB. A 5-lowercase-letter password falls to
  brute force in seconds.
- The owner **reuses that lock-screen password** as the backup encryption password
  ([CWE-521](https://cwe.mitre.org/data/definitions/521.html)), so cracking one unlocks the other.
- The backup contains **two** copies of the WhatsApp chats: a convenient plaintext export (the
  bait) and the app's own encrypted `crypt14` store (the truth).

## Solution

### 1. Recover the salt and crack the lock-screen password

`system/locksettings.db` holds `lockscreen.password_salt` as a **signed Java long**. Android hashes
with its `Long.toHexString` form (lowercase hex, no leading zeros). `system/password.key` is
`SHA1(pw+saltHex)` (first 40 hex chars) concatenated with `MD5(pw+saltHex)`. The device policy
(`device_policies.xml`) advertises a 5-lowercase-letter password, so the keyspace is `26^5`:

```python
import hashlib, itertools, string
salthex = format(6675990079707233028, 'x')          # from locksettings.db
sha1 = open('system/password.key').read().strip().lower()[:40]
for t in itertools.product(string.ascii_lowercase, repeat=5):
    pw = ''.join(t)
    if hashlib.sha1((pw + salthex).encode()).hexdigest() == sha1:
        print(pw); break                              # -> the lock-screen password
```

### 2. Decrypt the ADB backup with the reused password

The `.ab` format is a 9-line plaintext header (`ANDROID BACKUP / ver / compressed / AES-256 /
userSalt / ckSalt / rounds / userIV / masterKeyBlob`) followed by ciphertext. Derive the user key
with PBKDF2, decrypt the master blob, then the payload, then inflate:

```python
import hashlib, zlib
from Crypto.Cipher import AES
user_key   = hashlib.pbkdf2_hmac('sha1', pw.encode(), user_salt, rounds, 32)
blob       = AES.new(user_key, AES.MODE_CBC, user_iv).decrypt(master_blob)   # -> [len|masterIV][len|masterKey][len|checksum]
plain      = AES.new(master_key, AES.MODE_CBC, master_iv).decrypt(payload)
tar_bytes  = zlib.decompress(plain[:-plain[-1]])                              # a tar of the whole backup
```

### 3. Ignore the decoy, decrypt the real WhatsApp store

The tar carries WhatsApp data twice:

- `apps/com.whatsapp/db/msgstore.db` — the ADB plaintext copy. A chat here says *"Here is your
  secret HTB{…}"*. **This is a decoy — HTB rejects it.** (If your submission is rejected here, you
  grabbed the bait; the flag was not "rotated".)
- `shared/0/WhatsApp/Databases/msgstore.db.crypt14` — WhatsApp's own encrypted backup, the
  authoritative store.

`crypt14` is decrypted with the app's Java-serialized key file `apps/com.whatsapp/f/key` using
[wa-crypt-tools](https://github.com/ElDavoo/wa-crypt-tools):

```bash
pip install wa-crypt-tools
wadecrypt apps/com.whatsapp/f/key \
          shared/0/WhatsApp/Databases/msgstore.db.crypt14 \
          msgstore_real.db
grep -ao 'HTB{[^}]*}' msgstore_real.db      # -> HTB{...}
```

The real flag lives only in the decrypted `crypt14` store — it differs from the decoy by a single
trailing suffix, exactly the kind of near-miss that burns a submission attempt.

## Why it worked

Low-entropy screen-lock secret + a world-readable salt + a published password policy make the
lock-screen hash brute-forceable offline. Password reuse then turns that one secret into the backup
KEK. The `.ab` container is a fully documented, invertible AES-CBC + zlib + tar format, so no
`abe.jar` is needed. Finally, a backup keeps both a plaintext and an encrypted copy of the same app
data — and only the encrypted one, unlocked with the app key, is authoritative.

## Fix / defense

- Don't reuse the lock-screen credential as a backup password; use a long random backup passphrase.
- File-based/full-disk encryption with a strong (not 5-letter) credential defeats the offline crack.
- Treat any exported plaintext database as sensitive — the encrypted `crypt14` was meant to protect
  the chats, but the ADB backup leaked a plaintext copy alongside it.

**Investigator's reusable lesson:** when a forensics flag is rejected, look for a *second, encrypted*
copy of the same data and decrypt it with the app's own key. The convenient plaintext copy is often
the bait.
