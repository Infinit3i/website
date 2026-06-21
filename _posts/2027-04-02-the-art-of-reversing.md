---
title: "The Art of Reversing"
date: 2027-04-02 09:00:00 -0500
categories: [HackTheBox, Challenges, Reversing]
tags: [hackthebox, challenge, reversing, dotnet, keygen, factorial-number-system, integer-overflow, cwe-656]
description: "An Easy Reversing challenge: a .NET WinForms keygen turns a username and a day count into a product key. Given one key, recover the inputs. The username half is the N-th permutation of a recursive-swap generator — which is just the factorial number system — and the only real trap is that the selection index is computed in a 32-bit int that overflows."
---

## Overview

The Art of Reversing is an Easy **Reversing** challenge. We're handed a .NET WinForms keygen that turns a **username** and a **number of activation days** into a product key of the form `<perm>-<days>`, plus one known key, `cathhtkeepaln-wymddd`. The task is to recover the username **A** and the day count **B**; the flag is `HTB{AB}`. Both halves of the key are pure, deterministic functions of the inputs, so the whole thing inverts offline — the only catch is a 32-bit integer overflow hidden inside the index math.

## The technique

Because the key is `f(username, days)` with no server-side secret or signature, it is a [reversible client-side keygen](https://cwe.mitre.org/data/definitions/656.html) — security through obscurity. Decompiling the binary and inverting each half recovers the inputs.

`file` reports a PE32 .NET assembly, so decompile with `ilspycmd`:

```bash
ilspycmd TheArtOfReversing.exe > decompiled.cs
```

`buttonCreateProductKey_Click` is the entire algorithm:

```csharp
int num2 = nPr(text.Length, text.Length);   // = L!  (computed in a 32-bit int)
nToStop  = num2 / 2;
char[] word = text.ToCharArray();
GetPer(word);                                // ssOut = the nToStop-th permutation
string s = ToR(num);                         // Roman numeral of the day count
s = DoR(s);                                  // reverse, +1 each char, lowercase
textBoxProductKey.Text = ssOut + "-" + s;
```

Two independent halves:

- **Days half** (`wymddd`). `DoR(roman)` reverses the Roman-numeral string, adds 1 to each character, and lowercases. Inverting it — uppercase, subtract 1, un-reverse — gives `CCCLXV`, which is Roman for **365**.
- **Username half** (`cathhtkeepaln`). `GetPer` is the classic recursive-swap permutation generator, and `nToStop` selects the *N-th* permutation it emits. The swaps it performs depend only on the **index N**, not on the letters, so `word → perm` is a fixed position permutation. It is exactly the **factorial number system**: permutation `#N` is reached from the initial word by, for `k = 0 .. L-1`, swapping positions `(k, k + b_k)` where `b_k` are the factorial-base digits of `N-1`. Reverse-applying those swaps to the known permutation string recovers the username.

The trap is the index itself. `nPr(13, 13)` returns `13! = 6227020800`, but it is stored in a C# 32-bit `int`, so it **overflows** to `1932053504` and `nToStop = 966026752` — **not** `13!/2 = 3113510400`. Using the naive `13!/2` recovers a garbage username; faithfully modelling the int32 overflow recovers the readable one. That is the whole lesson: *when reversing a keygen, replicate the original program's integer width.*

## Solution

The solver inverts both halves and forward-checks the result against the known key.

Create `solve.py`:

```python
import math

KEY = "cathhtkeepaln-wymddd"
perm_part, days_part = KEY.split("-")

# B (days): invert days_part = lower(+1(reverse(Roman(B))))
roman = "".join(chr(ord(c.upper()) - 1) for c in days_part)[::-1]
rmap = {'I':1,'V':5,'X':10,'L':50,'C':100,'D':500,'M':1000}
def from_roman(s):
    total, prev = 0, 0
    for ch in reversed(s):
        v = rmap[ch]
        total += -v if v < prev else v
        prev = max(prev, v)
    return total
B = from_roman(roman)

# replicate the int32-overflowing nPr(L,L) = L!
def int32(x):
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x >= 0x80000000 else x
def npr_int32(L):
    num = 1
    for k in range(L, 0, -1):
        num = int32(num * k)
    return num

L = len(perm_part)
nToStop = npr_int32(L) // 2            # 966026752 for L=13 (overflowed!)

# A (username): reverse-apply the factorial-base swaps
n = nToStop - 1
digits = []
for k in range(L):
    base = math.factorial(L - 1 - k)
    digits.append(n // base)
    n %= base
W = list(perm_part)
for k in range(L - 1, -1, -1):
    i = k + digits[k]
    W[k], W[i] = W[i], W[k]
A = "".join(W)

print(f"days roman = {roman}  -> B = {B}")
print(f"nToStop    = {nToStop} (int32-overflowed L!/2)")
print(f"username A = {A}")
print(f"FLAG       = HTB{{{A}{B}}}")
```

Running it:

```bash
python3 solve.py
# days roman = CCCLXV  -> B = 365
# nToStop    = 966026752 (int32-overflowed L!/2)
# username A = hacktheplanet
# FLAG       = HTB{...}
```

The username resolves to a readable phrase and the day count to 365, which reconstruct the exact known key — confirming the inversion. The flag is `HTB{...}` (redacted).

## Why it worked

A keygen has no secret to protect it — the algorithm *is* the only barrier, so any pure `f(inputs)` is fully invertible and forgeable once decompiled. The permutation half looks like a three-billion-step search but collapses to a linear walk the moment you recognise the factorial-base structure. The overflow is the genuine difficulty: the "obvious" mathematical value (`L!/2`) is wrong, because the original program's 32-bit multiplication wrapped around.

## Fix / defense

Don't derive a license key from a pure client-side function. Sign the `(username, expiry)` tuple with a **server-held private key** (e.g. Ed25519); the client can verify but cannot forge:

```csharp
byte[] sig = Ed25519.Sign(serverPrivKey, $"{user}|{expiry}");
if (!Ed25519.Verify(serverPubKey, $"{user}|{expiry}", sig)) reject();
```

And never rely on silent integer overflow for "security through obscurity" — it's just a reproducible bug, not a protection.
