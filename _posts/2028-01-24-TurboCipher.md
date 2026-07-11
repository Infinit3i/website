---
layout: post
title: "TurboCipher"
date: 2028-01-24 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, telescoping-sum, lcg, affine, matrix-exponentiation]
---

## Overview

TurboCipher is a Medium **Crypto** challenge. A network oracle wraps its flag in a "fast recursion" cipher and gates access behind a Fibonacci-style OTP. Both the login and the cipher look intimidating, but each collapses to simple linear algebra — the whole thing is an affine map in disguise.

## The technique

Per connection the server picks 512-bit primes `p, b, c` then `m, n, k`, and exposes an oracle:

```python
def lcg(x, m, n, p):        return (m*x + n) % p
def turbocrypt(pt, k, f):   return sum(f(i+1) - f(i) for i in range(k, pt))
# option 1 -> ct_flag = turbocrypt(bytes_to_long(FLAG), k, f) % p
# option 2 -> encrypt a chosen plaintext the same way,  f(x) = lcg(x, m, n, p)
```

The sum `Σ_{i=k}^{pt-1} (f(i+1) - f(i))` **telescopes**: every interior term cancels and it collapses to `f(pt) - f(k)` for *any* `f`. With the affine LCG `f(x) = m*x + n`, that is:

```
ct = f(pt) - f(k) = m*(pt - k) mod p
```

The offset `n` cancels entirely, so the "cipher" is just `m*(pt - k) mod p` — linear in the plaintext.

Login first requires an OTP equal to `turbonacci(nonce)` where `T(n) = b*T(n-1) + c*T(n-2) mod p` (T0=0, T1=1) for a 512-bit `nonce`. That's a linear recurrence — computable in O(log n) by matrix exponentiation of `M = [[b, c], [1, 0]]`, with `T(n) = (Mⁿ)[1][0] mod p`. (The flavor text banning recursion is a nudge: the naive recursion is a stack-overflow DoS.)

## Solution

Log in with the matrix-exp OTP, then recover `m` and `k` from two chosen-plaintext queries and invert for the flag.

Create `solve.py`:

```python
import sys, re
from pwn import remote
from Crypto.Util.number import long_to_bytes, inverse, bytes_to_long
HOST, PORT = sys.argv[1], int(sys.argv[2])

def matmul(A,B,p): return [[(A[0][0]*B[0][0]+A[0][1]*B[1][0])%p,(A[0][0]*B[0][1]+A[0][1]*B[1][1])%p],
                           [(A[1][0]*B[0][0]+A[1][1]*B[1][0])%p,(A[1][0]*B[0][1]+A[1][1]*B[1][1])%p]]
def matpow(M,e,p):
    R=[[1,0],[0,1]]
    while e: 
        if e&1: R=matmul(R,M,p)
        M=matmul(M,M,p); e>>=1
    return R
def turbonacci(n,p,b,c): return 0 if n==0 else matpow([[b,c],[1,0]],n,p)[1][0]%p

io=remote(HOST,PORT)
d=io.recvuntil(b"TurbOTP\n").decode()
p,b,c,nonce=(int(re.search(rf"{k} = (\d+)",d).group(1)) for k in ("p","b","c","nonce"))
io.sendlineafter(b"OTP: ", str(turbonacci(nonce,p,b,c)).encode())
io.recvuntil(b"successful")

def enc(x):
    io.sendlineafter(b"> ", b"2"); io.sendlineafter(b"pt = ", x)
    return int(io.recvuntil(b"\n").decode().split("ct = ")[1])
x1,x2=b"\x02",b"\x05"; c1,c2=enc(x1),enc(x2)
X1,X2=bytes_to_long(x1),bytes_to_long(x2)
m=((c1-c2)*inverse((X1-X2)%p,p))%p            # ct1-ct2 = m*(X1-X2)
k=(X1 - c1*inverse(m,p))%p                    # c1 = m*(X1-k)
io.sendlineafter(b"> ", b"1")
cf=int(io.recvuntil(b"\n").decode().split("ct = ")[1])
print(long_to_bytes((cf*inverse(m,p)+k)%p))   # FLAG = cf/m + k
```

```bash
python3 solve.py <host> <port>     # -> HTB{...}
```

## Why it worked

A telescoping sum `Σ(f(i+1) - f(i))` is algebraic misdirection — it always collapses to `f(hi) - f(lo)`, so no amount of "recursion" or "calculus" framing adds security. The inner affine map is invertible from two chosen plaintexts, and the linear-recurrence login is just a matrix power.

## Fix / defense

Never build a cipher out of an affine map — `m*(pt - k) mod p` leaks its parameters to two chosen-plaintext queries. Use a real authenticated cipher (AES-GCM) and derive OTPs from a proper KDF/HMAC rather than a public linear recurrence.
