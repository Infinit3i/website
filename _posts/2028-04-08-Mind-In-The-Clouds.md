---
layout: post
title: "Mind In The Clouds"
date: 2028-04-08 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, ecdsa, nonce-leak, hidden-number-problem, lattice, lll, cwe-330]
description: "A cloud storage server signs filenames with ECDSA but leaks a slice of each signature nonce in the listing. A partial nonce is a full key compromise: reconstruct the Hidden Number Problem, recover the private key with an LLL lattice, forge a signature, and read the file that was never listed."
---

## Overview

Mind In The Clouds is a Hard HackTheBox Crypto challenge. A "cloud storage" server signs subject filenames with ECDSA (NIST P-256) and only returns a file's contents if you present a valid signature for its name. The catch: listing the files leaks the full signature `(r, s)` **and a slice of the per-signature nonce** for each one. That partial nonce leak lets us recover the private key with a lattice, forge a signature for the one file that isn't listed, and read the flag out of it. This is [CWE-330](https://cwe.mitre.org/data/definitions/330.html) — use of insufficiently random (here, insufficiently *hidden*) values.

## The technique

The filename construction in `source.py` is the whole vulnerability:

```python
def sign(self, fname):
    h = sha1(fname).digest()
    nonce = randint(1, self.n - 1)
    sig = self.privkey.sign(bytes_to_long(h), nonce)
    return {"r": hex(sig.r)[2:], "s": hex(sig.s)[2:], "nonce": hex(nonce)[2:]}

def init_storage():
    i = 0
    for fname in fnames[:-1]:
        data = ecc.sign(fname)
        nfname = fname.decode() + '_' + data['r'] + '_' + data['s'] + '_' + data['nonce'][(14 + i):-14]
        nfnames.append(nfname); i += 2
```

Each listed filename embeds `nonce[(14+i):-14]` — the **middle** of the nonce, hiding the top `14+i` hex digits and the bottom 14 hex digits. Two files are listed (`i = 0` and `i = 2`), so we get two signatures each with a partially-known nonce.

That is fatal, because the ECDSA signing equation is linear:

```
s·k ≡ h + r·d   (mod n)
```

with `d` the private key and `k` the nonce. When most of `k` is known, the remaining unknowns (a few high bits, a few low bits, and `d`) fit into a lattice — the **Hidden Number Problem** — and LLL recovers them.

## Solution

Both nonces are 64 hex digits (256 bits). Model each as `k = TOP·2^hi + known_middle + LOW`, where `LOW < 2^56` (hidden bottom 14 hex), `TOP < 2^(56+4i)` (hidden top), and `known_middle = int(leak,16) << 56`. Two signatures share `d`, so eliminate it to get one congruence in four small unknowns and reduce a lattice.

Create `solve.py`:

```python
import socket, json, sys, time
from hashlib import sha1
from ecdsa.ecdsa import generator_256
from Crypto.Util.number import inverse, bytes_to_long
from random import randint
from fpylll import IntegerMatrix, LLL, BKZ

host, port = sys.argv[1], int(sys.argv[2])
G = generator_256; n = G.order()

s = socket.socket(); s.connect((host, port)); s.settimeout(8)
time.sleep(0.6); s.recv(8192)
s.sendall(json.dumps({"option": "list"}).encode()); time.sleep(1)
listing = s.recv(8192).decode(errors='replace')
files = json.loads(listing[listing.index('{'):listing.rindex('}')+1])['files']

def parse(nf):
    p = nf.split('_'); return '_'.join(p[:-3]), int(p[-3],16), int(p[-2],16), p[-1]
sigs = [parse(f) for f in files]

def parts_of(idx):
    fname, r, sg, leak = sigs[idx]
    lowhex = 14; midhex = len(leak); tophex = 64 - lowhex - midhex
    return dict(r=r, s=sg, c=int(leak,16) << (lowhex*4), hi=(midhex+lowhex)*4,
                h=bytes_to_long(sha1(fname.encode()).digest()), tophex=tophex, lowhex=lowhex)
p1, p2 = parts_of(0), parts_of(1)

A1=(p2['r']*p1['s']*(1<<p1['hi']))%n; B1=(p2['r']*p1['s'])%n
A2=(-(p1['r']*p2['s']*(1<<p2['hi'])))%n; B2=(-(p1['r']*p2['s']))%n
C=(p2['r']*p1['s']*p1['c'] - p2['r']*p1['h'] - p1['r']*p2['s']*p2['c'] + p1['r']*p2['h'])%n
Xa1=1<<(p1['tophex']*4); Xb1=1<<(p1['lowhex']*4); Xa2=1<<(p2['tophex']*4); Xb2=1<<(p2['lowhex']*4)

K=n*n
rows=[[n*K,0,0,0,0,0],[A1*K,n//Xa1,0,0,0,0],[B1*K,0,n//Xb1,0,0,0],
      [A2*K,0,0,n//Xa2,0,0],[B2*K,0,0,0,n//Xb2,0],[C*K,0,0,0,0,n]]
M=IntegerMatrix.from_matrix([[int(x) for x in r] for r in rows]); LLL.reduction(M)
try: BKZ.reduction(M, BKZ.Param(block_size=25))
except Exception: pass

d=None
for i in range(M.nrows):
    row=[M[i][j] for j in range(6)]
    if row[0]!=0 or row[5]==0 or row[5]%n!=0: continue
    sc=row[5]//n
    a1=row[1]//(n//Xa1)//sc; b1=row[2]//(n//Xb1)//sc; a2=row[3]//(n//Xa2)//sc; b2=row[4]//(n//Xb2)//sc
    if not(0<=a1<Xa1 and 0<=b1<Xb1 and 0<=a2<Xa2 and 0<=b2<Xb2):
        a1,b1,a2,b2=-a1,-b1,-a2,-b2
        if not(0<=a1<Xa1 and 0<=b1<Xb1 and 0<=a2<Xa2 and 0<=b2<Xb2): continue
    k1=(a1<<p1['hi'])+b1+p1['c']; k2=(a2<<p2['hi'])+b2+p2['c']
    d1=(inverse(p1['r'],n)*(p1['s']*k1-p1['h']))%n
    d2=(inverse(p2['r'],n)*(p2['s']*k2-p2['h']))%n
    if d1==d2: d=d1; break
assert d is not None
print("[+] private key:", hex(d))

def sign(fname):
    h=bytes_to_long(sha1(fname).digest())
    while True:
        k=randint(1,n-1); P=k*G; r=P.x()%n
        if r==0: continue
        sg=(inverse(k,n)*(h+r*d))%n
        if sg: return hex(r)[2:], hex(sg)[2:]

for fname in [b'subject_danbeer', b'flag', b'flag.txt']:
    r,sg=sign(fname)
    s.sendall(json.dumps({"option":"access","fname":fname.decode(),"r":r,"s":sg}).encode()); time.sleep(1)
    resp=s.recv(16384).decode(errors='replace')
    j=json.loads(resp[resp.index('{'):resp.rindex('}')+1])
    if j.get('response')=='success' and 'data' in j:
        print(f"[+] {fname.decode()} ->", bytes.fromhex(j['data']))
```

```
$ python3 solve.py <host> <port>
[+] private key: 0x...
[+] subject_danbeer -> b'Test subject - Danbeer\n...\nHTB{...}\n'
```

The `d1 == d2` check is the correctness oracle — the right lattice row is the one where both signatures reconstruct the same private key. With `d`, we forge a signature for the unlisted third subject `subject_danbeer` and the server hands back its contents, flag included.

## Why it worked

ECDSA's security depends on the nonce `k` being secret and unpredictable. Because the signing equation is linear in `d` and `k`, even a partial leak of a few nonces turns key recovery into a lattice problem. Here two signatures, each missing only its top and bottom hex digits, left ~236 unknown bits against a 256-bit modulus — comfortably within LLL's reach — so the "private" key was never private.

## Fix / defense

- Never expose any portion of a signature nonce; treat `k` as exactly as secret as the private key.
- Generate nonces from a CSPRNG, or deterministically via RFC 6979 over SHA-256/512, and discard them the moment signing finishes.
- Don't embed cryptographic internals (nonces, intermediate scalars) into identifiers, logs, or debug output.
- Prefer Ed25519, whose nonce is a hash of the key and message and is never handled as a separately exposable value.
