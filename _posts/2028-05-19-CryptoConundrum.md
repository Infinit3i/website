---
layout: post
title: "CryptoConundrum"
date: 2028-05-19 09:00:00 -0500
categories: [HackTheBox, Challenges, Crypto]
tags: [hackthebox, challenge, crypto, aes-ecb, substitution-cipher, frequency-analysis, union-find, simulated-annealing]
description: "AES-ECB with a fixed key, applied to every sliding-window bigram, collapses into a substitution cipher — recovered key-free by threading the overlaps into a graph walk and frequency-labeling the nodes."
---

## Overview

CryptoConundrum is a **Medium** HackTheBox **Crypto** challenge. You get a Python source file, a list of AES ciphertext blocks, and an English bigram-frequency table. The twist: AES is a red herring — the way it is used turns the whole thing into a plain [substitution cipher](https://cwe.mitre.org/data/definitions/327.html), and the flag is recovered without ever touching the key.

## The technique

The cipher builds **one** AES-ECB instance with a fixed random key and a fixed 14-byte salt, then encrypts the secret `MESSAGE` (all uppercase A–Z, starts with `A`) using a **sliding window of width 2**:

```python
self.salt = urandom(14)
self.cipher = AES.new(urandom(16), AES.MODE_ECB)
def encrypt(self, message):
    return [ self.cipher.encrypt(message[i:i+2].encode() + self.salt)
             for i in range(len(message) - 1) ]
```

Each block is `AES_ECB( message[i:i+2] + salt )`. The salt pads the 2-letter bigram out to a full 16-byte block, so every block is a deterministic encryption of a **bigram**. Two facts break it:

- **Same bigram ⇒ same ciphertext.** ECB is deterministic and the key/salt never change, so 5050 blocks collapse to 383 distinct ciphertexts = 383 distinct bigrams. It is a monoalphabetic substitution over bigrams; the AES key is irrelevant.
- **Consecutive blocks overlap by one letter.** Block *i* = `msg[i:i+2]`, block *i+1* = `msg[i+1:i+3]`, so the 2nd letter of block *i* equals the 1st letter of block *i+1*.

The overlap turns the ciphertext stream into a **walk on a 26-node letter graph** where each distinct ciphertext is an edge (a bigram). Recover the plaintext by labeling the nodes.

## Solution

1. **Union-find the positions.** Each plaintext position holds a letter. Whenever two blocks share a ciphertext at positions *i* and *j*, they are the same bigram, so `union(i,j)` and `union(i+1,j+1)`. This merges positions into letter-classes.
2. **Label the classes A–Z** to maximize English bigram log-likelihood (from `frequencies.txt`), under two constraints: anchor `class(position 0) = 'A'` (because `MESSAGE.startswith('A')`), and a **hard collision penalty** — every distinct ciphertext must map to a *distinct* bigram, or the labels collapse onto `TH`/`HE`/… Simulated annealing gets ~95% (recognizably *Alice in Wonderland*); a coordinate-ascent + pairwise-swap polish, tie-broken by a common-word bonus, locks onto exact English.

Create `solve.py`:

```python
import math, random, re
from collections import defaultdict, Counter
random.seed(1337)

blocks=[l.strip() for l in open("output.txt") if l.strip()]
L=len(blocks)+1
parent=list(range(L))
def find(x):
    r=x
    while parent[r]!=r: r=parent[r]
    while parent[x]!=r: parent[x],x=r,parent[x]
    return r
def union(a,b):
    ra,rb=find(a),find(b)
    if ra!=rb: parent[ra]=rb
groups=defaultdict(list)
for i,b in enumerate(blocks): groups[b].append(i)
for ct,poss in groups.items():
    for p in poss[1:]:
        union(poss[0],p); union(poss[0]+1,p+1)
classes=sorted(set(find(i) for i in range(L)))
cmap={c:idx for idx,c in enumerate(classes)}
seq=[cmap[find(i)] for i in range(L)]
NC=len(classes)

raw={m.group(1):float(m.group(2)) for m in
     re.finditer(r'"([A-Z]{2})"\s*:\s*([0-9.]+)', open("frequencies.txt").read())}
A=[chr(ord('A')+i) for i in range(26)]
logf={(a,b):math.log(raw.get(a+b,0.0)+1e-7) for a in A for b in A}

trans=Counter((seq[i],seq[i+1]) for i in range(L-1))
edges=[(a,b,w) for (a,b),w in trans.items()]
inc=defaultdict(list)
for ei,(a,b,w) in enumerate(edges):
    inc[a].append(ei)
    if b!=a: inc[b].append(ei)
start=seq[0]; PEN=50.0

def collisions(letter):
    bc=Counter(letter[a]+letter[b] for a,b,w in edges)
    return sum(c-1 for c in bc.values() if c>1)
def full_freq(letter):
    return sum(w*logf[(letter[a],letter[b])] for a,b,w in edges)

# --- simulated annealing with collision penalty ---
best=None
for _ in range(80):
    letter=[random.choice(A) for _ in range(NC)]; letter[start]='A'
    T=6.0
    for _ in range(9000):
        c=random.randrange(NC)
        if c==start: T*=0.9995; continue
        old,new=letter[c],random.choice(A)
        if new==old: T*=0.9995; continue
        before=sum(w*logf[(letter[a],letter[b])] for ei in inc[c] for a,b,w in [edges[ei]])
        letter[c]=new
        after=sum(w*logf[(letter[a],letter[b])] for ei in inc[c] for a,b,w in [edges[ei]])
        if not (after>=before or random.random()<math.exp((after-before)/max(T,1e-3))):
            letter[c]=old
        T*=0.9995
    o=full_freq(letter)-PEN*collisions(letter)
    if best is None or o>best[0]: best=(o,letter[:])
letter=best[1]

# --- coordinate-ascent + swap polish, common-word tie-break ---
COMMON="THE AND THAT WAS HER WITH FOR ALICE SISTER BEGINNING VERY TIRED SITTING BANK BOOK".split()
def wordscore(letter):
    txt=''.join(letter[c] for c in seq); return sum(txt.count(w)*len(w) for w in COMMON)
def objective(letter):
    return full_freq(letter)-PEN*collisions(letter)+0.5*wordscore(letter)
cur=objective(letter); improved=True
while improved:
    improved=False
    for c in range(NC):
        if c==start: continue
        old,best_l,best_o=letter[c],letter[c],cur
        for cand in A:
            letter[c]=cand; o=objective(letter)
            if o>best_o: best_o,best_l=o,cand
        letter[c]=best_l
        if best_l!=old: cur=best_o; improved=True
    for i in range(NC):
        for j in range(i+1,NC):
            letter[i],letter[j]=letter[j],letter[i]
            o=objective(letter)
            if o>cur and letter[start]=='A': cur=o; improved=True
            else: letter[i],letter[j]=letter[j],letter[i]

pt=''.join(letter[c] for c in seq)
i=pt.find("HTB")
print("HTB{"+pt[i+3:].rstrip("X")[:20]+"...}")   # flag is the planted uppercase run at the tail
print(pt[:120])
```

Running it decrypts the 5051-character plaintext — the opening of *Alice's Adventures in Wonderland* — ending with the planted phrase `...HTBWITHDIGRAPHSITISHARDER`. Because the message alphabet is A–Z only, the flag is that uppercase run wrapped in the HTB format:

```
HTB{...}
```

Flag value redacted.

## Why it worked

ECB encrypts each block independently and deterministically. Reusing one key across the whole message and padding every 2-letter window with the same salt made `bigram → ciphertext` a fixed lookup table — exactly a substitution cipher, just with 16-byte "symbols" instead of single letters. The overlapping windows then hand you the graph structure for free, so no key and no oracle are needed.

## Fix / defense

- **Never use ECB.** ECB leaks equality of plaintext blocks — here, of every bigram. Use an authenticated mode with a fresh random nonce per message (AES-GCM), so identical plaintext never produces identical ciphertext.
- A constant key plus a constant salt add no per-message entropy; the "salt" here is decorative. If you must encrypt short tokens, randomize the nonce and authenticate the ciphertext.
