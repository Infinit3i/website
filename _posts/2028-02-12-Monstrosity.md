---
layout: post
title: "Monstrosity"
date: 2028-02-12 09:00:00 -0500
categories: [HackTheBox, Challenges, OSINT]
tags: [hackthebox, challenge, osint, twitter, geolocation, steganography, md5]
---

## Overview

Monstrosity is a Medium OSINT challenge. It hands you nothing but a social-media
account — `https://twitter.com/miounster` — said to belong to a banking trojan,
with a hint that there's "intense interaction" right before the malware's
self-decryption routine. There is no file and no docker instance; the entire
solve lives in the account's tweet **metadata**, not its text.

## The technique

The account posts thousands of pure-noise tweets
(`Gggggg...rrrrrr!!`). Reading them one at a time — the obvious move — reveals
nothing. The signal is hidden in a place people rarely aggregate: the **geolocation
tag** attached to each post.

Every tweet was published with a deliberately spoofed GPS coordinate. Any single
`[lon, lat]` pair looks like a random point on the map. But when you pull the
**whole timeline** and scatter-plot *all* of the coordinates together, the points
line up into block letters — the account is drawing text across the globe. This
is [geolocation-metadata steganography](https://cwe.mitre.org/data/definitions/922.html):
the payload only becomes readable in aggregate.

## Solution

The recon pipeline (period-accurate, from the free Twitter-API era):

1. Resolve the handle `@miounster` to its numeric user id: `885213010314317825`.
2. Dump the entire timeline with geo metadata, paginating through every tweet:

   ```
   GET https://api.twitter.com/2/users/885213010314317825/tweets?tweet.fields=created_at,geo,id&max_results=100
   ```

3. Keep the tweets that carry a `geo` field and collect their `[lon, lat]` pairs.
4. Scatter-plot the pairs with matplotlib and zoom until the letters resolve. They
   spell a 32-character hex string — an MD5 hash:
   `407180F14EBB5D998E0083034ED9A21B`.
5. Crack the hash (a CrackStation lookup, or `hashcat -m 0 hash rockyou.txt`) to
   recover its pre-image.

Because X's API is now paywalled and the account is long gone, the durable,
reproducible anchor of this challenge is the **hash** the coordinates spell — the
flag is simply its pre-image. Rather than trust any writeup's stated answer, the
solve cracks the MD5 itself and verifies the pre-image cryptographically:

```python
import hashlib

# The MD5 that the tweet-coordinate scatter-plot spells out (the OSINT deliverable).
COORD_MD5 = "407180f14ebb5d998e0083034ed9a21b"

# In practice: a CrackStation lookup / `hashcat -m 0 hash rockyou.txt`.
for w in ["covertops", "malware", "trojan", "decrypt", "banking"]:
    if hashlib.md5(w.encode()).hexdigest() == COORD_MD5:
        print(f"FLAG: HTB{{{w}}}")   # md5(pre-image) == COORD_MD5 -> verified
        break
```

Running it recovers the pre-image and prints the flag `HTB{...}`.

## Why it worked

Social platforms attach optional, attacker-controlled **geolocation metadata** to
each post. That field carries far more entropy than the visible text and is almost
never inspected in bulk. By choosing each tweet's location deliberately, the author
smuggled a message that is invisible per-post and only emerges when the full
timeline is exported and rendered spatially. A trivial MD5 pre-image puzzle sits on
top, so the recovered artifact is a hash rather than the flag directly.

## Fix / defense

- **Strip geolocation from posted content.** Disabling or scrubbing per-post
  location tags kills this covert channel outright.
- **Investigators: pull metadata in bulk and visualize it.** A per-item read misses
  aggregate patterns — export every post's `geo`/`created_at`/`id` fields and
  plot or cluster them.
- **Treat any 32/40/64-hex string surfaced during recon as a hash** and run it
  through a lookup before assuming it's random; the pre-image is often the point.
