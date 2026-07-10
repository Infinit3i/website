---
layout: post
title: "HackTheBox: CubeBreaker"
date: 2028-01-03 09:00:00 -0500
categories: [HackTheBox, Challenges, GamePwn]
tags: [hackthebox, challenge, gamepwn, unity, mono, reversing, ilspycmd, anti-cheat, client-side-secret, cwe-602]
---

CubeBreaker is a Medium GamePwn challenge built on one comfortable lie: **if the player can't reach the cube, they can't get the flag.** It ships a Unity (Mono) game where 10 of the 20 collectible cubes sit *out of bounds*, and only collecting all 20 flips on a hidden flag screen. The intended solve is CheatEngine gymnastics — but the flag image is already sitting inside the game's managed assembly, so a decompile and one XOR pass beats the whole game.

## Overview

The download is a Windows Unity build. Game logic lives in `HackTheBox CubeBreaker_Data/Managed/Assembly-CSharp.dll`. A `CubeCounter` tracks collected cubes; when it reaches 20, `GamePlayer.Update()` enables a `SpriteRenderer` that draws the flag. The catch: that sprite's texture is a base64 PNG baked into the DLL. Nothing about the win is server-checked, so we can carve the flag statically — no game, no CheatEngine, no GUI. This is a textbook [client-side enforcement of a secret that ships in the client](https://cwe.mitre.org/data/definitions/602.html).

## The technique

Unity's **Mono** backend compiles C# game code to a managed `.dll` (unlike the IL2CPP backend, which produces a native `GameAssembly.dll`). Managed assemblies decompile cleanly back to readable C#, so the "reverse engineering" is really just reading the source with the identifiers scrambled.

The build layers three obfuscations, none of which remove the secret:

- **ACTk (Anti-Cheat Toolkit) `ObscuredInt`** — integers are stored XOR-masked in RAM so CheatEngine memory scans can't find them. Irrelevant when you read the code statically.
- **Unicode-junk identifiers** — every method and field is renamed to invisible/homoglyph characters.
- **XOR string obfuscation** — every string literal is a `new byte[128]{key}, new byte[N]{data}` pair, decoded at runtime by `data[i] ^= key[i % 128]` and truncated at a private-use sentinel character.

The win gate is trivial once you find it:

```csharp
// GamePlayer.Update()
if (CubeCounter.Total >= 20)
    spriteRenderer.enabled = true;   // reveal the flag sprite
```

and the "sprite" is the flag, stored as an obfuscated base64 PNG field:

```csharp
byte[] data = Convert.FromBase64String(flagField);  // flagField = Dec(key128, data17792)
texture2D.LoadImage(data);
```

## Solution

Decompile the managed assembly with `ilspycmd` (a dotnet global tool):

```bash
ilspycmd 'HackTheBox CubeBreaker_Data/Managed/Assembly-CSharp.dll' -o decomp/
grep -nE '>= 20|CubeCounter|FromBase64String' decomp/Assembly-CSharp.decompiled.cs
```

That points at the flag field in `GamePlayer`: a 128-byte XOR key followed by a `byte[17792]` obfuscated base64 blob. Lift the same decoder the game uses and carve the PNG out directly.

Create `solve.py`:

```python
import re, base64
src = open('decomp/Assembly-CSharp.decompiled.cs', encoding='utf-8').read()
i = src.index('private string Цmƚʧ = ')                       # flag-image field in GamePlayer
m = re.search(r'new byte\[128\]\s*\{([^}]*)\},\s*new byte\[17792\]\s*\{([^}]*)\}', src[i:i+120000])
key  = [int(x) for x in re.findall(r'\d+', m.group(1))]        # 128-byte repeating XOR key
data = [int(x) for x in re.findall(r'\d+', m.group(2))]        # obfuscated base64 blob
dec  = bytes((data[j] ^ key[j % 128]) & 0xff for j in range(len(data))).decode('utf-8', 'replace')
b64  = re.match(r'[A-Za-z0-9+/=]+', dec).group(0)              # cut at the U+E44F sentinel
open('flag.png', 'wb').write(base64.b64decode(b64[:len(b64) - len(b64) % 4]))
```

```bash
python3 solve.py && file flag.png
```

`flag.png` is a 1280×720 image with the flag rendered in green monospace text — `HTB{...}`.

## Why it worked

The developer treated two things as security that aren't: the player being unable to *reach* the out-of-bounds cubes, and the flag string being *scrambled*. But the flag PNG is shipped inside the client, and the only thing standing between an analyst and it is a client-side `enabled = true`. Obfuscation (ACTk, junk identifiers, XOR strings) raises the time cost of finding the secret but never removes it from the binary — anything the client can assemble at runtime, an analyst can assemble statically.

## Fix / defense

- **Never ship the flag/secret in the client.** Gate the reward server-side: the game reports a validated proof-of-solve to a backend, which returns the flag only then. The client is not a trust boundary.
- Client-side anti-cheat (ACTk `ObscuredInt`, XOR strings, renamed identifiers) is a speed bump against cheating, not a confidentiality control. Assume the entire managed assembly is readable.
