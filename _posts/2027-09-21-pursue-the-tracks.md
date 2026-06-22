---
title: "Pursue the Tracks"
date: 2027-09-21 09:00:00 -0500
categories: [HackTheBox, Challenges, Forensics]
tags: [hackthebox, challenge, forensics, ntfs, mft, timeline-analysis, dfir, file-recovery]
description: "A Very Easy Forensics challenge that hands you nothing but a raw NTFS $MFT. A Q&A service asks nine questions — deleted file, copied file, hidden count, timeline order — and every answer lives in the Master File Table's record metadata. Parse it from scratch in Python and stream the answers back."
---

## Overview

`Pursue the Tracks` is a Very Easy HackTheBox **Forensics** challenge. The whole artifact is a single `z.mft` — a raw **NTFS Master File Table** (256 records of 1024 bytes), with no disk image, no files-on-disk, nothing else. A docker service asks **nine** forensic questions about the files that table once indexed; answer all nine and it prints the flag. The point of the challenge: the `$MFT` alone is a complete, queryable timeline of every file that ever existed on the volume — including ones that were deleted, hidden, or copied.

## The technique

NTFS keeps one 1024-byte `$MFT` record per file/directory. Each record starts with the signature `FILE` and carries typed attributes. Two of them hold everything the questions need:

- **`$STANDARD_INFORMATION`** (type `0x10`) — the four **MACB** timestamps (Created, Modified, MFT-changed, Accessed) as Windows `FILETIME` (100 ns ticks since 1601-01-01), plus the DOS attribute flags (HIDDEN = `0x02`, SYSTEM = `0x04`).
- **`$FILE_NAME`** (type `0x30`) — the UTF-16LE filename and the real file size.

The record header adds two more facts: a flags word at offset `0x16` (`bit0` = in-use, `bit1` = directory) and the record's own number (its index into the table). That's enough to recover everything: deleting a file only flips the in-use bit — name, size, and all four timestamps survive in the record until it's reused. This is the heart of NTFS timeline forensics, a form of analysing residual [file-system metadata](https://cwe.mitre.org/data/definitions/212.html) that an actor assumed was gone.

Each of the nine questions maps to one rule:

| Question | MFT rule | Answer |
|---|---|---|
| Two years the files relate to | directory entries named like years | `2023,2024` |
| First *document* written | min `$SI` Created over document files (skip system `WPSettings.dat`) | `Final_Annual_Report.xlsx` |
| Which file was **deleted** | record-header flags `bit0 == 0` | `Marketing_Plan.xlsx` |
| How many set **Hidden** | `$SI` DOS flags `& 0x02`, real files only | `1` |
| Important **TXT** file | the only `.txt` document | `credentials.txt` |
| File that was **copied** (new name) | `$SI` Modified `<` Created | `Financial_Statement_draft.xlsx` |
| File **modified after creation** | largest `Modified − Created` gap | `Project_Proposal.pdf` |
| Name at **record 45** | `recs[45].name` | `Annual_Report.xlsx` |
| Size at **record 40** | `recs[40].size` | `57344` |

Two timestamp tricks are the crux. A **copied** file shows `$SI Modified < Created` — Windows stamps the new copy's *Created* to "now" but keeps the original content's *Modified* time, so a record where content predates its own creation is a tell-tale copy. And the **"modified after creation"** file has to be picked by the *largest* `Modified − Created` gap: during bulk file creation, dozens of records differ by microseconds (just sequential-write noise), but the one real edit stands out by ~63 seconds (19:32:27 → 19:33:30).

## Solution

`solve.py` parses `z.mft` from scratch (no third-party tools — though `analyzeMFT.py` and Eric Zimmerman's MFTECmd + Timeline Explorer do the same), derives all nine answers, and streams them to the Q&A socket. The flag is whatever the service prints after the last correct answer — never hard-coded.

`solve.py`:

```python
#!/usr/bin/env python3
"""
HTB Forensics — "Pursue the Tracks": parse the supplied NTFS $MFT,
derive every answer the docker asks from record metadata, stream them back.
Usage: python3 solve.py <host> <port>   (MFT path = files/z.mft)
"""
import struct, datetime, socket, time, sys

MFT = "files/z.mft"
REC = 1024
HIDDEN = 0x02  # FILE_ATTRIBUTE_HIDDEN in $STANDARD_INFORMATION DOS flags


def ft(v):
    "Windows FILETIME (100ns since 1601) -> datetime, or None."
    return None if v == 0 else datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v // 10)


def parse_mft(path):
    d = open(path, "rb").read()
    recs = {}
    for off in range(0, len(d), REC):
        rec = d[off:off + REC]
        if rec[:4] != b"FILE":
            continue
        rno = off // REC
        rflags, = struct.unpack_from("<H", rec, 0x16)      # 0x01=in-use, 0x02=dir
        attr_off, = struct.unpack_from("<H", rec, 0x14)
        p = attr_off
        name = None; si = None; size = None; siflags = None
        while p < REC - 8:
            atype, = struct.unpack_from("<I", rec, p)
            if atype == 0xFFFFFFFF:
                break
            alen, = struct.unpack_from("<I", rec, p + 4)
            if alen == 0:
                break
            nonres = rec[p + 8]
            contoff, = struct.unpack_from("<H", rec, p + 0x14)
            if atype == 0x10:                               # $STANDARD_INFORMATION
                base = p + contoff
                si = [ft(struct.unpack_from("<Q", rec, base + i * 8)[0]) for i in range(4)]  # C,M,MFT,A
                siflags, = struct.unpack_from("<I", rec, base + 0x20)
            elif atype == 0x30:                             # $FILE_NAME
                base = p + contoff
                size, = struct.unpack_from("<Q", rec, base + 0x30)   # real size
                nlen = rec[base + 0x40]
                name = rec[base + 0x42:base + 0x42 + nlen * 2].decode("utf-16le", "replace")
            elif atype == 0x80 and nonres:                  # $DATA non-resident real size
                size, = struct.unpack_from("<Q", rec, p + 0x30)
            p += alen
        recs[rno] = dict(rno=rno, name=name, dir=bool(rflags & 2),
                         inuse=bool(rflags & 1), si=si, siflags=siflags, size=size)
    return recs


def derive(recs):
    DOC_EXT = (".xlsx", ".xls", ".pdf", ".txt", ".docx", ".doc", ".csv", ".pptx")
    docs = [r for r in recs.values()
            if r["name"] and not r["name"].startswith("$") and r["name"] != "."]
    files = [r for r in docs if not r["dir"]]
    document_files = [r for r in files if r["name"].lower().endswith(DOC_EXT)]

    years = sorted({r["name"] for r in docs if r["dir"] and r["name"].isdigit()})
    first = min((r for r in document_files if r["si"]), key=lambda r: r["si"][0])["name"]
    deleted = next(r["name"] for r in recs.values()
                   if not r["inuse"] and r["name"] and not r["name"].startswith("$"))
    hidden = [r for r in docs if r["siflags"] and (r["siflags"] & HIDDEN) and not r["dir"]]
    copied = next(r["name"] for r in files if r["si"] and r["si"][1] < r["si"][0])
    txt = next(r["name"] for r in files if r["name"].lower().endswith(".txt"))
    mod = max((r for r in files if r["si"] and r["si"][1] > r["si"][0]),
              key=lambda r: r["si"][1] - r["si"][0])["name"]

    return [",".join(years), first, deleted, str(len(hidden)), txt,
            copied, mod, recs[45]["name"], str(recs[40]["size"])]


def solve(host, port, answers):
    s = socket.create_connection((host, int(port)), timeout=15); s.settimeout(4)

    def rd():
        out = b""
        try:
            while True:
                b = s.recv(4096)
                if not b:
                    break
                out += b
        except socket.timeout:
            pass
        return out.decode("utf-8", "replace")

    print(rd())
    last = ""
    for a in answers:
        s.sendall(a.encode() + b"\n"); time.sleep(0.8); last = rd()
        print(last)
    s.close()
    return last


if __name__ == "__main__":
    recs = parse_mft(MFT)
    answers = derive(recs)
    print("[*] derived answers:", answers)
    if len(sys.argv) == 3:
        solve(sys.argv[1], sys.argv[2], answers)
```

Run it against the spawned instance:

```bash
python3 solve.py <docker-ip> <docker-port>
```

The service walks through all nine questions and finishes with:

```
[+] Here is the flag: HTB{...}
```

Flag value redacted.

## Why it worked

NTFS treats the `$MFT` as the authoritative index of the volume, and it is far more durable than the files themselves. A "deleted" file is only a record with its in-use bit cleared — the filename, size, and complete MACB timeline remain until that record slot is overwritten. Worse for anyone trying to hide their tracks, the timestamps *leak intent*: a copy reverses the normal `Created ≤ Modified` ordering, and a [timestomp](https://cwe.mitre.org/data/definitions/212.html) shows up as a divergence between the `$SI` and `$FN` timestamp sets. Everything the challenge asked was already recorded in metadata the user believed was gone.

## Fix / defense

For a defender, this is a feature, not a bug — `$MFT` parsing is a first-class DFIR technique precisely because it recovers deleted, hidden, and copied files long after the fact. For anyone trying to actually destroy evidence, the lesson is that unlinking a file does almost nothing: only securely wiping the underlying clusters **and** the MFT record (or the whole volume) removes the trail. On the detection side, watch `$SI`-vs-`$FN` timestamp divergence and `Modified < Created` ordering as high-signal indicators of tampering and exfil staging.
