

- https://any.run
- https://threatfox.abuse.ch/browse/
- https://malpedia.caad.fkie.fraunhofer.de/

* detonate

- https://bazaar.abuse.ch/browse/



* gather hashes or files
- https://any.run

### Static

* `get-filehash -a sha256 <FILE>`
* `md5deep <FILE>`
* `floss <FILE> > Filename.strings`
* `grep` on long strings
* pestr: `urls`, `file paths`, `cred`, `cmds`, `errors`
* Dependency Walker
* Capa
* PEStudio
* DetectItEasy
* PEiD
* `upx -d <FILE>`
* PEview
* PEBrowse Professional
* HxD
* `olevba.py`
* `python.exe .\onedump.py <FILE>`
* `python.exe .\onedump.py -s 1 -d -o <NAME>.vbs <FILE>`
* IDA Free
* Ghidra
* Identify `main()` and `entry`
* Analyze `imports` and `exports`
* Inspect `jmp`, `jne`, `cmp`
* Decode hardcoded `cmp` values

---

### Dynamic

* Check if malware has a dynamic base
* x64dbg
* DNSpy
* WinDbg
* `bp kernel32!VirtualAlloc`
* `bp kernel32!VirtualAllocStub`
* Set breakpoints and observe registers
* Regshot
* ProcMon
* System Informer
* Autoruns
* FakeNet-NG
* Wireshark
* Suricata 
