---
layout: post
title: "Confidentiality"
date: 2028-02-08 09:00:00 -0500
categories: [HackTheBox, Challenges, Blockchain]
tags: [hackthebox, challenge, blockchain, solidity, ecdsa, signature-malleability, ecrecover, replay]
---

## Overview

Confidentiality is a Medium Blockchain challenge. An ERC-721 `AccessToken` contract mints only when you present a signature from the contract `owner` — whose private key you don't have. `Setup.isSolved(player)` is true once you hold a token. The winning move is **ECDSA signature malleability**: the owner's already-used signature has a mathematical twin that verifies identically but slips past a bytes-based replay guard.

## The vulnerable code

```solidity
function safeMintWithSignature(bytes memory signature, address to) external returns (uint256) {
    require(_verifySignature(signature), "Not approved");
    require(!_isSignatureUsed(signature), "Signature already used");
    usedSignatures.push(signature);
    return _safeMintInternal(to);
}

function _verifySignature(bytes memory signature) internal view returns (bool) {
    (uint8 v, bytes32 r, bytes32 s) = deconstructSignature(signature);
    return ecrecover(approvalHash, v, r, s) == owner;   // raw ecrecover, no low-s check
}

function _isSignatureUsed(bytes memory sig) internal view returns (bool) {
    // compares keccak256 of the RAW BYTES against previously used signatures
}
```

`Setup`'s constructor already consumed one valid owner signature to mint itself a token, so that signature sits in `usedSignatures`.

## The bug — malleability

secp256k1 signatures are malleable: for any valid `(r, s, v)`, the twin `(r, n - s, v ^ 1)` recovers the **same signer**, where `n` is the curve order. `ecrecover` accepts it, but its bytes differ, so `keccak256(twin) != keccak256(original)` and the replay guard — which compares raw bytes — never catches it. The used owner signature can therefore be replayed as its twin to mint a second token to me.

## Solution

The challenge's TCP menu hands out the RPC URL, my wallet, and the contract addresses. The used signature is readable straight off-chain from the public `usedSignatures(0)` getter (`r || s || v`, 65 bytes, `v = 0x1c`). Flip it and mint:

```bash
RPC=http://<ip>:<rpc>; TARGET=<AccessToken>; PK=<player key>; ME=<player addr>
SIG=$(cast call $TARGET "usedSignatures(uint256)(bytes)" 0 --rpc-url $RPC)
TWIN=$(python3 - "$SIG" <<'PY'
import sys; sig=bytes.fromhex(sys.argv[1][2:]); r,s,v=sig[:32],sig[32:64],sig[64]
n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
s2=(n-int.from_bytes(s,'big')).to_bytes(32,'big'); v2=27 if v==28 else 28
print("0x"+(r+s2+bytes([v2])).hex())
PY
)
cast send $TARGET "safeMintWithSignature(bytes,address)" "$TWIN" "$ME" --private-key $PK --rpc-url $RPC
cast call $TARGET "balanceOf(address)(uint256)" $ME --rpc-url $RPC   # -> 1
```

`balanceOf(me) == 1` → `isSolved` → the menu's "Get flag" returns it.

## Why it worked

The contract conflated "is this a valid owner signature?" with "have I seen these exact bytes before?". Malleability breaks the second question: the same authorization exists in two distinct byte encodings, and only one was recorded as used. A signature is not a nonce.

## Fix / defense

- Enforce canonical `s`: require `s <= n/2` and `v ∈ {27,28}`. Use **OpenZeppelin `ECDSA.recover`**, which does this and reverts on malleable/invalid signatures.
- Don't key the replay guard on signature bytes — sign a message containing a **nonce** (plus recipient, chainid, and contract address via EIP-712) and mark the *nonce/digest* used, not the encoding.
- Always reject `ecrecover` returning the zero address.
