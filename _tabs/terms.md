---
title: Terms of Service
icon: fas fa-file-contract
order: 11
group: legal
group_label: "Legal"
group_icon: "fas fa-scale-balanced"
---

**Business name:** Matthew Iverson, sole proprietor, doing business as **Infinit3i**
**Location:** Spring Hill, Florida, United States — client work is performed remotely
**Contact:** <matthew@infinit3i.com>

*Last updated: September 2, 2026*

These terms govern the security testing services purchased from Infinit3i. They
apply alongside the individual written contract signed for each engagement. Where
the signed contract and these terms conflict, the signed contract controls.

## Services Offered

Infinit3i offers one professional service, delivered electronically:

**Bug bounty work on websites** — finding and reporting security vulnerabilities
in websites and web applications that the client owns or is authorized to have
tested. The service is described in full on the
[Services]({{ '/services/' | relative_url }}) page.

The deliverable is a written technical report — each valid finding with
reproduction steps, a CVSS-mapped severity rating, and remediation guidance —
plus supporting consultation, delivered electronically.

**No physical goods are sold or shipped. No software, tooling, or exploit code
is sold.**

## Ordering and Payment

1. **Scoping call.** We define which websites, applications, and endpoints are in
   scope, and what is explicitly out of scope.
2. **Written contract and authorization to test**, signed by both parties before
   any work begins. The contract includes the per-severity rate card.
3. **Testing window**, with findings reported as they are confirmed and immediate
   disclosure of critical issues.
4. **Delivery** of the written report by electronic means.
5. **Triage**, then a single invoice for accepted findings.
6. **Remediation support** and optional retest, if included in scope.

### Fees

Fees are charged **per valid finding**, at the per-severity rate card in the
signed contract. There is no upfront fee, no hourly rate, no retainer, no
subscription, and no recurring charge. If no valid findings are identified within
the agreed scope, no fee is due.

A finding is valid, and therefore billable, only where it is reproducible on an
in-scope target, has a real security impact rated against CVSS, is not a
duplicate of an issue the client already knew of or had already been reported,
and is not an issue the client has documented as an accepted risk. Duplicates,
out-of-scope findings, informational or hardening notes, and findings the client
demonstrates are not reproducible are not billed.

The client has **10 business days** from delivery of the final report to accept
each finding or state in writing why it is not valid. Findings not disputed
within that window are treated as accepted. Disagreements about severity are
resolved against the CVSS vector recorded in the report before the invoice is
issued.

One invoice is then issued covering accepted findings only, payable in United
States dollars per the terms in the signed contract. Card payments are processed
by Stripe; Infinit3i does not store your card details.

Card statements will show a charge from **INFINIT3I**.

## Authorization Requirement

No testing is performed without written permission from the owner of the target
systems. You warrant that you own, or are lawfully authorized to permit testing
of, every system you place in scope. If that authorization is withdrawn or proves
invalid, work stops immediately and fees for findings already accepted remain
payable.

## Client Responsibilities

- Provide accurate scope information, access credentials, and technical contacts.
- Maintain backups of any system in scope before testing begins.
- Respond to critical findings and scheduling requests within a reasonable time.

Delays caused by missing access or unavailable contacts may extend the testing
window. They do not create an additional charge — fees are per valid finding
only.

## Confidentiality

Engagement findings, client source code, and client data are treated as
confidential. They are not published, resold, or shared with third parties
without written client consent. Reports are retained only as long as needed for
the engagement and any agreed retest period, and are deleted on written request
unless a legal obligation requires retention.

Nothing published on this website derives from client engagements. Blog posts,
malware notes, and CTF write-ups on this site are based on public research,
publicly available samples, and intentionally vulnerable practice targets.

## Deliverables and Intellectual Property

On full payment, the client owns the report delivered for their engagement.
Infinit3i retains ownership of its own methodologies, tooling, checklists, and
templates, and may reuse them on other engagements.

## Limitations

Security testing is time-boxed and scope-bound. A report describes what was found
within the agreed scope during the agreed window. It is not a guarantee that a
system is free of vulnerabilities, and it is not a certification, legal advice,
or a regulatory compliance opinion. Infinit3i does not warrant that testing will
identify every weakness in a system.

To the extent permitted by law, total liability arising from an engagement is
limited to the fees paid for that engagement.

## Prohibited Uses and Legal Restrictions

Services are sold for lawful, authorized security testing only. Infinit3i does
not:

- test systems the client does not own or is not authorized to test;
- sell, license, or supply offensive tooling, exploit code, or malware to clients
  or to the public;
- provide services intended to gain unauthorized access to third-party systems,
  to conduct surveillance of individuals, or to evade law enforcement.

Engagements that appear to be for any of these purposes are declined, and work in
progress is terminated. Fees for findings already accepted remain payable and are
not refunded.

### Export and Sanctions Restrictions

Infinit3i is based in the United States and complies with U.S. export control and
economic sanctions law. Services are not sold to, and reports are not delivered
to, persons or entities in comprehensively sanctioned jurisdictions, or to
parties on the U.S. Treasury Specially Designated Nationals list or other
restricted-party lists. Clients must not re-export or transfer deliverables in
violation of those laws.

## Refunds, Cancellation, and Disputes

See the [Refund, Cancellation & Dispute Policy]({{ '/refunds/' | relative_url }}).

## Promotions

No discounts, coupons, or promotional offers are currently advertised. If one is
offered in future, its full terms — eligibility, value, and expiry — will be
stated with the offer and on this page.

## Changes to These Terms

These terms may be updated. The version in force for an engagement is the version
published on the date the contract for that engagement is signed. Material
changes are noted by updating the date at the top of this page.

## Governing Law

These terms are governed by the laws of the State of Florida, United States,
without regard to its conflict-of-law rules.

## Questions

Email <matthew@infinit3i.com>. See the
[Contact]({{ '/contact/' | relative_url }}) page for response times.
