# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting on this repository:
**Security → Report a vulnerability** (<https://github.com/decano5107-boop/sancho/security/advisories/new>). It creates a private thread visible only to the maintainer.

This is maintained by one person, so treat these as targets rather than guarantees: an
acknowledgement within 7 days, and a status update within 30.

Disclosure is coordinated: once a fix is released, the advisory is published with credit to the
reporter, unless they prefer to stay anonymous.

## Scope

This project runs locally as developer tooling. The most relevant risks are:

- A tool call the gate classifies in a lower tier than the documented policy says
  (a bypass of `sancho/tiers.py`)
- Any way for the model to learn or redeem an approval code, or to reuse an approval for a
  different call, thread or time
- A message from anyone other than the owner — another chat, another sender, a forward, a
  quote — reaching Claude Code through the listener
- A secret or personal data in a format the outbound redaction claims to cover (see
  `sancho/outbound.py`) reaching the phone. The redaction is pattern-based and partial: a
  token in a format it does not list is a known limit, not a vulnerability.

## Supported versions

The latest released minor version receives fixes. Older versions do not.
