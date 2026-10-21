# Security policy

CleiMesh is a security tool, so a flaw in it can be worse than a flaw in
the code it protects. Thank you for reporting one.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting instead: on
the repository page, go to **Security → Report a vulnerability**. Only the
maintainers see the report.

Please include what you can of:

- the component (token verification, sandbox grants, sandbox, receipts, MCP
  server, P2P) and the commit or version;
- what an attacker gains (e.g. a subagent reaching a directory its token
  does not grant, a forged or widened token being accepted, a receipt edit
  that `audit verify` misses, a call that runs without a decision receipt);
- steps or a test that reproduces it.

You can expect an acknowledgement within 7 days and a fix or a plan within
30. We will credit you in the release notes unless you prefer otherwise.

## Scope

In scope: anything that lets a call do more than its token grants, lets an
invalid token or proof be accepted, lets a tool escape the WASM sandbox's
grants, or lets a receipt log be altered without `cleimesh audit verify`
reporting it.

Known limits, not vulnerabilities by themselves, are listed in the
[threat model](docs/threat-model.md): among them, tools outside the sandbox
are not isolated, an allowed action can still be the wrong action, taint is
kept per node, and a log rolled back together with its head is only caught
against a head kept elsewhere.

## Supported versions

The project is alpha: only the latest commit on the default branch is
supported.
