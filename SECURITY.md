# Security policy

This project is **experimental**. It depends on Internet-Drafts and on Keycloak features marked experimental or
preview, and its reference deployment is a lab, not a hardened service. Do not run it in production.

## Reporting

Please report suspected vulnerabilities through **GitHub Security Advisories** on this repository
(“Security” → “Report a vulnerability”). Do not open a public issue for an unfixed vulnerability, and never
include secrets, tokens, private keys or tenant identifiers in a report.

We aim to acknowledge reports within a few working days. This is a volunteer reference project with no SLA and no
bug bounty.

## What is already known

`docs/SECURITY.md` documents the accepted lab limitations: the private lab CA, script-minted SVIDs instead of
SPIRE, token passthrough, static Cedar entities, same-user secret reachability, dynamic CIMD admission on the
local host, and the management port exposure. Those are design constraints of the reference deployment, not
undisclosed vulnerabilities, but if you find a way to turn one into a concrete exploit, that is a valid report.

## Supported versions

Only the current `main` branch is maintained. There are no security backports to older tags.
