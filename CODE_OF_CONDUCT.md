# Code of Conduct

## Our pledge

We pledge to make participation in the OCP community a harassment-free
experience for everyone, regardless of age, body size, disability,
ethnicity, sex characteristics, gender identity and expression, level
of experience, education, socio-economic status, nationality, personal
appearance, race, religion, or sexual identity and orientation.

## Our standards

**Positive behaviors include:**

- Using welcoming and inclusive language
- Respecting differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community and the protocol
- Showing empathy towards other community members

**Unacceptable behaviors include:**

- The use of sexualized language or imagery and unwelcome sexual
  attention or advances
- Trolling, insulting or derogatory comments, and personal or
  political attacks
- Public or private harassment
- Publishing others' private information, such as a physical or
  electronic address, without explicit permission
- Other conduct which could reasonably be considered inappropriate
  in a professional setting

## Enforcement

The Community Council (CC) is responsible for Code of Conduct enforcement.
The CC applies the following escalation ladder:

| Level | Violation | Response |
|-------|-----------|----------|
| 1 | Minor, first offense | Private warning |
| 2 | Repeated or moderate | Public warning; temporary interaction restrictions |
| 3 | Serious or persistent | Temporary ban (30–180 days) |
| 4 | Severe or threatening | Permanent ban; law enforcement referral if applicable |

## Reporting

Instances of unacceptable behavior may be reported to:

**conduct@ocp.foundation**

All complaints will be reviewed and investigated. The CC is obligated
to maintain confidentiality with regard to the reporter.

## Appeals

Any sanctioned individual may appeal to the full CC within 14 days.
The CC votes with a 3/5 majority required to overturn. If the
individual believes the CC is biased, they may appeal to the TSC
chair, who may appoint an independent mediator.

## Scope

This Code of Conduct applies within all community spaces (GitHub,
forums, chat, events) and in public spaces when an individual is
representing OCP.

## Attribution

This Code of Conduct is adapted from the
[Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).


═══ FILE: SECURITY.md ═══

# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Active    |

## Reporting a vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities to:

**security@ocp.foundation**

Include:

- Description of the vulnerability
- Steps to reproduce
- Affected components (spec, SDK, node, schemas, custodian)
- Potential impact assessment
- Suggested fix (if any)

## Response timeline

| Severity | Acknowledgement | Initial assessment | Fix target |
|----------|----------------|-------------------|------------|
| SEV-1 (Critical) | 4 hours | 24 hours | 24 hours |
| SEV-2 (High) | 24 hours | 72 hours | 7 days |
| SEV-3 (Medium) | 48 hours | 7 days | 30 days |
| SEV-4 (Low) | 7 days | 14 days | Next release |

## Severity definitions

- **SEV-1 (Critical):** Active exploitation or total compromise. Key
  compromise, PVL bypass, signature forgery.
- **SEV-2 (High):** Exploitable vulnerability, no active exploitation.
  Authentication bypass, replay attack, Sybil at scale.
- **SEV-3 (Medium):** Vulnerability requiring specific conditions. Timing
  side channels, information disclosure under edge cases.
- **SEV-4 (Low):** Theoretical vulnerability, defense in depth intact.
  Missing rate limit, verbose error messages.

## Scope

The following are in scope:

- Protocol specification weaknesses
- Reference SDK vulnerabilities (Python, JavaScript, Go)
- Reference node security issues (transport, registry, custodian)
- Cryptographic implementation flaws
- Privacy Validation Layer bypasses
- Key recovery mechanism weaknesses
- Smart contract vulnerabilities (blockchain extension)

## Disclosure policy

We follow coordinated disclosure:

1. Reporter notifies us privately.
2. We acknowledge within the timeline above.
3. We develop a fix on a private branch.
4. We agree on a disclosure date (default: 90 days from report).
5. Fix is released; advisory is published.
6. CVE is requested from MITRE.
7. Reporter is credited (unless they request anonymity).

If active exploitation is detected, the timeline may be shortened.

## Security Working Group

The SWG manages all security reports and coordinates responses.
The SWG has emergency powers to merge patches with expedited
approval (2 TSC + 1 SWG) subject to ratification at the next
TSC meeting.

## Bug bounty

We plan to establish a bug bounty program. Details will be published
at https://ocp.foundation/security/bounty when the program launches.

## What we will never do

Per OCP's inviolable governance principles:

- We will **never** introduce a backdoor or master key.
- We will **never** weaken the Privacy Validation Layer.
- We will **never** create privileged agent access.

These constraints apply regardless of pressure from any entity,
including governments and regulators. See OCP-GOV-1.0 §1.
