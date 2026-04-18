# OCP Governance Model — Summary

This is a summary of the OCP Governance Model (OCP-GOV-1.0). The full
governance document is the authoritative reference.

## Inviolable principles

These cannot be amended by any governing body:

1. **No single entity may control the protocol.**
2. **No backdoors.** No master keys, no administrative overrides.
3. **Privacy is enforced, not promised.** The PVL is mandatory.
4. **The protocol is open.** MIT license, permanent and irrevocable.
5. **Governance serves the protocol, not the reverse.**

## Governing bodies

### Technical Steering Committee (TSC)

- **Size:** 7 elected members, 2-year staggered terms
- **Scope:** Protocol specification, schemas, reference implementations
- **Decisions:** Simple majority (4/7) for additions; supermajority (5/7) for breaking changes
- **Diversity:** No more than 2 from the same organization

### Security Working Group (SWG)

- **Size:** 5 appointed members, 2-year terms
- **Scope:** Vulnerability management, crypto audits, incident response
- **Powers:** Emergency patch authority (2 TSC + 1 SWG approval)
- **Constraint:** Cannot introduce backdoors or bypass PVL

### Ethics Advisory Board (EAB)

- **Size:** 5 appointed members, 3-year staggered terms
- **Scope:** Extension ethics review, prohibited use investigation
- **Independence:** At least 2 members from academia or civil society
- **Power:** Suspensive veto on amendments (60-day delay, not permanent block)

### Community Council (CC)

- **Size:** 5 elected members, 1-year terms
- **Scope:** Code of Conduct, documentation, events, elections
- **Elections:** Administered by CC using Single Transferable Vote (STV)

## How decisions are made

| Decision | Authority | Process |
|----------|-----------|---------|
| Spec changes | TSC | RFC → 14-day discussion → vote |
| Security fixes | SWG + TSC | Embargo → fix → coordinated disclosure |
| Ethics concerns | EAB | Investigation → findings → recommendations |
| CoC violations | CC | Investigation → escalation ladder |
| Extensions | TSC (after SWG + EAB review) | Review → vote |

## Elections

- **Electorate:** Anyone who contributed in the last 12 months
- **Method:** Single Transferable Vote (proportional representation)
- **Recall:** 20% petition + majority vote
- **Vacancy:** By-election if >6 months remain; temporary appointment otherwise

## Amendment process

All provisions except the inviolable principles (§1) can be amended with:
- TSC supermajority (5/7), AND
- CC simple majority (3/5), AND
- No EAB ethical objection (suspensive veto, not permanent block)

## Full document

The complete governance model with all procedures, transition plan,
financial governance, and dissolution provisions is at:
