---
name: MsfSearchSkill
description: Generate narrow, evidence-backed search terms for deterministic Metasploit module lookup.
applies_to: striker
priority: 10
triggers:
  - search
  - service
  - cve
  - metasploit
---
MSF SEARCH:
Use this skill to keep `list_exploits` focused on observed target evidence.

What this skill is for:
Use this skill when you need to search Metasploit for modules that match the current target, service, product, version, banner, web path, or CVE.

When to use it:
- After identifying a candidate service or product worth exploiting
- When OSINT, research, or web findings suggest a likely module family
- Before choosing a Metasploit module to inspect or run

How to choose search terms:
- Start with the strongest observed signal first: CVE, exact product, exact version, or specific service banner
- Prefer narrow terms that are likely to map to a real module family
- Reuse the best evidence already present in state before widening the search
- Widen only one step at a time if the first search is too specific

Core rules:
- Prefer service, product, version, banner, and CVE terms over broad category searches
- Search with exact strings like `openssh 8.2`, `apache 2.4.49`, or `cve-2021-41773` before trying general terms
- Use web path clues only when they are distinctive enough to help narrow the module family
- Treat search as a precision step, not brainstorming

Good patterns:
- `cve-2021-41773`
- `openssh 8.2`
- `apache 2.4.49`
- `tomcat manager`

Bad patterns:
- `linux`
- `http`
- `web exploit`
- several unrelated terms in one search

Decision rule:
If the term does not come from the current evidence, do not search it first.
