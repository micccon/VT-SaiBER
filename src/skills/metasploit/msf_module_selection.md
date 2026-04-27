---
name: MsfModuleSelectionSkill
description: Keep deterministic module selection anchored to the strongest available service evidence.
applies_to: striker
priority: 20
triggers:
  - module
  - exploit
  - auxiliary
---
MSF MODULE SELECTION:
Use this skill to rank candidate Metasploit paths without drifting away from the discovered surface.

What this skill is for:
Use this skill after search results are available and you need to choose which module is the best next path.

When to use it:
- After `list_exploits` returns candidate modules
- When several modules seem related to the same target
- Before spending time inspecting options or executing a module

How to choose a module:
- Prefer the module that most directly matches the observed service, product, version, platform, or CVE
- Favor specificity over popularity
- Lower confidence when the fit depends on guesses rather than evidence
- Prefer one strong candidate over several weak ones

Core rules:
- Prefer exploit modules when the target fit is direct and the objective is access
- Use auxiliary modules for login checks, service validation, or evidence gathering when they still advance the path
- Lower confidence in generic modules whose names only loosely resemble the target
- If a prior attempt on the same path failed cleanly with no session, pivot unless new evidence has appeared
- Treat CVE-aligned modules as strong candidates only when the CVE actually matches the discovered target

Good patterns:
- Exact product and version match
- Service plus CVE match
- HTTP findings that clearly align to a specific web module family

Bad patterns:
- Picking a module because it has many options
- Choosing a generic module with weak target fit
- Repeating nearly the same failed path with no new evidence

Decision rule:
Choose the module you can justify from evidence in one sentence.
