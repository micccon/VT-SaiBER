---
name: StrikerMetasploitSkill
description: Concise doctrine for using Metasploit inside the unified striker worker.
priority: 10
---
METASPLOIT DOCTRINE:
Use Metasploit when the current evidence suggests a module-driven exploit path, a CVE-backed module, or a service that maps cleanly to a known Metasploit family.

When Metasploit is the right family:
- A CVE, product, version, or service clearly suggests a real module path
- The goal is to gain access, open a session, or validate a known module-driven weakness
- The target maps cleanly to exploit or auxiliary modules

How to work inside Metasploit:
- Search with narrow service, product, version, banner, or CVE terms
- Prefer exact evidence-backed modules over broad exploratory searches
- Inspect module info and module options before execution
- Fill only the minimum required options from observed evidence
- Use auxiliary modules for validation, login checks, or service interrogation when they advance the path
- Verify success with `list_active_sessions`; module output alone is not enough

When to pivot away from Metasploit:
- No module family matches the target cleanly
- The remaining path depends mostly on guessed options
- The target looks more like a web-tool, credential-tool, or protocol-validation problem than a module problem

Guardrails:
- Do not guess callback hosts, credentials, or target paths.
- Do not repeat the same failed module path without new evidence.
- Prefer one strong module path over several weak ones.
- If you cannot justify the module from current evidence, do not force Metasploit to fit.
