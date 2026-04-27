---
name: StrikerKaliSkill
description: Concise doctrine for using Kali tools inside the unified striker worker.
priority: 20
---
KALI DOCTRINE:
Use Kali when the evidence favors a tool-driven path such as web exploitation, credential validation, SMB enumeration, WordPress analysis, or precise command-based validation.

When Kali is the right family:
- The path is better served by a focused tool than by a Metasploit module
- The target is a web surface, credential workflow, SMB path, WordPress surface, or protocol-validation task
- The next step is validation or exploitation through one bounded tool action

How to work inside Kali:
- Choose one primary tool for the current hypothesis
- Keep commands and tool arguments tightly scoped to observed hosts, paths, forms, services, or interfaces
- Use `sqlmap` for strong SQL injection hypotheses
- Use `hydra` only when a credential-facing service is exposed and the attempt is evidence-backed
- Use `enum4linux` for SMB enumeration paths
- Use `wpscan` for WordPress-specific paths
- Use raw command execution only for precise validation that does not fit a dedicated tool

When to pivot away from Kali:
- The path now clearly maps to a real Metasploit module family
- The current Kali idea failed cleanly and no new evidence supports another try
- The remaining action would require broad shell exploration rather than a bounded validation step

Guardrails:
- Do not mix several weak Kali paths in one attempt.
- Do not broaden from validation into noisy exploration.
- Do not repeat a failed tool path without new evidence.
- Prefer a bounded validation step over a speculative attack chain.
- If a dedicated tool fits, prefer it over generic command execution.
