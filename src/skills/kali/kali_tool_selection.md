---
name: KaliToolSelectionSkill
description: Recommend the single best next Kali tool from current state.
applies_to: striker
priority: 50
triggers:
  - web
  - sqli
  - smb
  - wordpress
  - automotive
---
KALI TOOL SELECTION:
Choose a single best next tool from the current evidence instead of mixing multiple weak paths.

What this skill is for:
Use this skill when several Kali-capable paths are possible and you need to commit to one best next tool.

When to use it:
- When the target has multiple promising signals
- When both web and credential paths seem possible
- Before invoking any Kali tool so the next action stays deliberate

How to choose the tool:
- Pick the one tool that best matches the strongest current evidence
- Prefer dedicated tools over generic commands
- Choose the path that validates the clearest hypothesis with the least noise
- Use `execute_command` only when the dedicated tools do not fit

Core rules:
- `wpscan_analyze` fits WordPress-specific surfaces
- `sqlmap_scan` fits a strong SQL injection or web-form hypothesis
- `enum4linux_scan` fits SMB discovery and account-oriented follow-up
- `hydra_attack` fits evidence-backed credential validation against a known service
- `execute_command` is the fallback for precise validation that does not fit the dedicated Kali tools
- Use the chosen tool first unless new evidence clearly favors a different path

Good patterns:
- WordPress indicators present
  Good: choose `wpscan_analyze`
- A strong SQLi hint on one route or form
  Good: choose `sqlmap_scan`
- SMB present and accounts are still unknown
  Good: choose `enum4linux_scan`
- Known service plus evidence-backed credentials
  Good: choose `hydra_attack`

Bad patterns:
- Starting with `execute_command` because it feels flexible
- Using two or three tools in parallel for the same vague idea
- Choosing a tool that does not match the strongest available signal

Decision rule:
Pick the tool that best matches the evidence you have now, not the evidence you wish you had.
