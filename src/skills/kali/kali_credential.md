---
name: KaliCredentialSkill
description: Highlight credential and SMB-oriented Kali paths from current evidence.
applies_to: striker
priority: 20
triggers:
  - smb
  - hydra
  - login
  - credentials
---
KALI CREDENTIAL:
Use this skill when the target exposes a service that supports credential validation or SMB enumeration.

What this skill is for:
Use this skill when the current target exposes SMB or another credential-facing service and you need to decide between evidence gathering and credential validation.

When to use it:
- When SMB is exposed
- When SSH, FTP, Telnet, databases, or other login-oriented services are exposed
- When credentials, usernames, or password hints already exist in state

How to choose the next step:
- Prefer evidence gathering before credential attacks when the service is still poorly understood
- Use SMB enumeration first when SMB is present
- Use Hydra only when the service, username source, and password hypothesis are already grounded in evidence
- Prefer one service at a time rather than spraying across multiple protocols

Core rules:
- Prefer `enum4linux_scan` first for SMB-oriented evidence gathering
- Use `hydra_attack` only when the target service is known and the input credentials are justified
- Keep Hydra attempts bounded to the specific service under test
- Use real credential inputs from CyberState, operator context, or clear prior findings
- Treat credential validation as hypothesis testing, not guessing

Good patterns:
- SMB is open and no valid accounts are known
  Good: start with `enum4linux_scan`
- SSH is open and state already includes a username/password pair
  Good: run `hydra_attack` against SSH with those exact creds
- A small username list and one evidence-backed password candidate
  Good: test only that bounded combination set

Bad patterns:
- Running Hydra with invented defaults like `admin/admin`
- Brute-forcing multiple services at once because credentials might work somewhere
- Skipping SMB enumeration and going straight to noisy guessing

Decision rule:
If the credential source is weak or unknown, gather more evidence before using Hydra.
