---
name: KaliValidationSkill
description: Summarize prior exploit activity and reinforce evidence-backed next steps.
applies_to: striker
priority: 40
triggers:
  - failure
  - retry
  - validation
---
KALI VALIDATION:
Use this skill to keep the next Kali step focused and hypothesis-driven.

What this skill is for:
Use this skill whenever you are deciding whether to continue, pivot, or stop after a Kali-driven attempt.

When to use it:
- After any Kali tool run
- When the prior attempt failed or produced weak output
- When several possible next steps exist and you need to avoid flailing

How to decide what happens next:
- Prefer one strong validation action over several weak exploratory actions
- Ask whether the previous attempt produced new evidence
- Pivot when the path failed cleanly and did not improve understanding
- Continue only when the next step is clearly justified by what you just learned

Core rules:
- Avoid repeating a failed tool path without materially new evidence
- Prefer bounded follow-up over broad escalation
- Use the smallest next action that answers the current question
- Treat uncertainty as a reason to narrow the hypothesis, not broaden the activity
- Stop when the current tool family is no longer a good fit

Good patterns:
- A failed SQLi check leads to a pivot toward a different web hypothesis
- SMB enumeration produces usernames, then credential validation follows
- A precise command confirms or rejects one automotive assumption before moving on

Bad patterns:
- Re-running the same command with cosmetic tweaks and no new evidence
- Switching tools repeatedly without a clear reason
- Expanding the scope because the first path was inconclusive

Decision rule:
If the next action does not answer a sharper question than the last one, it is probably not a good next action.
