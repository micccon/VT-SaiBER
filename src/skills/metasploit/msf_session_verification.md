---
name: MsfSessionVerificationSkill
description: Treat Metasploit execution as successful only after active session verification.
applies_to: striker
priority: 40
triggers:
  - session
  - verification
  - metasploit
---
MSF SESSION VERIFICATION:
Use this skill after execution to confirm whether Metasploit actually opened a usable session.

What this skill is for:
Use this skill after running a Metasploit exploit or auxiliary module that may produce a session.

When to use it:
- After any exploit run that claims success
- After any auxiliary flow that may create or reveal a session
- Before updating state to say that access has been achieved

How to verify:
- Treat module output as provisional first
- Check the reported `session_id` if one exists
- Confirm it through `msf_list_sessions`
- Only then treat the run as a real success

Core rules:
- A reported `session_id` is not enough on its own
- Verify the session through `msf_list_sessions`
- If no matching session is present, treat the run as a failure or unverified result
- Record the attempt clearly whether it succeeded or failed
- Pivot after an unverified no-session result instead of thrashing on the same path

Good patterns:
- Module reports `session_id=5` and `msf_list_sessions` includes session `5`
  Good: treat as success
- Module output says success but no matching session appears
  Good: treat as unverified and pivot

Bad patterns:
- Trusting console text alone
- Claiming access without session confirmation
- Repeating the same path because the output looked hopeful

Decision rule:
No confirmed session means no confirmed success.
