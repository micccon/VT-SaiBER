---
name: KaliAutomotiveSkill
description: Surface automotive protocol clues that favor precise command-driven validation.
applies_to: striker
priority: 30
triggers:
  - can
  - uds
  - obd
  - replay
---
KALI AUTOMOTIVE:
Use this skill when the mission references CAN, UDS, OBD, replay, or related automotive validation tasks.

What this skill is for:
Use this skill when the mission is about automotive protocol validation rather than ordinary host exploitation.

When to use it:
- When the context references CAN, UDS, OBD, replay, fuzzing, ECU interaction, or related terms
- When OT discovery or prior findings suggest an automotive protocol workflow
- When the right next step is a precise command rather than a standard Kali exploit tool

How to choose the next step:
- Start from one concrete protocol hypothesis
- Prefer exact commands that validate or reproduce one expected behavior
- Keep the action close to the observed bus, service, port, or tool context
- Treat each command as a bounded experiment

Core rules:
- Prefer exact, evidence-backed commands over general shell exploration
- Treat automotive protocol work as validation, not generic host exploitation
- Use `execute_command` only for narrowly scoped checks that you can explain
- Keep commands reversible and focused when possible
- Avoid turning protocol validation into noisy host-level exploration

Good patterns:
- Validate one suspected CAN or UDS interaction with a single targeted command
- Reproduce one replay or fuzzing hypothesis against the known interface in context
- Confirm one observed port or automotive service with a minimal check

Bad patterns:
- Wandering through the shell because the environment feels unfamiliar
- Running broad host reconnaissance when the task is protocol-specific
- Combining several unrelated validation ideas into one command chain

Decision rule:
If the command is not tied to a specific protocol hypothesis, it is probably too broad.
