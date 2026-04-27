---
name: MsfOptionsSkill
description: Keep execution options minimal, evidence-backed, and safe.
applies_to: striker
priority: 30
triggers:
  - options
  - targeturi
  - credentials
  - payload
---
MSF OPTIONS:
Use this skill to fill only the minimum justified module options before execution.

What this skill is for:
Use this skill when a Metasploit module has already been chosen and you need to decide which options to set before running it.

When to use it:
- After selecting a module that looks like a strong match
- Before any `msf_run_exploit` or `msf_run_auxiliary` call
- When deciding whether the current evidence is enough to execute safely

How to choose options:
- Start with the required options only
- Fill values from CyberState, observed services, web findings, credentials, or explicit operator expectations
- Add optional values only when they are clearly supported by evidence or needed to make the module work
- If a value is uncertain, stop and gather more evidence instead of guessing

Core rules:
- Always fetch module options before execution
- Set `RHOSTS` or `RHOST` from the selected target
- Set `RPORT` from the observed open port when the module expects it
- Set `TARGETURI`, `PATH`, or `URI` only when a real route or path was observed
- Set credential fields only from discovered or operator-provided credentials
- Set `SSL` or related protocol flags only when the service evidence supports them
- Set callback fields like `LHOST` only when you have a real reachable listener configuration
- Do not fill options just because they exist

Guardrails:
- Do not invent usernames, passwords, domains, vhosts, or paths
- Do not guess callback values such as `LHOST`
- Do not copy options from another module unless they are also valid for the current one
- Do not set many optional knobs just to see if the module runs
- If required values are missing, pause and gather evidence

Good patterns:
- Service shows `80/http` on `10.0.0.15` and findings include `/admin`
  Good: set `RHOSTS=10.0.0.15`, `RPORT=80`, and `TARGETURI=/admin` only if the module supports it
- Service shows `22/ssh` and credentials are already present
  Good: set `RHOSTS`, `RPORT`, `USERNAME`, and `PASSWORD`
- Reverse payload selected and no real listener info is available
  Good: stop and obtain a valid `LHOST` first

Bad patterns:
- Setting `TARGETURI=/` only because many web modules use it
- Setting `admin:admin` because no credentials were found
- Setting `LHOST=127.0.0.1` or `localhost`
- Filling every optional field to brute-force a module into running

Decision rule:
If you cannot explain where an option value came from, do not set it.
