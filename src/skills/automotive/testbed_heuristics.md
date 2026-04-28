applies to: automotive, automotive-testbed, gateway, infotainment, obd, ssh, sql injection, command injection, traversal, idor, default credentials

Use this skill when working against the automotive testbed and you need a tactical pivot rather than a full solution playbook.

- The testbed mixes web, shell, CAN, and diagnostic paths, so pivot based on observed evidence instead of assuming a single exploit chain.
- If you see gateway SSH or obvious embedded-service exposure, check whether the path looks like a low-friction access route before attempting deeper exploitation.
- If infotainment web behavior shows auth or upload features, prefer focused validation of input-handling flaws over broad scanning.
- CAN and UDS paths are better validated through interface-aware actions than through generic web exploitation logic.
- Fuzzing-oriented findings usually matter when discovery is weak but protocol exposure is clear; treat them as specialized pivots, not the default first move.
- Keep the workflow generic: use these heuristics to narrow the next step, not to override clear mission evidence.
