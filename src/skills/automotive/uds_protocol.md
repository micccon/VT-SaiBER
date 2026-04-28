applies to: uds, iso 14229, securityaccess, writeDataByIdentifier, transferdata, requestdownload, diagnostic, ecu, 0x27, 0x2e, 0x34, 0x36, 9556

Use this skill when the target behavior involves UDS diagnostics, session-state flaws, or diagnostic message handling.

- Anchor on the service and sub-function first; UDS paths usually depend on message sequence and session context more than broad brute force.
- For SecurityAccess-style work, compare expected negative responses with unusual positive responses to spot state-machine bypasses.
- For length-sensitive handlers, prioritize malformed short or oversized requests over random traffic.
- Firmware or TransferData paths should focus on header fields, declared lengths, and parser trust boundaries.
- If the path references both TCP and CAN delivery, keep the transport separate in your reasoning and validate one transport cleanly before pivoting.
- Prefer bounded diagnostic validation over noisy enumeration when the objective is to prove a bypass or parser flaw.
