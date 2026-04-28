applies to: can, vcan, vcan0, candump, cansend, canplayer, python-can, door, doors, replay

Use this skill when the mission references CAN bus activity, vCAN interfaces, door state, or replay behavior.

- Confirm interface presence before acting: `ip link show`, then inspect `vcan0` or another CAN interface.
- Prefer observing traffic first with `candump` before sending frames, especially when the goal is to map message meaning.
- Treat repeated identical frames and short bursts as replay indicators; record the arbitration ID and payload before pivoting.
- For vehicle-state actions, validate current state after sending a frame instead of assuming the effect landed.
- When using `python-can`, keep messages tightly scoped: one bus, one arbitration ID hypothesis, one validating send path.
- If the host already has shell or session access, prefer the smallest validation step that proves CAN reachability before attempting a mission action.
