applies to: boofuzz, radamsa, fuzz, fuzzing, python-can, can fd, dlc, overflow, crash, header, parser

Use this skill when the mission references fuzzing, malformed frames, parser crashes, or protocol edge cases.

- Choose one fuzzing hypothesis at a time: state machine, length handling, format parsing, or transport framing.
- For boofuzz, start with a minimal seed request and mutate the field most likely to affect state or length calculations.
- For Radamsa-style inputs, mutate realistic seed payloads instead of starting from fully random bytes.
- CAN FD and DLC issues usually center on payload length mismatches; validate whether the receiver assumes classic 8-byte CAN semantics.
- Record crash markers, disconnects, or validation API evidence immediately after a fuzzing step so the signal is not lost.
- If the goal is validation rather than full exploit development, stop once you have strong evidence of the malformed-input effect.
