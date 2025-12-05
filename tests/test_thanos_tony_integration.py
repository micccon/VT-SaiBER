
from interaction.api.thanos import process_user_input
from orchestrator.tony_stark import StarkPromptEngine


TEST_INPUTS = [
    ("192.168.0.10", "port_scan"),
    ("example.com", "service_scan"),
    ("http://internal.example.local/test", "service_scan"),
    ("scan badhost.com for port 22", "quick_scan"),
    ("scan 10.0.0.8 ports 22,443", "port_scan"),
    ("quick scan 123.123.123.123", "quick_scan"),
    ("please check 1.2.3.4; rm -rf /", "quick_scan"),
    ("ports 80,8080 on 192.168.1.1", "port_scan"),
]


def test_thanos_parses_and_stark_builds():
    """Integration test: raw input -> thanos -> StarkPromptEngine.build_prompt

    Verifies that:
    - `process_user_input` returns a structured dict
    - `build_prompt` returns a non-empty string
    - common placeholders are replaced (no literal `{user_input}` remains)
    """
    builder = StarkPromptEngine()

    for raw, _expected in TEST_INPUTS:
        processed = process_user_input(raw, output_context="dict")
        assert isinstance(processed, dict), f"process_user_input did not return dict for: {raw}"
        # basic structure
        for key in ("raw", "action", "sanitized_targets", "validation_errors"):
            assert key in processed, f"Missing key {key} in processed result for: {raw}"

        # build prompt
        prompt = builder.build_prompt(processed)
        assert isinstance(prompt, str)
        assert prompt.strip() != "", f"Empty prompt for input: {raw}"

        # placeholders should be replaced
        assert "{user_input}" not in prompt

        # If sanitized target exists, ensure one of its values appear in the prompt
        st = processed.get("sanitized_targets", [])
        if st:
            first = st[0]
            if isinstance(first, dict):
                val = first.get("value") or first.get("raw")
            else:
                val = first
            if val:
                assert str(val) in prompt or processed.get("raw") in prompt

if __name__ == "__main__":
    test_thanos_parses_and_stark_builds()
