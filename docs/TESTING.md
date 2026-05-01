# Testing

The active test suite lives under `scripts/tests/`.

## Test Layout

- `scripts/tests/runtime/`: shared runtime behavior, approvals, tracing, execution/chat runners
- `scripts/tests/agents/unit/`: unit coverage for supervisor, scout, fuzzer, librarian, striker, and resident
- `scripts/tests/agents/live/`: live agent checks against real services and credentials
- `scripts/tests/infrastructure/unit/`: graph smoke tests, failure-path tests, direct infrastructure logic
- `scripts/tests/infrastructure/live/`: MCP probe tests, full-graph live checks, Docker health scripts
- `scripts/tests/database/unit/`: persistence, reporting, and retrieval tests
- `scripts/tests/database/live/`: live KB, CVE, OSINT, and librarian data-source tests

## Common Commands

Fast regression slice:

```bash
python -m pytest \
  scripts/tests/runtime \
  scripts/tests/agents/unit \
  scripts/tests/infrastructure/unit \
  scripts/tests/database/unit \
  -q
```

Run by family:

```bash
python -m pytest scripts/tests/runtime -q
python -m pytest scripts/tests/agents/unit -q
python -m pytest scripts/tests/agents/live -m live -q
python -m pytest scripts/tests/infrastructure/unit -q
python -m pytest scripts/tests/infrastructure/live -m live -q
python -m pytest scripts/tests/database/unit -q
python -m pytest scripts/tests/database/live -m live -q
```

## Pytest Markers

- `live`
- `kb`
- `cve`
- `osint`
- `librarian`

## Runner Scripts

Useful live helpers include:

- `scripts/tests/agents/live/run_supervisor_live.sh`
- `scripts/tests/agents/live/run_striker_live.sh`
- `scripts/tests/infrastructure/live/run_full_graph_live.sh`
- `scripts/tests/infrastructure/live/postgres_test.sh`

## Practical Notes

- live tests are opt-in
- MCP-backed tests expect a healthy `attackbox`
- database tests expect a working Postgres path
- some librarian and database live tests depend on external credentials
