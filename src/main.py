"""VT-SaiBER catalyst runner and CLI entrypoint."""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

from src.config import RuntimeConfig, get_runtime_config
from src.database.connection import ensure_runtime_indexes
from src.graph.builder import build_graph
from src.state.cyber_state import CyberState
from src.utils.logging_config import setup_logging
from src.utils.parsers import to_jsonable

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MissionRequest:
    """Single orchestration request to the catalyst runner."""

    mission_goal: str
    target_scope: List[str]
    mission_id: str
    thread_id: str
    resume: bool = False
    checkpoint_id: str = ""
    export_dir: str = ""
    include_json: bool = False


@dataclass(frozen=True)
class MissionSummary:
    """Compact post-run mission summary for operator output."""

    mission_status: str
    iteration_count: int
    next_agent: Optional[str]
    discovered_targets: int
    web_findings: int
    active_sessions: int
    critical_findings: int
    errors: int

    @classmethod
    def from_state(cls, state: Dict[str, Any]) -> "MissionSummary":
        return cls(
            mission_status=str(state.get("mission_status", "unknown")),
            iteration_count=int(state.get("iteration_count", 0) or 0),
            next_agent=state.get("next_agent"),
            discovered_targets=len(state.get("discovered_targets", {}) or {}),
            web_findings=len(state.get("web_findings", []) or []),
            active_sessions=len(state.get("active_sessions", {}) or {}),
            critical_findings=len(state.get("critical_findings", []) or []),
            errors=len(state.get("errors", []) or []),
        )


@dataclass(frozen=True)
class MissionRunResult:
    """Structured result returned by the catalyst runner."""

    request: MissionRequest
    final_state: Dict[str, Any]
    summary: MissionSummary
    report_export: Optional[Dict[str, Any]] = None


def _parse_scope(scope_value: str) -> List[str]:
    """Split a comma-separated scope string into normalized entries."""

    return [item.strip() for item in (scope_value or "").split(",") if item.strip()]


def _default_mission_id(prefix: str) -> str:
    """Build a timestamped mission identifier for ad hoc runs."""

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{stamp}"


def build_initial_state(mission_goal: str, target_scope: List[str], mission_id: str) -> CyberState:
    """Build the initial CyberState for a fresh mission."""

    # This is the single canonical bootstrap state used by the CLI, graph, and many tests.
    return {
        "current_agent": "supervisor",
        "next_agent": None,
        "iteration_count": 0,
        "mission_status": "active",
        "mission_goal": mission_goal,
        "target_scope": target_scope,
        "mission_id": mission_id,
        "discovered_targets": {},
        "ot_discovery": {},
        "web_findings": [],
        "active_sessions": {},
        "exploited_services": [],
        "credential_findings": [],
        "exploit_attempts": [],
        "protocol_observations": [],
        "fuzzing_runs": [],
        "crash_indicators": [],
        "artifacts": [],
        "validations": [],
        "research_cache": {},
        "intelligence_findings": [],
        "supervisor_messages": [],
        "supervisor_expectations": {},
        "agent_log": [],
        "critical_findings": [],
        "errors": [],
    }


@asynccontextmanager
async def maybe_checkpointer(config: RuntimeConfig | None = None):
    """Best-effort Postgres checkpointer bootstrap."""

    cfg = config or get_runtime_config()
    if not cfg.checkpoint_enabled:
        yield None
        return
    if not cfg.checkpoint_database_url:
        logger.warning("Checkpointing enabled but no database URL found; running without checkpointer.")
        yield None
        return

    try:
        from langgraph.checkpoint.postgres import PostgresSaver
    except Exception as exc:
        logger.warning("PostgresSaver import failed; running without checkpointing: %s", exc)
        yield None
        return

    cm = None
    saver = None
    try:
        # Support both context-manager and direct-constructor variants from langgraph.checkpoint.postgres.
        if hasattr(PostgresSaver, "from_conn_string"):
            cm = PostgresSaver.from_conn_string(cfg.checkpoint_database_url)
            if hasattr(cm, "__aenter__"):
                saver = await cm.__aenter__()
            elif hasattr(cm, "__enter__"):
                saver = cm.__enter__()
            else:
                saver = cm
        else:
            try:
                saver = PostgresSaver(cfg.checkpoint_database_url)
            except TypeError:
                saver = PostgresSaver(connection_string=cfg.checkpoint_database_url)

        if saver is not None and hasattr(saver, "setup"):
            # Some saver implementations need an explicit setup call before use.
            maybe_setup = saver.setup()
            if inspect.isawaitable(maybe_setup):
                await maybe_setup

        yield saver
    except Exception as exc:
        logger.warning("Failed to initialize Postgres checkpointer; continuing without it: %s", exc)
        yield None
    finally:
        if cm is not None:
            if hasattr(cm, "__aexit__"):
                await cm.__aexit__(None, None, None)
            elif hasattr(cm, "__exit__"):
                cm.__exit__(None, None, None)
        elif saver is not None:
            if hasattr(saver, "aclose"):
                await saver.aclose()
            elif hasattr(saver, "close"):
                saver.close()


class CatalystRunner:
    """Central orchestration runner for VT-SaiBER missions."""

    def __init__(self, config: RuntimeConfig | None = None):
        """Capture the shared runtime config once for this runner instance."""

        self.config = config or get_runtime_config()

    def build_request(self, args: argparse.Namespace) -> MissionRequest:
        """Translate CLI arguments into a normalized mission request."""

        mission_id = args.mission_id or _default_mission_id(self.config.default_thread_prefix)
        thread_id = args.thread_id or mission_id
        target_scope = _parse_scope(args.target_scope)

        if not args.resume:
            if not args.mission_goal:
                raise ValueError("--mission-goal is required when not resuming")
            if not target_scope:
                raise ValueError("--target-scope must include at least one CIDR/IP when not resuming")

        return MissionRequest(
            mission_goal=args.mission_goal,
            target_scope=target_scope,
            mission_id=mission_id,
            thread_id=thread_id,
            resume=args.resume,
            checkpoint_id=args.checkpoint_id,
            export_dir=args.export_dir or (self.config.report_export_dir or ""),
            include_json=bool(args.json),
        )

    def build_graph_config(self, request: MissionRequest) -> Dict[str, Any]:
        """Build the LangGraph configurable payload for this mission thread."""

        config: Dict[str, Any] = {"configurable": {"thread_id": request.thread_id}}
        if request.checkpoint_id:
            config["configurable"]["checkpoint_id"] = request.checkpoint_id
        return config

    def build_initial_state_for_request(self, request: MissionRequest) -> CyberState | None:
        """Return fresh state for new runs or None for checkpoint resumes."""

        if request.resume:
            return None
        return build_initial_state(
            mission_goal=request.mission_goal,
            target_scope=request.target_scope,
            mission_id=request.mission_id,
        )

    async def _invoke_graph(self, request: MissionRequest) -> Dict[str, Any]:
        """Run the compiled graph and normalize the final state to plain JSONable objects."""

        ensure_runtime_indexes()
        initial_state = self.build_initial_state_for_request(request)
        graph_config = self.build_graph_config(request)

        async with maybe_checkpointer(self.config) as checkpointer:
            # The catalyst runner is intentionally thin here: graph construction and orchestration stay centralized.
            graph = build_graph(checkpointer=checkpointer)
            result = await graph.ainvoke(initial_state, config=graph_config)
            return to_jsonable(result)

    async def run(self, request: MissionRequest) -> Dict[str, Any]:
        """Backward-compatible state-only execution path."""

        return await self._invoke_graph(request)

    def summarize(self, state: Dict[str, Any]) -> MissionSummary:
        """Create the compact operator-facing mission summary."""

        return MissionSummary.from_state(state)

    def export_if_requested(self, state: Dict[str, Any], export_dir: str) -> Optional[Dict[str, Any]]:
        """Write the report bundle when a mission id and export directory are available."""

        if not export_dir or not state.get("mission_id"):
            return None
        from src.database.reporting.exporter import export_mission_bundle

        written = export_mission_bundle(str(state["mission_id"]), export_dir)
        return {"report_export": written}

    async def execute(self, request: MissionRequest) -> MissionRunResult:
        """Run a mission end-to-end and return the structured result."""

        final_state = await self._invoke_graph(request)
        summary = self.summarize(final_state)
        report_export = self.export_if_requested(final_state, request.export_dir)
        return MissionRunResult(
            request=request,
            final_state=final_state,
            summary=summary,
            report_export=report_export,
        )


async def run_orchestrator(args: argparse.Namespace) -> Dict[str, Any]:
    """Backward-compatible orchestration wrapper."""

    runner = CatalystRunner()
    request = runner.build_request(args)
    return await runner.run(request)


def _print_summary(summary: MissionSummary) -> None:
    """Print a short text summary for CLI runs."""

    print("Mission Summary")
    print(f"  mission_status: {summary.mission_status}")
    print(f"  iteration_count: {summary.iteration_count}")
    print(f"  next_agent: {summary.next_agent}")
    print(f"  discovered_targets: {summary.discovered_targets}")
    print(f"  web_findings: {summary.web_findings}")
    print(f"  active_sessions: {summary.active_sessions}")
    print(f"  critical_findings: {summary.critical_findings}")
    print(f"  errors: {summary.errors}")


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the CLI parser for the catalyst runner entrypoint."""

    parser = argparse.ArgumentParser(description="Run the VT-SaiBER catalyst runner")
    parser.add_argument("--mission-goal", type=str, default="", help="Mission objective text")
    parser.add_argument(
        "--target-scope",
        type=str,
        default="",
        help="Comma-separated IPs/CIDRs/hostnames allowed in scope",
    )
    parser.add_argument("--mission-id", type=str, default="", help="Mission identifier")
    parser.add_argument("--thread-id", type=str, default="", help="Checkpoint thread identifier")
    parser.add_argument("--resume", action="store_true", help="Resume from latest checkpoint")
    parser.add_argument("--checkpoint-id", type=str, default="", help="Resume from specific checkpoint id")
    parser.add_argument("--export-dir", type=str, default="", help="Write mission report bundle after run")
    parser.add_argument("--json", action="store_true", help="Print full final state JSON")
    return parser


async def _amain() -> int:
    """Async CLI entrypoint used by main()."""

    load_dotenv()
    setup_logging()
    parser = build_arg_parser()
    args = parser.parse_args()
    runner = CatalystRunner()

    try:
        request = runner.build_request(args)
        # execute() returns both the final state and the operator-facing summary/export info.
        result = await runner.execute(request)
    except Exception as exc:
        logger.exception("Catalyst runner failed: %s", exc)
        return 1

    _print_summary(result.summary)
    if result.report_export is not None:
        print(json.dumps(result.report_export, indent=2, default=str))
    if request.include_json:
        print(json.dumps(result.final_state, indent=2, default=str))
    return 0


def main() -> int:
    """Synchronous process entrypoint."""

    return asyncio.run(_amain())


if __name__ == "__main__":
    raise SystemExit(main())
