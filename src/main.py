"""
VT-SaiBER orchestrator entrypoint.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

from src.config import get_runtime_config
from src.graph.builder import build_graph
from src.state.cyber_state import CyberState
from src.utils.logging_config import setup_logging
from src.utils.parsers import to_jsonable

logger = logging.getLogger(__name__)


def _parse_scope(scope_value: str) -> List[str]:
    return [item.strip() for item in (scope_value or "").split(",") if item.strip()]


def _default_mission_id(prefix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{prefix}-{stamp}"


def build_initial_state(mission_goal: str, target_scope: List[str], mission_id: str) -> CyberState:
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
        "research_cache": {},
        "osint_findings": [],
        "supervisor_messages": [],
        "supervisor_expectations": {},
        "agent_log": [],
        "critical_findings": [],
        "errors": [],
    }


@asynccontextmanager
async def maybe_checkpointer():
    """
    Best-effort Postgres checkpointer bootstrap.
    Falls back to no checkpointer when unavailable/misconfigured.
    """
    cfg = get_runtime_config()
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


async def run_orchestrator(args: argparse.Namespace) -> Dict[str, Any]:
    cfg = get_runtime_config()
    mission_id = args.mission_id or _default_mission_id(cfg.default_thread_prefix)
    thread_id = args.thread_id or mission_id
    target_scope = _parse_scope(args.target_scope)

    if not args.resume:
        if not args.mission_goal:
            raise ValueError("--mission-goal is required when not resuming")
        if not target_scope:
            raise ValueError("--target-scope must include at least one CIDR/IP when not resuming")

    initial_state = None
    if not args.resume:
        initial_state = build_initial_state(
            mission_goal=args.mission_goal,
            target_scope=target_scope,
            mission_id=mission_id,
        )

    config: Dict[str, Any] = {"configurable": {"thread_id": thread_id}}
    if args.checkpoint_id:
        config["configurable"]["checkpoint_id"] = args.checkpoint_id

    async with maybe_checkpointer() as checkpointer:
        graph = build_graph(checkpointer=checkpointer)
        result = await graph.ainvoke(initial_state, config=config)
        return to_jsonable(result)


def _print_summary(state: Dict[str, Any]) -> None:
    print("Mission Summary")
    print(f"  mission_status: {state.get('mission_status', 'unknown')}")
    print(f"  iteration_count: {state.get('iteration_count', 0)}")
    print(f"  next_agent: {state.get('next_agent')}")
    print(f"  discovered_targets: {len(state.get('discovered_targets', {}) or {})}")
    print(f"  web_findings: {len(state.get('web_findings', []) or [])}")
    print(f"  active_sessions: {len(state.get('active_sessions', {}) or {})}")
    print(f"  critical_findings: {len(state.get('critical_findings', []) or [])}")
    print(f"  errors: {len(state.get('errors', []) or [])}")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run VT-SaiBER orchestrator")
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
    parser.add_argument("--json", action="store_true", help="Print full final state JSON")
    return parser


async def _amain() -> int:
    load_dotenv()
    setup_logging()
    parser = build_arg_parser()
    args = parser.parse_args()

    try:
        final_state = await run_orchestrator(args)
    except Exception as exc:
        logger.exception("Orchestrator run failed: %s", exc)
        return 1

    _print_summary(final_state)
    if args.json:
        print(json.dumps(final_state, indent=2, default=str))
    return 0


def main() -> int:
    return asyncio.run(_amain())


if __name__ == "__main__":
    raise SystemExit(main())
